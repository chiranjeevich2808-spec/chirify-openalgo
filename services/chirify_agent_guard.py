"""Three-Gate AI Agent Safety Architecture for Chirify / OpenAlgo.

Complements :mod:`services.agent.safety.risk` with three independent, layered
deterministic controls ensuring no prompt injection, hallucination, or unapproved
remote call can trigger unauthorized or non-compliant live orders:

1. **Gate 1 — Surface Exclusion & Remote MCP Transport Security**:
   - Docked chart surface (``surface == "trading_chart"``) strips all 7
     order-mutating tool schemas (``place_order``, ``place_smart_order``,
     ``modify_order``, ``cancel_order``, ``cancel_all_order``, ``close_position``,
     ``close_all_positions`` — plus the ``cancel_all_orders`` alias) before the
     LLM sees the schema.
   - Remote HTTP/SSE MCP transport requires ``https://``, OAuth 2.1 bearer scope
     ``write:orders``, and verified TOTP before exposing or invoking mutating tools.

2. **Gate 2 — Human-in-the-Loop (HITL) Confirmation**:
   - Every call to any of the 7 order-mutating tools deterministically produces a
     structured :class:`PendingOrderConfirmation` payload bound via HMAC-SHA256
     to ``(session_id, tool_name, normalized_arguments)`` and refuses execution
     until an explicit, single-use, unexpired user approval token is presented.

3. **Gate 3 — Prompt-Blind Deterministic Order Guard**:
   - Pure-state validator whose signature accepts **zero conversation, prompt, or
     reasoning strings**. Enforces:
     * Global kill switch (flag or file).
     * Strict symbol/exchange/action/product identifier hygiene + allow/block lists.
     * SEBI ``<10 OPS`` sliding 1-second window (``max_orders_per_second=9``
       safety margin for Indian retail).
     * ``max_quantity`` and ``max_order_notional`` caps.
     * ``max_ltp_deviation_pct`` price collar around LTP.
     * Duplicate-order cooldown window.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from utils import real_threading

HUNDRED = Decimal("100")

# Canonical 7 order-mutating tools specified by the Three-Gate contract
ORDER_MUTATING_TOOLS: tuple[str, ...] = (
    "place_order",
    "place_smart_order",
    "modify_order",
    "cancel_order",
    "cancel_all_order",
    "close_position",
    "close_all_positions",
)

# Includes ``cancel_all_orders`` (plural) used in services/agent/tools/orders.py
ALL_ORDER_MUTATING_TOOL_NAMES: frozenset[str] = frozenset(ORDER_MUTATING_TOOLS) | frozenset(
    {"cancel_all_orders"}
)

REMOTE_MCP_TRANSPORTS: frozenset[str] = frozenset(
    {"http", "sse", "streamable_http", "streamable-http", "remote_http"}
)

# Strict identifier patterns: reject prompt-injection payloads stuffed into fields
_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9._:&/-]{0,47}$")
_EXCHANGE_RE = re.compile(r"^[A-Z0-9_]{2,20}$")
_VALID_ACTIONS: frozenset[str] = frozenset({"BUY", "SELL"})
_VALID_PRODUCTS: frozenset[str] = frozenset({"CNC", "MIS", "NRML", "MARGIN", "CASH"})
_VALID_PRICE_TYPES: frozenset[str] = frozenset({"MARKET", "LIMIT", "SL", "SL-M", "SLM"})


# =============================================================================
# Gate 1: Surface Exclusion & Remote MCP Security
# =============================================================================


@dataclass(frozen=True, slots=True)
class Gate1Verdict:
    """Result of a Gate 1 surface exclusion or remote MCP transport check."""

    allowed: bool
    code: str
    reason: str


def _extract_schema_tool_name(schema: Mapping[str, Any] | str) -> str:
    """Extract tool name from OpenAI function schema, MCP tool dict, or string."""
    if isinstance(schema, str):
        return schema.strip()
    if isinstance(schema, Mapping):
        fn = schema.get("function")
        if isinstance(fn, Mapping) and fn.get("name"):
            return str(fn["name"]).strip()
        if schema.get("name"):
            return str(schema["name"]).strip()
    return ""


def filter_surface_tool_schemas(
    surface: str,
    tool_schemas: Sequence[Mapping[str, Any] | str],
) -> list[Any]:
    """Strip all 7 order-mutating tool schemas when ``surface == "trading_chart"``."""
    normalized_surface = (surface or "").strip().lower()
    if normalized_surface != "trading_chart":
        return list(tool_schemas)
    return [
        schema
        for schema in tool_schemas
        if _extract_schema_tool_name(schema) not in ALL_ORDER_MUTATING_TOOL_NAMES
    ]


def verify_surface_exclusion(
    surface: str,
    tool_schemas: Sequence[Mapping[str, Any] | str],
) -> Gate1Verdict:
    """Verify docked ``trading_chart`` surface exposes zero order-mutating tools."""
    normalized_surface = (surface or "").strip().lower()
    if normalized_surface == "trading_chart":
        leaked = sorted(
            {
                name
                for schema in tool_schemas
                if (name := _extract_schema_tool_name(schema)) in ALL_ORDER_MUTATING_TOOL_NAMES
            }
        )
        if leaked:
            return Gate1Verdict(
                allowed=False,
                code="surface_mutating_tools_forbidden",
                reason=(
                    f"Surface 'trading_chart' must strip all order-mutating tools; "
                    f"found: {', '.join(leaked)}."
                ),
            )
    return Gate1Verdict(allowed=True, code="ok", reason="Surface tool schema policy satisfied.")


def verify_remote_mcp_transport(
    *,
    transport: str,
    url: str = "",
    bearer_scopes: Iterable[str] = (),
    totp_verified: bool = False,
    tool_name: str | None = None,
) -> Gate1Verdict:
    """Enforce HTTPS + OAuth 2.1 ``write:orders`` scope + TOTP on remote HTTP/SSE MCP."""
    norm_transport = (transport or "").strip().lower()
    if norm_transport not in REMOTE_MCP_TRANSPORTS:
        return Gate1Verdict(allowed=True, code="ok", reason="Local stdio transport permitted.")

    clean_url = (url or "").strip()
    if not clean_url.lower().startswith("https://"):
        return Gate1Verdict(
            allowed=False,
            code="mcp_https_required",
            reason=f"Remote MCP transport ({norm_transport}) requires an https:// endpoint.",
        )

    requires_order_auth = tool_name is None or tool_name in ALL_ORDER_MUTATING_TOOL_NAMES
    if requires_order_auth:
        scopes = {str(s).strip() for s in bearer_scopes if s}
        if "write:orders" not in scopes:
            return Gate1Verdict(
                allowed=False,
                code="mcp_missing_write_orders_scope",
                reason="Remote MCP order mutation requires OAuth 2.1 scope 'write:orders'.",
            )
        if not totp_verified:
            return Gate1Verdict(
                allowed=False,
                code="mcp_totp_required",
                reason="Remote MCP order mutation requires verified TOTP step-up authentication.",
            )

    return Gate1Verdict(
        allowed=True,
        code="ok",
        reason="Remote MCP HTTPS, OAuth 2.1 write:orders scope, and TOTP verified.",
    )


# =============================================================================
# Gate 2: Deterministic HITL Confirmation
# =============================================================================


def _canonical_json(data: Mapping[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True, slots=True)
class PendingOrderConfirmation:
    """Structured HITL confirmation payload required before executing any mutating tool."""

    confirmation_id: str
    session_id: str
    tool_name: str
    normalized_arguments: Mapping[str, Any]
    approval_token: str
    created_at_epoch: float
    expires_at_epoch: float
    status: str = "pending_confirmation"

    def public_payload(self) -> dict[str, Any]:
        """Payload safe to return to the UI / stream frame (excludes raw approval secret if split)."""
        return {
            "status": self.status,
            "confirmation_id": self.confirmation_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "arguments": dict(self.normalized_arguments),
            "created_at_epoch": self.created_at_epoch,
            "expires_at_epoch": self.expires_at_epoch,
            "requires_explicit_approval": True,
        }


@dataclass(frozen=True, slots=True)
class Gate2Verdict:
    """Outcome of Gate 2 HITL confirmation check."""

    allowed: bool
    code: str
    reason: str
    pending_confirmation: PendingOrderConfirmation | None = None


class Gate2ConfirmationManager:
    """Deterministic single-use HITL approval gate for all 7 order-mutating tools."""

    def __init__(
        self,
        *,
        signing_secret: str | None = None,
        ttl_seconds: float = 120.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._secret = (signing_secret or secrets.token_hex(32)).encode("utf-8")
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock or time.time
        self._lock = real_threading.RLock()
        self._pending: dict[str, PendingOrderConfirmation] = {}
        self._consumed_ids: set[str] = set()

    def _compute_token(
        self,
        confirmation_id: str,
        session_id: str,
        tool_name: str,
        normalized_arguments: Mapping[str, Any],
        expires_at_epoch: float,
    ) -> str:
        msg = (
            f"{confirmation_id}|{session_id}|{tool_name}|"
            f"{_canonical_json(normalized_arguments)}|{expires_at_epoch:.6f}"
        ).encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def request_confirmation(
        self,
        *,
        session_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> PendingOrderConfirmation:
        """Create and register a pending confirmation for a mutating order tool."""
        clean_tool = (tool_name or "").strip()
        if clean_tool not in ALL_ORDER_MUTATING_TOOL_NAMES:
            raise ValueError(f"Tool {clean_tool!r} is not an order-mutating tool.")

        now = self._clock()
        expires = now + self._ttl_seconds
        conf_id = f"conf_{secrets.token_hex(12)}"
        norm_args = dict(sorted((str(k), v) for k, v in arguments.items()))
        token = self._compute_token(conf_id, session_id, clean_tool, norm_args, expires)

        pending = PendingOrderConfirmation(
            confirmation_id=conf_id,
            session_id=session_id,
            tool_name=clean_tool,
            normalized_arguments=norm_args,
            approval_token=token,
            created_at_epoch=now,
            expires_at_epoch=expires,
        )
        with self._lock:
            self._pending[conf_id] = pending
        return pending

    def verify_or_pause(
        self,
        *,
        session_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        confirmation_id: str | None = None,
        approval_token: str | None = None,
    ) -> Gate2Verdict:
        """Pause unapproved mutating calls or verify an explicit user approval token."""
        clean_tool = (tool_name or "").strip()
        if clean_tool not in ALL_ORDER_MUTATING_TOOL_NAMES:
            return Gate2Verdict(allowed=True, code="non_mutating_tool", reason="Read-only tool.")

        norm_args = dict(sorted((str(k), v) for k, v in arguments.items()))

        if not confirmation_id or not approval_token:
            pending = self.request_confirmation(
                session_id=session_id,
                tool_name=clean_tool,
                arguments=norm_args,
            )
            return Gate2Verdict(
                allowed=False,
                code="hitl_confirmation_required",
                reason=f"Tool {clean_tool!r} requires explicit human approval before execution.",
                pending_confirmation=pending,
            )

        with self._lock:
            if confirmation_id in self._consumed_ids:
                return Gate2Verdict(
                    allowed=False,
                    code="hitl_token_replayed",
                    reason="Approval token has already been used and cannot be replayed.",
                )

            record = self._pending.get(confirmation_id)
            if record is None:
                return Gate2Verdict(
                    allowed=False,
                    code="hitl_unknown_confirmation",
                    reason="Unknown confirmation_id.",
                )

            now = self._clock()
            if now > record.expires_at_epoch:
                self._pending.pop(confirmation_id, None)
                return Gate2Verdict(
                    allowed=False,
                    code="hitl_confirmation_expired",
                    reason="Confirmation token has expired.",
                )

            if record.session_id != session_id or record.tool_name != clean_tool:
                return Gate2Verdict(
                    allowed=False,
                    code="hitl_context_mismatch",
                    reason="Approval token session or tool_name does not match the execution call.",
                )

            if _canonical_json(record.normalized_arguments) != _canonical_json(norm_args):
                return Gate2Verdict(
                    allowed=False,
                    code="hitl_arguments_tampered",
                    reason="Order arguments differ from the human-approved confirmation payload.",
                )

            expected_token = self._compute_token(
                record.confirmation_id,
                record.session_id,
                record.tool_name,
                record.normalized_arguments,
                record.expires_at_epoch,
            )
            if not hmac.compare_digest(approval_token, expected_token):
                return Gate2Verdict(
                    allowed=False,
                    code="hitl_invalid_signature",
                    reason="Invalid user approval token signature.",
                )

            self._pending.pop(confirmation_id, None)
            self._consumed_ids.add(confirmation_id)

        return Gate2Verdict(
            allowed=True,
            code="ok",
            reason=f"Explicit human approval verified for {clean_tool}.",
        )


# =============================================================================
# Gate 3: Prompt-Blind Deterministic Order Guard
# =============================================================================


@dataclass(frozen=True, slots=True)
class Gate3Policy:
    """Deterministic numerical & structural limits enforced by Gate 3."""

    kill_switch_engaged: bool = False
    kill_switch_file: Path | None = None
    max_orders_per_second: int = 9  # SEBI <10 OPS retail threshold with 1 OPS safety margin
    max_quantity: int = 1000
    max_order_notional: Decimal = Decimal("500000")
    max_ltp_deviation_pct: Decimal = Decimal("5.0")
    duplicate_cooldown_seconds: float = 5.0
    allowed_symbols: frozenset[str] = frozenset()
    blocked_symbols: frozenset[str] = frozenset()
    require_reference_price: bool = True


@dataclass(frozen=True, slots=True)
class Gate3Verdict:
    """Outcome of Gate 3 prompt-blind deterministic order validation."""

    allowed: bool
    code: str
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)


def _to_decimal(val: Decimal | float | int | str | None) -> Decimal | None:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, Decimal):
        return val if val.is_finite() else None
    try:
        parsed = Decimal(str(val).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed.is_finite() else None


class PromptBlindOrderGuard:
    """Pure-state Gate 3 order validator.

    Accepts **zero** prompt, conversation, message, or LLM reasoning strings in
    its constructor or :meth:`validate_order` signature. Even if an adversarial
    prompt injection hijacks the LLM's reasoning, it cannot bypass the kill switch,
    SEBI ``<10 OPS`` sliding window, notional/quantity limits, LTP price collar,
    symbol allow/block lists, or duplicate-order cooldown.
    """

    def __init__(
        self,
        policy: Gate3Policy | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy or Gate3Policy()
        self._clock = clock or time.monotonic
        self._lock = real_threading.RLock()
        self._ops_timestamps: deque[float] = deque()
        self._recent_fingerprints: dict[str, float] = {}

    @property
    def policy(self) -> Gate3Policy:
        return self._policy

    def reset(self) -> None:
        """Clear sliding-window OPS timestamps and duplicate fingerprint state."""
        with self._lock:
            self._ops_timestamps.clear()
            self._recent_fingerprints.clear()

    def validate_order(
        self,
        *,
        symbol: str,
        exchange: str,
        action: str,
        quantity: int,
        product: str,
        price_type: str = "MARKET",
        price: Decimal | float | int | str | None = None,
        trigger_price: Decimal | float | int | str | None = None,
        ltp: Decimal | float | int | str | None = None,
    ) -> Gate3Verdict:
        """Validate a structured order intent using pure state (prompt-blind).

        Notice that no conversation, prompt, system instruction, or free-text
        override parameter exists in this method's signature.
        """
        pol = self._policy

        # 1. Global kill switch (in-memory flag or filesystem sentinel)
        if pol.kill_switch_engaged or (
            pol.kill_switch_file is not None and pol.kill_switch_file.exists()
        ):
            return Gate3Verdict(
                allowed=False,
                code="kill_switch_engaged",
                reason="Global kill switch is engaged; all order execution is halted.",
            )

        # 2. Strict identifier hygiene (defeats prompt/SQL/command strings stuffed into fields)
        sym = str(symbol or "").strip().upper()
        if not _SYMBOL_RE.match(sym):
            return Gate3Verdict(
                allowed=False,
                code="invalid_symbol",
                reason=f"Symbol {symbol!r} failed strict identifier validation.",
            )

        exch = str(exchange or "").strip().upper()
        if not _EXCHANGE_RE.match(exch):
            return Gate3Verdict(
                allowed=False,
                code="invalid_exchange",
                reason=f"Exchange {exchange!r} failed strict identifier validation.",
            )

        act = str(action or "").strip().upper()
        if act not in _VALID_ACTIONS:
            return Gate3Verdict(
                allowed=False,
                code="invalid_action",
                reason=f"Action must be BUY or SELL, got {action!r}.",
            )

        prod = str(product or "").strip().upper()
        if prod not in _VALID_PRODUCTS:
            return Gate3Verdict(
                allowed=False,
                code="invalid_product",
                reason=f"Product {product!r} is not in allowed vocabulary.",
            )

        ptype = str(price_type or "MARKET").strip().upper()
        if ptype not in _VALID_PRICE_TYPES:
            return Gate3Verdict(
                allowed=False,
                code="invalid_price_type",
                reason=f"Price type {price_type!r} is not in allowed vocabulary.",
            )
        if ptype == "SLM":
            ptype = "SL-M"

        # 3. Symbol blocklist / allowlist
        blocked_upper = {s.upper() for s in pol.blocked_symbols}
        if sym in blocked_upper:
            return Gate3Verdict(
                allowed=False,
                code="symbol_blocked",
                reason=f"Symbol {sym} is on the risk guard blocklist.",
            )
        if pol.allowed_symbols:
            allowed_upper = {s.upper() for s in pol.allowed_symbols}
            if sym not in allowed_upper:
                return Gate3Verdict(
                    allowed=False,
                    code="symbol_not_allowed",
                    reason=f"Symbol {sym} is not in the configured symbol allowlist.",
                )

        # 4. Quantity bounds
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity <= 0:
            return Gate3Verdict(
                allowed=False,
                code="invalid_quantity",
                reason=f"Quantity must be a positive integer, got {quantity!r}.",
            )
        if quantity > pol.max_quantity:
            return Gate3Verdict(
                allowed=False,
                code="max_quantity_exceeded",
                reason=f"Order quantity {quantity} exceeds max_quantity={pol.max_quantity}.",
                details={"quantity": quantity, "max_quantity": pol.max_quantity},
            )

        # 5. Price & LTP collar + Notional cap
        dec_price = _to_decimal(price)
        dec_trigger = _to_decimal(trigger_price)
        dec_ltp = _to_decimal(ltp)

        if ptype in {"LIMIT", "SL"} and (dec_price is None or dec_price <= 0):
            return Gate3Verdict(
                allowed=False,
                code="invalid_price",
                reason=f"{ptype} order requires a positive limit price.",
            )
        if ptype in {"SL", "SL-M"} and (dec_trigger is None or dec_trigger <= 0):
            return Gate3Verdict(
                allowed=False,
                code="invalid_trigger_price",
                reason=f"{ptype} order requires a positive trigger price.",
            )
        if dec_ltp is not None and dec_ltp <= 0:
            return Gate3Verdict(
                allowed=False,
                code="invalid_ltp",
                reason="Reference LTP must be strictly positive.",
            )

        # Price collar check against LTP whenever an order/trigger price and LTP exist
        collar_target = dec_price if ptype in {"LIMIT", "SL"} else (dec_trigger if ptype == "SL-M" else None)
        if collar_target is not None and dec_ltp is not None and pol.max_ltp_deviation_pct > 0:
            deviation_pct = (abs(collar_target - dec_ltp) / dec_ltp) * HUNDRED
            if deviation_pct > pol.max_ltp_deviation_pct:
                return Gate3Verdict(
                    allowed=False,
                    code="price_collar_breach",
                    reason=(
                        f"Order price {collar_target} deviates {deviation_pct:.2f}% from LTP "
                        f"{dec_ltp}, exceeding max_ltp_deviation_pct={pol.max_ltp_deviation_pct}%."
                    ),
                    details={
                        "deviation_pct": str(deviation_pct),
                        "max_ltp_deviation_pct": str(pol.max_ltp_deviation_pct),
                    },
                )

        # Reference price for notional evaluation
        ref_price = (
            dec_price
            if ptype in {"LIMIT", "SL"} and dec_price is not None
            else (dec_ltp if dec_ltp is not None else dec_trigger)
        )
        if ref_price is None:
            if pol.require_reference_price and pol.max_order_notional > 0:
                return Gate3Verdict(
                    allowed=False,
                    code="missing_reference_price",
                    reason="Cannot verify max_order_notional without a valid price or LTP.",
                )
            notional = Decimal("0")
        else:
            notional = ref_price * Decimal(quantity)
            if pol.max_order_notional > 0 and notional > pol.max_order_notional:
                return Gate3Verdict(
                    allowed=False,
                    code="max_notional_exceeded",
                    reason=(
                        f"Order notional {notional} exceeds max_order_notional="
                        f"{pol.max_order_notional}."
                    ),
                    details={
                        "notional": str(notional),
                        "max_order_notional": str(pol.max_order_notional),
                    },
                )

        # 6 & 7. Atomic sliding 1-second SEBI <10 OPS check + Duplicate-order cooldown
        fingerprint = (
            f"{sym}|{exch}|{act}|{quantity}|{prod}|{ptype}|"
            f"{dec_price if dec_price is not None else ''}|"
            f"{dec_trigger if dec_trigger is not None else ''}"
        )

        with self._lock:
            now = self._clock()

            # Prune expired OPS window entries (> 1.0s old)
            window_cutoff = now - 1.0
            while self._ops_timestamps and self._ops_timestamps[0] <= window_cutoff:
                self._ops_timestamps.popleft()

            if len(self._ops_timestamps) >= pol.max_orders_per_second:
                return Gate3Verdict(
                    allowed=False,
                    code="ops_rate_limit_exceeded",
                    reason=(
                        f"SEBI <10 OPS retail rate limit reached: "
                        f"{len(self._ops_timestamps)} orders in the last 1.0s "
                        f"(cap={pol.max_orders_per_second} OPS)."
                    ),
                    details={
                        "orders_in_last_second": len(self._ops_timestamps),
                        "max_orders_per_second": pol.max_orders_per_second,
                    },
                )

            # Prune expired duplicate fingerprints & check cooldown
            if pol.duplicate_cooldown_seconds > 0:
                dup_cutoff = now - pol.duplicate_cooldown_seconds
                expired_fps = [
                    fp for fp, ts in self._recent_fingerprints.items() if ts <= dup_cutoff
                ]
                for fp in expired_fps:
                    self._recent_fingerprints.pop(fp, None)

                prev_ts = self._recent_fingerprints.get(fingerprint)
                if prev_ts is not None and (now - prev_ts) < pol.duplicate_cooldown_seconds:
                    return Gate3Verdict(
                        allowed=False,
                        code="duplicate_order_cooldown",
                        reason=(
                            f"Duplicate order {act} {quantity} {sym} blocked within "
                            f"{pol.duplicate_cooldown_seconds:.1f}s cooldown window."
                        ),
                    )
                self._recent_fingerprints[fingerprint] = now

            # Claim OPS slot
            self._ops_timestamps.append(now)

        return Gate3Verdict(
            allowed=True,
            code="ok",
            reason=f"{act} {quantity} {sym} on {exch} passed Gate 3 deterministic checks.",
            details={
                "symbol": sym,
                "exchange": exch,
                "action": act,
                "quantity": quantity,
                "notional": str(notional),
            },
        )
