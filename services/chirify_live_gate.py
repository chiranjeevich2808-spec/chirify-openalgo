"""Cohort-A Sandbox-Gated Live Mode & SEBI Regulatory Compliance Gate.

When OpenAlgo runs as a standalone OSS installation (``CHIRIFY_ENFORCE_LIVE_GATE``
unset or ``"false"``), :func:`check_live_mode_transition` and
:func:`enforce_live_mode_transition` act as zero-overhead pass-throughs so
upstream OpenAlgo behavior and tests remain completely untouched.

When ``CHIRIFY_ENFORCE_LIVE_GATE`` is truthy (``"true"``, ``"1"``, ``"yes"``) in
Chirify managed SaaS pods, switching ``analyze_mode`` from ``True`` (Sandbox /
Analyze) to ``False`` (Live execution) requires a valid HMAC-SHA256 signed
Chirify Entitlement token (or explicit :class:`EntitlementClaims`) satisfying:

1. **Sandbox Qualification**: ``sandbox_qualified=True``,
   ``simulated_trades >= 5``, and ``unhandled_rms_breaches == 0``.
2. **Risk Guard Kill-Switch Configured**: ``max_daily_loss > 0`` and
   ``max_order_notional > 0``.
3. **SEBI Retail Algo Compliance** (for ``broker_type == "IN_stock"``):
   - ``cohort == "india_pro_pod"`` requires ``static_ip_verified=True``.
   - ``hosted_cloud=True`` requires a non-empty ``exchange_algo_id``
     (SEBI Circular ``SEBI/HO/MIRSD/MIRSD-PoD/P/CIR/2025/0000013`` /
     NSE Circular ``NSE/INVG/67858``).
   - ``cohort == "india_byo_vps"`` requires
     ``personal_family_under_10ops_attested=True``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

MIN_SIMULATED_TRADES = 5
TRUTHY_VALUES: frozenset[str] = frozenset({"true", "1", "yes", "t", "on"})


class EntitlementVerificationError(PermissionError):
    """Raised when a Chirify Entitlement token is missing, malformed, forged, or expired."""


@dataclass(frozen=True, slots=True)
class EntitlementClaims:
    """Structured entitlement claims signed by the Chirify Control Plane."""

    tenant_id: str = ""
    user_id: str = ""
    cohort: str = "india_pro_pod"
    broker_name: str = ""
    broker_type: str = "IN_stock"
    hosted_cloud: bool = True
    sandbox_qualified: bool = False
    simulated_trades: int = 0
    unhandled_rms_breaches: int = 0
    max_daily_loss: float = 0.0
    max_order_notional: float = 0.0
    static_ip_verified: bool = False
    exchange_algo_id: str = ""
    personal_family_under_10ops_attested: bool = False
    issued_at: int | None = None
    expires_at: int | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EntitlementClaims:
        """Parse and strictly coerce a decoded JSON payload into :class:`EntitlementClaims`."""

        def _strict_bool(val: Any) -> bool:
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.strip().lower() in TRUTHY_VALUES
            return False

        def _int_val(val: Any, default: int = 0) -> int:
            if val is None or isinstance(val, bool):
                return default
            return int(val)

        def _float_val(val: Any, default: float = 0.0) -> float:
            if val is None or isinstance(val, bool):
                return default
            return float(val)

        iat_raw = data.get("issued_at", data.get("iat"))
        exp_raw = data.get("expires_at", data.get("exp"))

        raw_tier = str(data.get("tier") or "").strip()
        raw_cohort = str(data.get("cohort") or "").strip()
        if raw_tier and (not raw_cohort or raw_cohort in {"A", "B"}):
            cohort_str = raw_tier
        else:
            cohort_str = raw_cohort or raw_tier or "india_pro_pod"
        default_hosted = cohort_str != "india_byo_vps"
        hosted_val = (
            _strict_bool(data["hosted_cloud"])
            if "hosted_cloud" in data
            else default_hosted
        )

        return cls(
            tenant_id=str(data.get("tenant_id") or "").strip(),
            user_id=str(data.get("user_id") or data.get("sub") or "").strip(),
            cohort=cohort_str,
            broker_name=str(data.get("broker_name") or data.get("broker") or "").strip(),
            broker_type=str(data.get("broker_type") or "IN_stock").strip(),
            hosted_cloud=hosted_val,
            sandbox_qualified=_strict_bool(data.get("sandbox_qualified", False)),
            simulated_trades=_int_val(data.get("simulated_trades"), 0),
            unhandled_rms_breaches=_int_val(data.get("unhandled_rms_breaches"), 0),
            max_daily_loss=_float_val(data.get("max_daily_loss"), 0.0),
            max_order_notional=_float_val(data.get("max_order_notional"), 0.0),
            static_ip_verified=_strict_bool(data.get("static_ip_verified", False)),
            exchange_algo_id=str(data.get("exchange_algo_id") or "").strip(),
            personal_family_under_10ops_attested=_strict_bool(
                data.get("personal_family_under_10ops_attested", False)
            ),
            issued_at=_int_val(iat_raw) if iat_raw is not None else None,
            expires_at=_int_val(exp_raw) if exp_raw is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize claims to a plain dictionary."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class LiveGateVerdict:
    """Outcome of a Sandbox-to-Live mode gate check."""

    allowed: bool
    code: str
    message: str
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Render the verdict as JSON-serializable primitives."""
        return {
            "allowed": self.allowed,
            "code": self.code,
            "message": self.message,
            "reasons": list(self.reasons),
        }


class LiveGateBlockedError(PermissionError):
    """Raised when a transition from Analyze/Sandbox mode to Live mode is refused."""

    status_code: int = 403

    def __init__(self, verdict: LiveGateVerdict) -> None:
        self.verdict = verdict
        super().__init__(verdict.message)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def is_emergency_kill_switch_engaged(env: Mapping[str, str] | None = None) -> bool:
    """Return True iff the DORA/SEBI emergency kill switch (``CHIRIFY_EMERGENCY_KILL_SWITCH``) is engaged."""
    source = env if env is not None else os.environ
    raw = str(source.get("CHIRIFY_EMERGENCY_KILL_SWITCH") or "").strip().lower()
    return raw in TRUTHY_VALUES


def is_live_gate_enforced(env: Mapping[str, str] | None = None) -> bool:
    """Return True iff ``CHIRIFY_ENFORCE_LIVE_GATE`` or ``CHIRIFY_EMERGENCY_KILL_SWITCH`` is enabled."""
    source = env if env is not None else os.environ
    if is_emergency_kill_switch_engaged(source):
        return True
    raw = str(source.get("CHIRIFY_ENFORCE_LIVE_GATE") or "").strip().lower()
    if raw:
        return raw in TRUTHY_VALUES
    managed = str(source.get("CHIRIFY_MANAGED_POD") or "").strip().lower()
    return managed in {"true", "1", "yes", "on"}


def sign_entitlement_token(claims: EntitlementClaims | Mapping[str, Any], secret: str) -> str:
    """Create an HMAC-SHA256 signed Chirify Entitlement token (HS256 compact format).

    Format: ``<base64url(header)>.<base64url(payload)>.<base64url(hmac_sha256)>``.
    """
    if not secret or not secret.strip():
        raise ValueError("CHIRIFY_ENTITLEMENT_SECRET must be non-empty to sign tokens.")
    payload_dict = claims.to_dict() if isinstance(claims, EntitlementClaims) else dict(claims)
    header_b64 = _b64url_encode(
        json.dumps({"alg": "HS256", "typ": "CHIRIFY-ENTITLEMENT"}, separators=(",", ":")).encode(
            "utf-8"
        )
    )
    payload_b64 = _b64url_encode(
        json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def verify_entitlement_token(
    token: str,
    secret: str,
    *,
    now_epoch: float | None = None,
) -> EntitlementClaims:
    """Verify an HMAC-SHA256 signed Chirify Entitlement token and parse claims.

    Supports both 3-part HS256 JWT-style tokens (``header.payload.sig``) and
    2-part compact tokens (``payload.sig`` with base64url or hex HMAC-SHA256).

    Raises:
        EntitlementVerificationError: On missing secret/token, bad signature,
            malformed payload, or expired ``expires_at``.
    """
    if not secret or not secret.strip():
        raise EntitlementVerificationError("CHIRIFY_ENTITLEMENT_SECRET is not configured.")
    if not token or not isinstance(token, str) or not token.strip():
        raise EntitlementVerificationError("CHIRIFY_ENTITLEMENT_TOKEN is missing.")

    parts = token.strip().split(".")
    key_bytes = secret.encode("utf-8")

    try:
        if len(parts) == 3:
            header_b64, payload_b64, sig_part = parts
            header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
            if not isinstance(header, Mapping) or header.get("alg") != "HS256":
                raise EntitlementVerificationError("Unsupported entitlement token algorithm.")
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            expected_sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
            provided_sig = _b64url_decode(sig_part)
            if not hmac.compare_digest(provided_sig, expected_sig):
                raise EntitlementVerificationError("Invalid entitlement token HMAC signature.")
            payload_raw = _b64url_decode(payload_b64)
        elif len(parts) == 2:
            payload_b64, sig_part = parts
            signing_input = payload_b64.encode("ascii")
            expected_digest = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
            expected_hex = expected_digest.hex()
            if len(sig_part) == 64 and all(c in "0123456789abcdefABCDEF" for c in sig_part):
                if not hmac.compare_digest(sig_part.lower(), expected_hex):
                    raise EntitlementVerificationError("Invalid entitlement token HMAC signature.")
            else:
                provided_sig = _b64url_decode(sig_part)
                if not hmac.compare_digest(provided_sig, expected_digest):
                    raise EntitlementVerificationError("Invalid entitlement token HMAC signature.")
            payload_raw = _b64url_decode(payload_b64)
        else:
            raise EntitlementVerificationError("Malformed entitlement token format.")

        payload = json.loads(payload_raw.decode("utf-8"))
    except EntitlementVerificationError:
        raise
    except Exception as exc:
        raise EntitlementVerificationError(f"Invalid entitlement token encoding: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise EntitlementVerificationError("Entitlement token payload must be a JSON object.")

    claims = EntitlementClaims.from_mapping(payload)
    if claims.expires_at is not None:
        current = now_epoch if now_epoch is not None else time.time()
        if current > float(claims.expires_at):
            raise EntitlementVerificationError("Entitlement token has expired.")

    return claims


def evaluate_live_gate(
    claims: EntitlementClaims,
    *,
    env: Mapping[str, str] | None = None,
) -> LiveGateVerdict:
    """Deterministically evaluate Cohort-A sandbox, risk, SEBI, and emergency kill-switch gates."""
    if is_emergency_kill_switch_engaged(env):
        reason = (
            "Emergency compliance kill switch (CHIRIFY_EMERGENCY_KILL_SWITCH) is engaged; "
            "all Live mode activations are unconditionally blocked."
        )
        return LiveGateVerdict(
            allowed=False,
            code="emergency_kill_switch_engaged",
            message=f"Live mode blocked [emergency_kill_switch_engaged]: {reason}",
            reasons=(reason,),
        )

    reasons: list[str] = []
    primary_code = "ok"

    def _fail(code: str, reason: str) -> None:
        nonlocal primary_code
        if primary_code == "ok":
            primary_code = code
        reasons.append(reason)

    # 1. Sandbox qualification checks
    if not claims.sandbox_qualified:
        _fail(
            "sandbox_unqualified",
            "Sandbox qualification is incomplete (sandbox_qualified must be True).",
        )
    if claims.simulated_trades < MIN_SIMULATED_TRADES:
        _fail(
            "insufficient_simulated_trades",
            f"At least {MIN_SIMULATED_TRADES} simulated sandbox trades are required "
            f"before enabling Live mode (recorded: {claims.simulated_trades}).",
        )
    if claims.unhandled_rms_breaches != 0:
        _fail(
            "unhandled_rms_breaches",
            f"Account has {claims.unhandled_rms_breaches} unhandled RMS breach(es) in Sandbox; "
            "zero unhandled breaches are required.",
        )

    # 2. Risk Guard kill-switch configuration
    if claims.max_daily_loss <= 0:
        _fail(
            "risk_kill_switch_unconfigured",
            "Risk Guard max_daily_loss kill-switch must be configured (> 0) before Live mode.",
        )
    if claims.max_order_notional <= 0:
        _fail(
            "risk_notional_unconfigured",
            "Risk Guard max_order_notional cap must be configured (> 0) before Live mode.",
        )

    # 3. SEBI retail algorithmic trading compliance for Indian stock/derivatives brokers
    if claims.broker_type == "IN_stock":
        if claims.cohort == "india_pro_pod" and not claims.static_ip_verified:
            _fail(
                "sebi_static_ip_unverified",
                "Indian broker Pro Pod requires static_ip_verified=True before Live mode.",
            )
        if claims.hosted_cloud and not (claims.exchange_algo_id and claims.exchange_algo_id.strip()):
            _fail(
                "sebi_exchange_algo_id_required",
                "Hosted cloud pods for Indian brokers require a non-empty exchange_algo_id "
                "(SEBI Circular 2025/0000013 / NSE INVG/67858).",
            )
        if (
            claims.cohort == "india_byo_vps"
            and not claims.personal_family_under_10ops_attested
        ):
            _fail(
                "sebi_byo_vps_attestation_required",
                "BYO-VPS Indian deployments require personal_family_under_10ops_attested=True.",
            )

    if reasons:
        return LiveGateVerdict(
            allowed=False,
            code=primary_code,
            message=f"Live mode blocked [{primary_code}]: {'; '.join(reasons)}",
            reasons=tuple(reasons),
        )

    return LiveGateVerdict(
        allowed=True,
        code="ok",
        message="Live mode transition permitted by Chirify Live Gate.",
    )


def _resolve_broker_type(broker: str | None, fallback: str) -> str:
    """Resolve broker_type from OpenAlgo's plugin capability cache if available."""
    if not broker:
        return fallback
    try:
        from utils.plugin_loader import get_broker_capabilities

        caps = get_broker_capabilities(broker)
        if isinstance(caps, Mapping) and caps.get("broker_type"):
            return str(caps["broker_type"])
    except Exception:
        pass
    return fallback


def check_live_mode_transition(
    *,
    current_mode: bool = True,
    target_mode: bool = False,
    broker: str | None = None,
    claims: EntitlementClaims | None = None,
    env: Mapping[str, str] | None = None,
    now_epoch: float | None = None,
) -> LiveGateVerdict:
    """Evaluate whether transitioning ``analyze_mode`` to ``target_mode`` is allowed.

    Switching *into* Analyze/Sandbox mode (``target_mode=True``) is always allowed.
    Switching *into* Live mode (``target_mode=False``) is gated whenever
    ``CHIRIFY_ENFORCE_LIVE_GATE`` or ``CHIRIFY_EMERGENCY_KILL_SWITCH`` is truthy
    (or when ``claims`` is passed directly).
    """
    # Entering or staying in Sandbox/Analyze mode is always safe and allowed.
    if target_mode:
        return LiveGateVerdict(
            allowed=True,
            code="sandbox_mode",
            message="Analyze (sandbox) mode is always permitted.",
        )

    effective_env = env if env is not None else os.environ
    if is_emergency_kill_switch_engaged(effective_env):
        reason = (
            "Emergency compliance kill switch (CHIRIFY_EMERGENCY_KILL_SWITCH) is engaged; "
            "all Live mode activations are unconditionally blocked."
        )
        return LiveGateVerdict(
            allowed=False,
            code="emergency_kill_switch_engaged",
            message=f"Live mode blocked [emergency_kill_switch_engaged]: {reason}",
            reasons=(reason,),
        )

    if claims is None and not is_live_gate_enforced(effective_env):
        return LiveGateVerdict(
            allowed=True,
            code="gate_disabled",
            message="CHIRIFY_ENFORCE_LIVE_GATE is disabled; allowing standalone OSS transition.",
        )

    resolved_claims = claims
    if resolved_claims is None:
        secret = str(effective_env.get("CHIRIFY_ENTITLEMENT_SECRET") or "")
        token = str(effective_env.get("CHIRIFY_ENTITLEMENT_TOKEN") or "")
        try:
            resolved_claims = verify_entitlement_token(token, secret, now_epoch=now_epoch)
        except EntitlementVerificationError as exc:
            reason = str(exc)
            return LiveGateVerdict(
                allowed=False,
                code="entitlement_invalid",
                message=f"Live mode blocked [entitlement_invalid]: {reason}",
                reasons=(reason,),
            )

    if broker and not resolved_claims.broker_name:
        inferred_type = _resolve_broker_type(broker, resolved_claims.broker_type)
        resolved_claims = EntitlementClaims.from_mapping(
            {
                **resolved_claims.to_dict(),
                "broker_name": broker,
                "broker_type": inferred_type,
            }
        )

    return evaluate_live_gate(resolved_claims, env=effective_env)


def enforce_live_mode_transition(
    *,
    current_mode: bool = True,
    target_mode: bool = False,
    broker: str | None = None,
    claims: EntitlementClaims | None = None,
    env: Mapping[str, str] | None = None,
    now_epoch: float | None = None,
) -> LiveGateVerdict:
    """Enforce the Cohort-A Live Gate, raising :class:`LiveGateBlockedError` if refused."""
    verdict = check_live_mode_transition(
        current_mode=current_mode,
        target_mode=target_mode,
        broker=broker,
        claims=claims,
        env=env,
        now_epoch=now_epoch,
    )
    if not verdict.allowed:
        raise LiveGateBlockedError(verdict)
    return verdict
