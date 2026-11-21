"""CCXT Deterministic Decimal Precision, `contractSize` Normalizer & Nonce Lock Registry.

Eliminates the four classic production failure modes of multi-venue crypto adapters:
1. **IEEE-754 Float Drift**: :class:`PreciseFormatter` uses pure ``decimal.Decimal``
   arithmetic for ``amount_to_precision`` (truncating to step/tick so orders never
   exceed free balance) and ``price_to_precision`` (snapping to exact tick size).
2. **Spot vs Perpetual ``contractSize`` Mismatches**: Normalizes unified spot
   symbols (``BTC/USDT``) vs linear perpetuals (``BTC/USDT:USDT``) and inverse
   perpetuals (``BTC/USD:BTC``) using exact ``contractSize`` scaling.
3. **Rate-Limit & Sandbox Safety**: Enforces ``enableRateLimit=True`` on every
   CCXT client config and catches ``NotSupported`` cleanly on venues without
   sandbox/testnet endpoints when calling ``set_sandbox_mode(True)``.
4. **Cross-Worker ``InvalidNonce`` Collisions**: :class:`ApiKeyNonceLockRegistry`
   locks SHA-256 fingerprints of ``(exchange_id, api_key)`` across threads and
   processes (via optional ``fcntl.flock``) and issues strictly monotonic
   microsecond nonces.
"""

from __future__ import annotations

import fcntl
import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from utils import real_threading


class CCXTConfigError(ValueError):
    """Raised on unsafe or invalid CCXT configuration."""


class CCXTPrecisionError(ValueError):
    """Raised when an amount or price violates exchange precision or min/max limits."""


class DuplicateApiKeyNonceError(RuntimeError):
    """Raised when two workers/pods attempt to bind the same exchange API key concurrently."""


def _dec(value: Decimal | int | float | str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise CCXTPrecisionError(f"Expected numeric value, got {value!r}.")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CCXTPrecisionError("Decimal value must be finite.")
        return value
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise CCXTPrecisionError(f"Invalid numeric value {value!r}: {exc}") from exc
    if not parsed.is_finite():
        raise CCXTPrecisionError(f"Non-finite numeric value {value!r}.")
    return parsed


def _format_clean_decimal(val: Decimal, step: Decimal) -> str:
    """Format quantized Decimal matching ``step``'s scale without scientific notation."""
    quantized = val.quantize(step)
    text = format(quantized, "f")
    if "." in text and step >= Decimal("1"):
        text = text.split(".", 1)[0]
    return text


def _step_from_precision_spec(spec: Any) -> Decimal:
    """Resolve CCXT precision entry (either integer decimal places or tick-size Decimal)."""
    if spec is None:
        return Decimal("0.00000001")
    # Integer decimal places (e.g. precision=4 -> 0.0001; precision=0 -> 1)
    if isinstance(spec, int) and not isinstance(spec, bool) and spec >= 0:
        return Decimal(10) ** (-spec)
    dec_spec = _dec(spec)
    if dec_spec <= 0:
        raise CCXTPrecisionError(f"Precision step must be > 0, got {spec!r}.")
    # In CCXT DECIMAL_PLACES mode an integer float like 4.0 >= 1 with no fractional part
    # greater than 1 can represent decimal places only if explicitly flagged; when < 1 or
    # fractional (e.g. 0.05, 0.001, 1) treat as tick size unless integer >= 2 without tick_mode.
    return dec_spec


class PreciseFormatter:
    """Deterministic ``Decimal`` formatter for CCXT order amounts and prices."""

    @staticmethod
    def _quantize_to_step(value: Decimal, step: Decimal, *, rounding: str) -> str:
        if value <= 0:
            raise CCXTPrecisionError(f"Order value must be > 0, got {value}.")
        units = (value / step).to_integral_value(rounding=rounding)
        snapped = units * step
        if snapped <= 0:
            raise CCXTPrecisionError(
                f"Value {value} rounds down to zero at precision step {step}."
            )
        return _format_clean_decimal(snapped, step)

    @classmethod
    def amount_to_precision(
        cls,
        symbol: str,
        amount: Decimal | int | float | str,
        market: Mapping[str, Any] | None = None,
        *,
        tick_mode: bool | None = None,
    ) -> str:
        """Truncate ``amount`` to exchange precision step and verify ``limits.amount``."""
        dec_amount = _dec(amount)
        mkt = market or {}
        prec_map = mkt.get("precision") or {}
        raw_prec = prec_map.get("amount")

        if isinstance(raw_prec, int) and not isinstance(raw_prec, bool) and tick_mode is not True:
            step = Decimal(10) ** (-raw_prec) if raw_prec >= 0 else Decimal("1")
        else:
            step = _step_from_precision_spec(raw_prec)

        formatted = cls._quantize_to_step(dec_amount, step, rounding=ROUND_DOWN)
        final_dec = Decimal(formatted)

        limits = (mkt.get("limits") or {}).get("amount") or {}
        min_amt = limits.get("min")
        max_amt = limits.get("max")
        if min_amt is not None and final_dec < _dec(min_amt):
            raise CCXTPrecisionError(
                f"{symbol} amount {formatted} is below exchange minimum {min_amt}."
            )
        if max_amt is not None and final_dec > _dec(max_amt):
            raise CCXTPrecisionError(
                f"{symbol} amount {formatted} exceeds exchange maximum {max_amt}."
            )
        return formatted

    @classmethod
    def price_to_precision(
        cls,
        symbol: str,
        price: Decimal | int | float | str,
        market: Mapping[str, Any] | None = None,
        *,
        rounding: str = ROUND_HALF_UP,
        tick_mode: bool | None = None,
    ) -> str:
        """Snap ``price`` to exact exchange tick size and verify ``limits.price``."""
        dec_price = _dec(price)
        mkt = market or {}
        prec_map = mkt.get("precision") or {}
        raw_prec = prec_map.get("price")

        if isinstance(raw_prec, int) and not isinstance(raw_prec, bool) and tick_mode is not True:
            step = Decimal(10) ** (-raw_prec) if raw_prec >= 0 else Decimal("1")
        else:
            step = _step_from_precision_spec(raw_prec)

        formatted = cls._quantize_to_step(dec_price, step, rounding=rounding)
        final_dec = Decimal(formatted)

        limits = (mkt.get("limits") or {}).get("price") or {}
        min_px = limits.get("min")
        max_px = limits.get("max")
        if min_px is not None and final_dec < _dec(min_px):
            raise CCXTPrecisionError(
                f"{symbol} price {formatted} is below exchange minimum {min_px}."
            )
        if max_px is not None and final_dec > _dec(max_px):
            raise CCXTPrecisionError(
                f"{symbol} price {formatted} exceeds exchange maximum {max_px}."
            )
        return formatted


@dataclass(frozen=True, slots=True)
class NormalizedContractOrder:
    """Result of normalizing a spot vs linear/inverse perpetual order size."""

    symbol: str
    market_kind: str  # "spot" | "linear_swap" | "inverse_swap" | "option"
    settle_currency: str | None
    contract_size: Decimal
    order_amount: Decimal
    formatted_amount: str
    base_equivalent: Decimal


def normalize_contract_quantity(
    symbol: str,
    base_quantity: Decimal | int | float | str,
    market: Mapping[str, Any] | None = None,
    *,
    reference_price: Decimal | int | float | str | None = None,
) -> NormalizedContractOrder:
    """Convert a trader's base-asset quantity into CCXT unified spot/contract units.

    - Spot ``BTC/USDT``: 1:1 base units (``contractSize`` ignored).
    - Linear Swap ``BTC/USDT:USDT`` (``contractSize = 0.001`` BTC): ``0.05`` BTC -> ``50`` contracts.
    - Inverse Swap ``BTC/USD:BTC`` (``contractSize = 100`` USD): converts ``base_quantity * reference_price / 100``
      into whole/step USD contracts.
    """
    clean_sym = (symbol or "").strip().upper()
    if "/" not in clean_sym:
        raise ValueError(
            f"Expected unified CCXT symbol ('BASE/QUOTE' or 'BASE/QUOTE:SETTLE'), got {symbol!r}."
        )

    mkt = dict(market or {})
    dec_base_qty = _dec(base_quantity)
    if dec_base_qty <= 0:
        raise CCXTPrecisionError("base_quantity must be > 0.")

    pair_part, settle_part = (
        clean_sym.split(":", 1) if ":" in clean_sym else (clean_sym, None)
    )
    base_ccy, quote_ccy = pair_part.split("/", 1)

    is_spot = settle_part is None and not mkt.get("swap") and not mkt.get("option")
    if is_spot:
        formatted = PreciseFormatter.amount_to_precision(clean_sym, dec_base_qty, mkt)
        final_amt = Decimal(formatted)
        return NormalizedContractOrder(
            symbol=clean_sym,
            market_kind="spot",
            settle_currency=None,
            contract_size=Decimal("1"),
            order_amount=final_amt,
            formatted_amount=formatted,
            base_equivalent=final_amt,
        )

    contract_size = _dec(mkt.get("contractSize", "1"))
    if contract_size <= 0:
        raise CCXTPrecisionError(f"Invalid contractSize={contract_size} for {clean_sym}.")

    is_inverse = bool(mkt.get("inverse")) or (settle_part == base_ccy and base_ccy != quote_ccy)
    is_option = bool(mkt.get("option")) or clean_sym.count("-") >= 2

    if is_inverse:
        if reference_price is None:
            raise CCXTPrecisionError(
                f"Inverse contract {clean_sym} requires reference_price to convert base units to quote-denominated contracts."
            )
        ref_px = _dec(reference_price)
        if ref_px <= 0:
            raise CCXTPrecisionError("reference_price must be > 0.")
        raw_contracts = (dec_base_qty * ref_px) / contract_size
        default_mkt = {"precision": {"amount": 0}, **mkt}
        formatted = PreciseFormatter.amount_to_precision(clean_sym, raw_contracts, default_mkt)
        final_contracts = Decimal(formatted)
        base_equiv = (final_contracts * contract_size) / ref_px
        kind = "inverse_swap"
    else:
        raw_contracts = dec_base_qty / contract_size
        default_mkt = {"precision": {"amount": 0}, **mkt}
        formatted = PreciseFormatter.amount_to_precision(clean_sym, raw_contracts, default_mkt)
        final_contracts = Decimal(formatted)
        base_equiv = final_contracts * contract_size
        kind = "option" if is_option else "linear_swap"

    return NormalizedContractOrder(
        symbol=clean_sym,
        market_kind=kind,
        settle_currency=settle_part,
        contract_size=contract_size,
        order_amount=final_contracts,
        formatted_amount=formatted,
        base_equivalent=base_equiv,
    )


def contracts_to_base_amount(
    contracts: Decimal | int | float | str,
    market: Mapping[str, Any] | None = None,
) -> Decimal:
    """Convert derivative contract count back to base-asset exposure."""
    dec_contracts = _dec(contracts)
    csize = _dec((market or {}).get("contractSize", "1"))
    return dec_contracts * csize


def build_ccxt_exchange_config(
    *,
    api_key: str = "",
    api_secret: str = "",
    password: str | None = None,
    extra_options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a CCXT exchange configuration dictionary enforcing ``enableRateLimit=True``."""
    cfg: dict[str, Any] = {}
    if extra_options:
        if extra_options.get("enableRateLimit") is False:
            raise CCXTConfigError(
                "Disabling CCXT rate limiter (enableRateLimit=False) is forbidden; "
                "causes IP bans across crypto venues."
            )
        cfg.update(extra_options)

    cfg["enableRateLimit"] = True
    if api_key.strip():
        cfg["apiKey"] = api_key.strip()
    if api_secret.strip():
        cfg["secret"] = api_secret.strip()
    if password:
        cfg["password"] = password
    return cfg


@dataclass(frozen=True, slots=True)
class SandboxCapabilityResult:
    """Result of attempting ``exchange.set_sandbox_mode(True)``."""

    requested: bool
    enabled: bool
    supported: bool
    reason: str = ""


def configure_sandbox_mode(exchange: Any, enabled: bool = True) -> SandboxCapabilityResult:
    """Safely enable CCXT sandbox/testnet mode, catching ``NotSupported`` cleanly."""
    if not enabled:
        return SandboxCapabilityResult(
            requested=False,
            enabled=False,
            supported=bool((getattr(exchange, "has", None) or {}).get("sandbox", False)),
            reason="Live venue mode requested.",
        )

    has_map = getattr(exchange, "has", None) or {}
    if has_map.get("sandbox") is False:
        return SandboxCapabilityResult(
            requested=True,
            enabled=False,
            supported=False,
            reason=f"Exchange {getattr(exchange, 'id', 'unknown')!r} declares has['sandbox']=False.",
        )

    setter = getattr(exchange, "set_sandbox_mode", None)
    if not callable(setter):
        return SandboxCapabilityResult(
            requested=True,
            enabled=False,
            supported=False,
            reason="Exchange object does not implement set_sandbox_mode().",
        )

    try:
        setter(True)
        return SandboxCapabilityResult(
            requested=True,
            enabled=True,
            supported=True,
            reason="Sandbox/testnet mode enabled.",
        )
    except Exception as exc:
        # Catch ccxt.NotSupported (without requiring ccxt installed at import time)
        if type(exc).__name__ == "NotSupported" or "not supported" in str(exc).lower() or "sandbox" in str(exc).lower():
            return SandboxCapabilityResult(
                requested=True,
                enabled=False,
                supported=False,
                reason=f"Sandbox mode not supported by venue: {exc}",
            )
        raise


class ApiKeyNonceLockRegistry:
    """Pod/process SHA-256 API-key lock & monotonic nonce generator preventing ``InvalidNonce``."""

    def __init__(self, *, lock_dir: str | Path | None = None) -> None:
        self._lock = real_threading.RLock()
        self._active_holders: dict[str, str] = {}  # key_hash -> holder_id
        self._last_nonce: dict[str, int] = {}
        self._flock_fds: dict[str, Any] = {}
        self._lock_dir = Path(lock_dir) if lock_dir is not None else None
        if self._lock_dir is not None:
            self._lock_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def fingerprint(exchange_id: str, api_key: str) -> str:
        """Return 64-char SHA-256 hex digest of ``exchange_id:api_key`` (never logs raw key)."""
        ex = (exchange_id or "").strip().lower()
        key = (api_key or "").strip()
        if not ex or not key:
            raise ValueError("exchange_id and api_key must both be non-empty.")
        return hashlib.sha256(f"{ex}:{key}".encode("utf-8")).hexdigest()

    def register(self, exchange_id: str, api_key: str, *, holder_id: str) -> str:
        """Acquire exclusive nonce lock for ``(exchange_id, api_key)``."""
        fp = self.fingerprint(exchange_id, api_key)
        clean_holder = (holder_id or "").strip()
        if not clean_holder:
            raise ValueError("holder_id must be non-empty.")

        with self._lock:
            existing = self._active_holders.get(fp)
            if existing is not None and existing != clean_holder:
                raise DuplicateApiKeyNonceError(
                    f"API key fingerprint {fp[:12]}... on {exchange_id!r} is already locked "
                    f"by {existing!r}; sharing one CCXT API key across workers causes InvalidNonce collisions."
                )

            if self._lock_dir is not None and fp not in self._flock_fds:
                lock_file = self._lock_dir / f"ccxt_nonce_{fp[:24]}.lock"
                fh = open(lock_file, "a+", encoding="utf-8")
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    fh.close()
                    raise DuplicateApiKeyNonceError(
                        f"Cross-process flock held for {exchange_id!r} key {fp[:12]}...; "
                        "issue a dedicated sub-account API key per worker."
                    ) from exc
                self._flock_fds[fp] = fh

            self._active_holders[fp] = clean_holder
        return fp

    def release(self, exchange_id: str, api_key: str, *, holder_id: str) -> None:
        """Release the exclusive API-key lock held by ``holder_id``."""
        fp = self.fingerprint(exchange_id, api_key)
        with self._lock:
            if self._active_holders.get(fp) != holder_id:
                return
            self._active_holders.pop(fp, None)
            fh = self._flock_fds.pop(fp, None)
            if fh is not None:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                finally:
                    fh.close()

    def next_nonce(self, exchange_id: str, api_key: str) -> int:
        """Generate a strictly monotonic microsecond nonce for ``(exchange_id, api_key)``."""
        fp = self.fingerprint(exchange_id, api_key)
        with self._lock:
            candidate = time.time_ns() // 1_000
            prev = self._last_nonce.get(fp, 0)
            nonce = candidate if candidate > prev else prev + 1
            self._last_nonce[fp] = nonce
            return nonce


GLOBAL_CCXT_NONCE_REGISTRY = ApiKeyNonceLockRegistry()
