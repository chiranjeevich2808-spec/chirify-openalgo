"""CCXT Broker Authentication Entrypoint for OpenAlgo."""

from __future__ import annotations

import os
from typing import Any

from broker.ccxt.api.precision_and_nonce import (
    GLOBAL_CCXT_NONCE_REGISTRY,
    ApiKeyNonceLockRegistry,
    DuplicateApiKeyNonceError,
    build_ccxt_exchange_config,
    configure_sandbox_mode,
)
from utils.logging import get_logger

logger = get_logger(__name__)


def authenticate_broker(
    code: str | None = None,
    *,
    exchange_id: str | None = None,
    api_key: str | None = None,
    api_secret: str | None = None,
    password: str | None = None,
    sandbox: bool = False,
    holder_id: str = "openalgo_main",
    exchange_instance: Any | None = None,
    nonce_registry: ApiKeyNonceLockRegistry | None = None,
) -> tuple[str | None, str | None]:
    """Validate CCXT credentials, acquire SHA-256 nonce lock, and optionally enable sandbox."""
    raw_market = (os.getenv("BROKER_API_KEY_MARKET") or "").strip().lower()
    market_ex_id = ""
    market_sandbox = False
    if raw_market:
        parts = [p.strip() for p in raw_market.split(":") if p.strip()]
        if parts:
            market_ex_id = parts[0]
            market_sandbox = any(flag in {"testnet", "sandbox"} for flag in parts[1:])

    key = (api_key if api_key is not None else os.getenv("BROKER_API_KEY", "")).strip()
    inline_ex_id = ""
    if ":::" in key:
        inline_ex_id, key = [seg.strip() for seg in key.split(":::", 1)]
        inline_ex_id = inline_ex_id.lower()

    ex_id = (
        exchange_id or os.getenv("CCXT_EXCHANGE_ID") or market_ex_id or inline_ex_id or "binance"
    ).strip().lower()
    secret = (api_secret if api_secret is not None else os.getenv("BROKER_API_SECRET", "")).strip()
    resolved_password = (
        password
        if password is not None
        else (os.getenv("CCXT_PASSWORD") or os.getenv("BROKER_API_SECRET_MARKET") or None)
    )
    resolved_sandbox = bool(sandbox or market_sandbox)

    if not key:
        return None, "BROKER_API_KEY is not set"
    if not secret:
        return None, "BROKER_API_SECRET is not set"

    registry = nonce_registry or GLOBAL_CCXT_NONCE_REGISTRY
    try:
        build_ccxt_exchange_config(api_key=key, api_secret=secret, password=resolved_password)
        registry.register(ex_id, key, holder_id=holder_id)

        if exchange_instance is not None:
            sb = configure_sandbox_mode(exchange_instance, enabled=resolved_sandbox)
            if resolved_sandbox and not sb.supported:
                registry.release(ex_id, key, holder_id=holder_id)
                return None, sb.reason
            if hasattr(exchange_instance, "fetch_balance"):
                exchange_instance.fetch_balance()

        return f"{ex_id}:{key}", None
    except DuplicateApiKeyNonceError as exc:
        logger.error(f"[CCXT] Nonce lock conflict: {exc}")
        return None, str(exc)
    except Exception as exc:
        registry.release(ex_id, key, holder_id=holder_id)
        logger.exception(f"[CCXT] Authentication error on {ex_id}: {exc}")
        return None, str(exc)
