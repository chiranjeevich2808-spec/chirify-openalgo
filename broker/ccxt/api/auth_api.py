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
    ex_id = (exchange_id or os.getenv("CCXT_EXCHANGE_ID") or "binance").strip().lower()
    key = (api_key if api_key is not None else os.getenv("BROKER_API_KEY", "")).strip()
    secret = (api_secret if api_secret is not None else os.getenv("BROKER_API_SECRET", "")).strip()

    if not key:
        return None, "BROKER_API_KEY is not set"
    if not secret:
        return None, "BROKER_API_SECRET is not set"

    registry = nonce_registry or GLOBAL_CCXT_NONCE_REGISTRY
    try:
        build_ccxt_exchange_config(api_key=key, api_secret=secret, password=password)
        registry.register(ex_id, key, holder_id=holder_id)

        if exchange_instance is not None:
            sb = configure_sandbox_mode(exchange_instance, enabled=sandbox)
            if sandbox and not sb.supported:
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
