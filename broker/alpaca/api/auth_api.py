"""Alpaca Authentication & Strict Paper vs Live Host/Credential Separation.

Prevents accidental routing of Alpaca Live API keys (``AK...``) to Paper
(``https://paper-api.alpaca.markets``) or Paper API keys (``PK...``) to Live
(``https://api.alpaca.markets``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from broker.alpaca.api.rate_limiter import DEFAULT_ALPACA_LIMITER, TokenBucketLimiter
from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)

PAPER_TRADING_BASE_URL = "https://paper-api.alpaca.markets"
LIVE_TRADING_BASE_URL = "https://api.alpaca.markets"
MARKET_DATA_BASE_URL = "https://data.alpaca.markets"


class AlpacaEnvironmentMismatchError(ValueError):
    """Raised when Paper/Live API key prefix conflicts with the configured Alpaca host."""


@dataclass(frozen=True, slots=True)
class AlpacaEndpointConfig:
    """Validated, environment-isolated Alpaca endpoint and credential descriptor."""

    api_key: str
    paper: bool
    trading_base_url: str
    data_base_url: str = MARKET_DATA_BASE_URL


def resolve_alpaca_environment(
    api_key: str,
    *,
    paper: bool | None = None,
    base_url: str | None = None,
) -> AlpacaEndpointConfig:
    """Validate API key prefix against ``paper`` flag and ``base_url`` host.

    Rules:
    - Keys starting with ``PK`` are Paper keys -> must target ``https://paper-api.alpaca.markets``.
    - Keys starting with ``AK`` are Live keys -> must target ``https://api.alpaca.markets``.
    - Any cross-wiring between ``PK``/``AK`` and ``paper``/``base_url`` raises
      :class:`AlpacaEnvironmentMismatchError`.
    """
    clean_key = (api_key or "").strip()
    if not clean_key:
        raise AlpacaEnvironmentMismatchError("Alpaca API key must not be empty.")

    upper_key = clean_key.upper()
    is_paper_key = upper_key.startswith("PK")
    is_live_key = upper_key.startswith("AK")

    if not (is_paper_key or is_live_key):
        raise AlpacaEnvironmentMismatchError(
            "Alpaca API key must carry a valid 'PK' (Paper) or 'AK' (Live) prefix."
        )

    clean_url = (base_url or "").strip().rstrip("/")
    if clean_url and clean_url not in {PAPER_TRADING_BASE_URL, LIVE_TRADING_BASE_URL}:
        raise AlpacaEnvironmentMismatchError(
            f"Untrusted or non-HTTPS Alpaca base_url {clean_url!r}; expected "
            f"{PAPER_TRADING_BASE_URL!r} or {LIVE_TRADING_BASE_URL!r}."
        )

    if is_paper_key:
        if paper is False:
            raise AlpacaEnvironmentMismatchError(
                "Paper API key (PK*) cannot be used when paper=False (Live mode)."
            )
        if clean_url == LIVE_TRADING_BASE_URL:
            raise AlpacaEnvironmentMismatchError(
                f"Paper API key (PK*) cannot target Live host {LIVE_TRADING_BASE_URL}."
            )
        return AlpacaEndpointConfig(
            api_key=clean_key,
            paper=True,
            trading_base_url=PAPER_TRADING_BASE_URL,
        )

    # Live key (AK*)
    if paper is True:
        raise AlpacaEnvironmentMismatchError(
            "Live API key (AK*) cannot be used when paper=True (Paper mode)."
        )
    if clean_url == PAPER_TRADING_BASE_URL:
        raise AlpacaEnvironmentMismatchError(
            f"Live API key (AK*) cannot target Paper host {PAPER_TRADING_BASE_URL}."
        )
    return AlpacaEndpointConfig(
        api_key=clean_key,
        paper=False,
        trading_base_url=LIVE_TRADING_BASE_URL,
    )


def build_alpaca_headers(api_key: str, api_secret: str) -> dict[str, str]:
    """Build Alpaca v2 authentication headers."""
    clean_secret = (api_secret or "").strip()
    if not clean_secret:
        raise ValueError("Alpaca API secret must not be empty.")
    return {
        "APCA-API-KEY-ID": api_key.strip(),
        "APCA-API-SECRET-KEY": clean_secret,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _env_paper_preference() -> bool | None:
    raw = os.getenv("ALPACA_PAPER", "").strip().lower()
    if raw in {"true", "1", "yes"}:
        return True
    if raw in {"false", "0", "no"}:
        return False
    return None


def authenticate_broker(
    code: str | None = None,
    *,
    api_key: str | None = None,
    api_secret: str | None = None,
    paper: bool | None = None,
    base_url: str | None = None,
    client: httpx.Client | None = None,
    limiter: TokenBucketLimiter | None = None,
) -> tuple[str | None, str | None]:
    """Authenticate with Alpaca Markets and verify Paper/Live account isolation.

    Returns:
        ``(api_key, None)`` on success or ``(None, error_message)`` on failure.
    """
    resolved_key = (api_key if api_key is not None else os.getenv("BROKER_API_KEY", "")).strip()
    resolved_secret = (
        api_secret if api_secret is not None else os.getenv("BROKER_API_SECRET", "")
    ).strip()

    if not resolved_key:
        return None, "BROKER_API_KEY is not set"
    if not resolved_secret:
        return None, "BROKER_API_SECRET is not set"

    resolved_paper = paper if paper is not None else _env_paper_preference()
    resolved_url = base_url if base_url is not None else os.getenv("ALPACA_BASE_URL")

    try:
        endpoint = resolve_alpaca_environment(
            resolved_key, paper=resolved_paper, base_url=resolved_url
        )
        headers = build_alpaca_headers(endpoint.api_key, resolved_secret)
        active_limiter = limiter or DEFAULT_ALPACA_LIMITER
        active_limiter.acquire(max_wait=5.0)

        http = client or get_httpx_client()
        resp = http.get(f"{endpoint.trading_base_url}/v2/account", headers=headers, timeout=15.0)
        if resp.status_code == 200:
            acct = resp.json()
            if acct.get("trading_blocked"):
                return None, "Alpaca account has trading_blocked=True"
            logger.info(
                f"[Alpaca] Authenticated ({'paper' if endpoint.paper else 'live'}) "
                f"account={acct.get('account_number', 'unknown')}"
            )
            return endpoint.api_key, None
        if resp.status_code in (401, 403):
            return None, f"Alpaca authentication rejected (HTTP {resp.status_code})"
        return None, f"Unexpected HTTP {resp.status_code} from Alpaca: {resp.text[:200]}"
    except AlpacaEnvironmentMismatchError as exc:
        logger.error(f"[Alpaca] Environment isolation violation: {exc}")
        return None, str(exc)
    except Exception as exc:
        logger.exception(f"[Alpaca] Authentication failed: {exc}")
        return None, str(exc)
