"""IBKR Broker Authentication Entrypoint for OpenAlgo."""

from __future__ import annotations

import os

import httpx

from broker.ibkr.api.oauth_web_api import (
    IBKRAuthError,
    IBKRCompetingSessionError,
    IBKROAuthWebClient,
    SingleBrokerageSessionGuard,
)
from utils.logging import get_logger

logger = get_logger(__name__)


def authenticate_broker(
    code: str | None = None,
    *,
    access_token: str | None = None,
    username: str | None = None,
    owner_id: str = "openalgo_pod",
    client: httpx.Client | None = None,
    session_guard: SingleBrokerageSessionGuard | None = None,
) -> tuple[str | None, str | None]:
    """Authenticate with IBKR Unified OAuth 2.0 Web API and initialize ``iserver``."""
    token = (
        access_token
        or code
        or os.getenv("IBKR_OAUTH_ACCESS_TOKEN")
        or os.getenv("BROKER_API_KEY")
        or ""
    ).strip()
    user = (username or os.getenv("IBKR_USERNAME") or "default_ibkr_user").strip()

    if not token:
        return None, "IBKR OAuth 2.0 access token is not configured"

    try:
        web_client = IBKROAuthWebClient(
            token,
            username=user,
            owner_id=owner_id,
            client=client,
            session_guard=session_guard,
        )
        web_client.init_brokerage_session(compete=False)
        return token, None
    except (IBKRAuthError, IBKRCompetingSessionError, ValueError) as exc:
        logger.error(f"[IBKR] Authentication failed: {exc}")
        return None, str(exc)
    except Exception as exc:
        logger.exception(f"[IBKR] Unexpected authentication error: {exc}")
        return None, str(exc)
