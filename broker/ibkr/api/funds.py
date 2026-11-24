"""IBKR Portfolio Margin & Account Summary Adapter."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from broker.ibkr.api.oauth_web_api import IBKROAuthWebClient
from utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MARGIN_RESPONSE: dict[str, str] = {
    "availablecash": "0.00",
    "collateral": "0.00",
    "m2mrealized": "0.00",
    "m2munrealized": "0.00",
    "utiliseddebits": "0.00",
}


def _extract_amount(summary: Mapping[str, Any], field: str) -> float:
    entry = summary.get(field)
    if isinstance(entry, Mapping):
        try:
            return float(entry.get("amount") or 0.0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def get_margin_data(
    auth_token: str,
    *,
    account_id: str | None = None,
    web_client: IBKROAuthWebClient | None = None,
) -> dict[str, str]:
    """Fetch IBKR ``/portfolio/{accountId}/summary`` and format as OpenAlgo margin."""
    acct = (account_id or os.getenv("IBKR_ACCOUNT_ID") or "DU000000").strip()
    try:
        client = web_client or IBKROAuthWebClient(auth_token, owner_id=f"funds_{acct}")
        status_code, summary = client.request("GET", f"/portfolio/{acct}/summary")
        if status_code != 200 or not isinstance(summary, Mapping):
            return dict(DEFAULT_MARGIN_RESPONSE)

        available = _extract_amount(summary, "availablefunds")
        excess_liq = _extract_amount(summary, "excessliquidity")
        maint_margin = _extract_amount(summary, "maintmarginreq")

        return {
            "availablecash": f"{available:.2f}",
            "collateral": f"{excess_liq:.2f}",
            "m2mrealized": "0.00",
            "m2munrealized": "0.00",
            "utiliseddebits": f"{maint_margin:.2f}",
        }
    except Exception as exc:
        logger.error(f"[IBKR] Failed to fetch margin data: {exc}")
        return dict(DEFAULT_MARGIN_RESPONSE)
