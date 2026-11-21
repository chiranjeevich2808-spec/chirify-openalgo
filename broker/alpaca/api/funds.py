"""Alpaca Account Margin & Funds Mapping (`GET /v2/account`)."""

from __future__ import annotations

from typing import Any

from broker.alpaca.api.order_api import alpaca_request
from utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MARGIN_RESPONSE: dict[str, str] = {
    "availablecash": "0.00",
    "collateral": "0.00",
    "m2mrealized": "0.00",
    "m2munrealized": "0.00",
    "utiliseddebits": "0.00",
}


def _f(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def get_margin_data(auth_token: str, **kwargs: Any) -> dict[str, str]:
    """Fetch Alpaca account balances and normalize into OpenAlgo's margin schema."""
    try:
        status_code, acct = alpaca_request("GET", "/v2/account", auth_token, **kwargs)
        if status_code != 200 or not isinstance(acct, dict):
            return dict(DEFAULT_MARGIN_RESPONSE)

        buying_power = _f(acct.get("buying_power", acct.get("cash")))
        equity = _f(acct.get("equity"))
        last_equity = _f(acct.get("last_equity", equity))
        initial_margin = _f(acct.get("initial_margin"))
        non_marginable = _f(acct.get("non_marginable_buying_power"))

        day_pnl = equity - last_equity
        return {
            "availablecash": f"{buying_power:.2f}",
            "collateral": f"{non_marginable:.2f}",
            "m2mrealized": "0.00",
            "m2munrealized": f"{day_pnl:.2f}",
            "utiliseddebits": f"{initial_margin:.2f}",
        }
    except Exception as exc:
        logger.error(f"[Alpaca] Failed to fetch margin data: {exc}")
        return dict(DEFAULT_MARGIN_RESPONSE)
