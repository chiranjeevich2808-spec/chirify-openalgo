"""CCXT Wallet Balance & Margin Adapter."""

from __future__ import annotations

from typing import Any

DEFAULT_MARGIN_RESPONSE: dict[str, str] = {
    "availablecash": "0.00",
    "collateral": "0.00",
    "m2mrealized": "0.00",
    "m2munrealized": "0.00",
    "utiliseddebits": "0.00",
}


def get_margin_data(
    auth_token: str,
    *,
    quote_currency: str = "USDT",
    exchange_instance: Any | None = None,
) -> dict[str, str]:
    """Fetch CCXT ``fetch_balance()`` and return OpenAlgo standard margin fields."""
    if exchange_instance is None or not hasattr(exchange_instance, "fetch_balance"):
        return dict(DEFAULT_MARGIN_RESPONSE)
    try:
        bal = exchange_instance.fetch_balance()
        free = float((bal.get("free") or {}).get(quote_currency, 0.0) or 0.0)
        used = float((bal.get("used") or {}).get(quote_currency, 0.0) or 0.0)
        total = float((bal.get("total") or {}).get(quote_currency, 0.0) or 0.0)
        return {
            "availablecash": f"{free:.2f}",
            "collateral": f"{total:.2f}",
            "m2mrealized": "0.00",
            "m2munrealized": "0.00",
            "utiliseddebits": f"{used:.2f}",
        }
    except Exception:
        return dict(DEFAULT_MARGIN_RESPONSE)
