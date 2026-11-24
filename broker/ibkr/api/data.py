"""IBKR Market Data Snapshot & Historical Bars Adapter."""

from __future__ import annotations

from typing import Any

import pandas as pd

from broker.ibkr.api.oauth_web_api import IBKROAuthWebClient


def get_quotes(
    conid: int | str,
    auth_token: str,
    *,
    web_client: IBKROAuthWebClient | None = None,
) -> dict[str, Any]:
    """Fetch IBKR market data snapshot (fields: 31=Last, 84=Bid, 86=Ask, 70=High, 71=Low, 87=Vol)."""
    client = web_client or IBKROAuthWebClient(auth_token, owner_id="marketdata")
    status_code, data = client.request(
        "GET",
        "/iserver/marketdata/snapshot",
        params={"conids": str(conid), "fields": "31,84,86,70,71,87"},
    )
    snap = data[0] if status_code == 200 and isinstance(data, list) and data else {}

    def _num(key: str) -> float:
        raw = str(snap.get(key) or "0").lstrip("C").lstrip("H")
        try:
            return float(raw)
        except ValueError:
            return 0.0

    return {
        "ltp": _num("31"),
        "bid": _num("84"),
        "ask": _num("86"),
        "high": _num("70"),
        "low": _num("71"),
        "volume": int(_num("87")),
    }


def get_history(
    conid: int | str,
    period: str,
    bar: str,
    auth_token: str,
    *,
    web_client: IBKROAuthWebClient | None = None,
) -> pd.DataFrame:
    """Fetch IBKR historical OHLCV bars via ``GET /iserver/marketdata/history``."""
    client = web_client or IBKROAuthWebClient(auth_token, owner_id="marketdata")
    status_code, resp = client.request(
        "GET",
        "/iserver/marketdata/history",
        params={"conid": str(conid), "period": period, "bar": bar},
    )
    bars = resp.get("data", []) if status_code == 200 and isinstance(resp, dict) else []
    if not bars:
        return pd.DataFrame(columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])

    return pd.DataFrame(
        [
            {
                "timestamp": int(item["t"]) // 1000,
                "open": float(item["o"]),
                "high": float(item["h"]),
                "low": float(item["l"]),
                "close": float(item["c"]),
                "volume": int(float(item.get("v", 0))),
                "oi": 0,
            }
            for item in bars
        ]
    )
