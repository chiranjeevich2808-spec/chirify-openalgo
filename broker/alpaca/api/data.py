"""Alpaca Market Data Adapter (`US_EQUITY`, `US_OPTIONS`, `CRYPTO`)."""

from __future__ import annotations

import os
from typing import Any

import httpx
import pandas as pd

from broker.alpaca.api.auth_api import (
    MARKET_DATA_BASE_URL,
    build_alpaca_headers,
    resolve_alpaca_environment,
)
from broker.alpaca.api.order_api import normalize_alpaca_symbol
from utils.httpx_client import get_httpx_client


def get_quotes(
    symbol: str,
    exchange: str,
    auth_token: str,
    *,
    api_secret: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Fetch latest quote + trade snapshot from ``https://data.alpaca.markets``."""
    secret = (api_secret if api_secret is not None else os.getenv("BROKER_API_SECRET", "")).strip()
    endpoint = resolve_alpaca_environment(auth_token)
    headers = build_alpaca_headers(endpoint.api_key, secret)
    norm_sym = normalize_alpaca_symbol(symbol, exchange)
    exch = (exchange or "US_EQUITY").strip().upper()

    http = client or get_httpx_client()
    if exch == "CRYPTO":
        resp = http.get(
            f"{MARKET_DATA_BASE_URL}/v1beta3/crypto/us/snapshots",
            params={"symbols": norm_sym},
            headers=headers,
            timeout=15.0,
        )
        snap = (resp.json().get("snapshots") or {}).get(norm_sym, {}) if resp.status_code == 200 else {}
    elif exch == "US_OPTIONS":
        resp = http.get(
            f"{MARKET_DATA_BASE_URL}/v1beta1/options/snapshots/{norm_sym}",
            headers=headers,
            timeout=15.0,
        )
        snap = resp.json() if resp.status_code == 200 else {}
    else:
        resp = http.get(
            f"{MARKET_DATA_BASE_URL}/v2/stocks/{norm_sym}/snapshot",
            headers=headers,
            timeout=15.0,
        )
        snap = resp.json() if resp.status_code == 200 else {}

    trade = snap.get("latestTrade") or {}
    quote = snap.get("latestQuote") or {}
    bar = snap.get("dailyBar") or {}
    prev_bar = snap.get("prevDailyBar") or {}

    return {
        "ltp": float(trade.get("p") or 0.0),
        "bid": float(quote.get("bp") or 0.0),
        "ask": float(quote.get("ap") or 0.0),
        "open": float(bar.get("o") or 0.0),
        "high": float(bar.get("h") or 0.0),
        "low": float(bar.get("l") or 0.0),
        "prev_close": float(prev_bar.get("c") or 0.0),
        "volume": int(bar.get("v") or 0),
        "oi": 0,
    }


def get_history(
    symbol: str,
    exchange: str,
    interval: str,
    start_date: str,
    end_date: str,
    auth_token: str,
    *,
    api_secret: str | None = None,
    client: httpx.Client | None = None,
) -> pd.DataFrame:
    """Fetch historical OHLCV bars as a normalized OpenAlgo DataFrame."""
    secret = (api_secret if api_secret is not None else os.getenv("BROKER_API_SECRET", "")).strip()
    endpoint = resolve_alpaca_environment(auth_token)
    headers = build_alpaca_headers(endpoint.api_key, secret)
    norm_sym = normalize_alpaca_symbol(symbol, exchange)
    exch = (exchange or "US_EQUITY").strip().upper()

    tf_map = {"1m": "1Min", "5m": "5Min", "15m": "15Min", "30m": "30Min", "1h": "1Hour", "D": "1Day"}
    timeframe = tf_map.get(interval, "1Day")
    http = client or get_httpx_client()

    if exch == "CRYPTO":
        resp = http.get(
            f"{MARKET_DATA_BASE_URL}/v1beta3/crypto/us/bars",
            params={"symbols": norm_sym, "timeframe": timeframe, "start": start_date, "end": end_date},
            headers=headers,
            timeout=20.0,
        )
        bars = (resp.json().get("bars") or {}).get(norm_sym, []) if resp.status_code == 200 else []
    else:
        resp = http.get(
            f"{MARKET_DATA_BASE_URL}/v2/stocks/{norm_sym}/bars",
            params={"timeframe": timeframe, "start": start_date, "end": end_date},
            headers=headers,
            timeout=20.0,
        )
        bars = resp.json().get("bars", []) if resp.status_code == 200 else []

    if not bars:
        return pd.DataFrame(columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])

    rows = [
        {
            "timestamp": int(pd.Timestamp(b["t"]).timestamp()),
            "open": float(b["o"]),
            "high": float(b["h"]),
            "low": float(b["l"]),
            "close": float(b["c"]),
            "volume": int(b.get("v", 0)),
            "oi": 0,
        }
        for b in bars
    ]
    return pd.DataFrame(rows)
