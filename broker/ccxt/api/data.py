"""CCXT Market Data Adapter (Quotes, Orderbook Depth, Historical OHLCV)."""

from __future__ import annotations

from typing import Any

import pandas as pd


def get_quotes(symbol: str, *, exchange_instance: Any) -> dict[str, Any]:
    """Fetch ticker snapshot via CCXT ``fetch_ticker``."""
    ticker = exchange_instance.fetch_ticker(symbol)
    return {
        "ltp": float(ticker.get("last") or 0.0),
        "bid": float(ticker.get("bid") or 0.0),
        "ask": float(ticker.get("ask") or 0.0),
        "open": float(ticker.get("open") or 0.0),
        "high": float(ticker.get("high") or 0.0),
        "low": float(ticker.get("low") or 0.0),
        "prev_close": float(ticker.get("previousClose") or 0.0),
        "volume": float(ticker.get("baseVolume") or 0.0),
        "oi": 0,
    }


def get_history(
    symbol: str,
    timeframe: str = "1m",
    since_ms: int | None = None,
    limit: int = 500,
    *,
    exchange_instance: Any,
) -> pd.DataFrame:
    """Fetch OHLCV candles via CCXT ``fetch_ohlcv``."""
    candles = exchange_instance.fetch_ohlcv(symbol, timeframe=timeframe, since=since_ms, limit=limit)
    if not candles:
        return pd.DataFrame(columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])
    return pd.DataFrame(
        [
            {
                "timestamp": int(row[0]) // 1000,
                "open": float(row[1]),
                "high": float(row[2]),
                "low": float(row[3]),
                "close": float(row[4]),
                "volume": float(row[5]),
                "oi": 0,
            }
            for row in candles
        ]
    )
