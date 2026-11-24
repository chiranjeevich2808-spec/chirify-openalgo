"""Idempotent Analyzer Sandbox & Multi-Asset Historify DuckDB Bootstrap Service.

Provisions a ready-to-trade, 100% genuine Analyzer Sandbox environment for Chirify
managed pods without requiring external broker OAuth credentials:

1. **Multi-Asset Historify DuckDB 1.5.5 Seeding (49 Core Symbols):**
   - 22 NIFTY50 NSE equities + 2 NSE indices (``NIFTY``, ``BANKNIFTY``)
   - 15 US equities & ETFs (``US_EQUITY``)
   - 10 Crypto USDT pairs (``CRYPTO``)
   - Hybrid online-first Yahoo Finance v8 Chart API (using stdlib ``urllib.request``
     so it respects proxies without ``httpx``'s ``NO_PROXY`` IPv6 parse bug) with
     a fast deterministic offline institutional generator (PCG64 + cross-asset
     latent market/sector factors + 3-state Markov regime switching + GARCH(1,1)
     volatility clustering + Merton jumps + Half-Normal wicks + quadratic
     U-shaped intraday volume — **strictly zero ``math.sin()``/``math.cos()``**).
   - Seeds ~740–755 Daily (``D``) bars for all 49 symbols and >=375 ``1m``
     intraday bars (anchored to the latest daily close) for 16 flagship symbols
     (automatically enabling ``1m/5m/15m/30m/1h/D/W/M`` via Historify).
   - Consistently populates ``market_data``, ``data_catalog``, ``watchlist``,
     and ``symbol_metadata``.
2. **Idempotent ``SymToken`` Seeding & Cache Refresh:**
   - All 49 core spot/index/crypto instruments + dynamic future-dated ``NFO``
     option chains for ``NIFTY`` (lotsize 75, step 50) & ``BANKNIFTY`` (lotsize
     30, step 100) across 3 upcoming future Thursdays × 15 strikes around actual
     seeded spot × CE/PE + near-month FUT contracts.
   - Calls ``load_cache_for_broker("chirify_sandbox")`` and ``clear_strikes_cache()``.
3. **Idempotent Sandbox ``Auth`` & ``SandboxFunds`` Provisioning:**
   - Inserts ``Auth(broker="chirify_sandbox", is_revoked=False)`` ONLY when no
     active ``Auth`` row exists (never overwrites an active live broker!).
   - Initializes ``SandboxFunds`` via ``FundManager`` ONLY if no row exists.
   - Configures ``sandbox_24x7="true"`` in ``SandboxConfig`` when requested.

CLI usage::

    python -m services.chirify_sandbox_bootstrap --seed-mode auto
    python -m services.chirify_sandbox_bootstrap --seed-mode synthetic --force-reseed
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import math
import os
import secrets
import sys
import urllib.parse
import urllib.request
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from utils.logging import get_logger

logger = get_logger(__name__)

_IST = ZoneInfo("Asia/Kolkata")
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True, slots=True)
class CoreInstrument:
    symbol: str
    exchange: str
    name: str
    yahoo_ticker: str
    anchor_price: float
    sector: str
    instrumenttype: str
    lotsize: int
    tick_size: float
    base_volume: int
    beta_mkt: float = 0.72
    beta_sec: float = 0.32
    ann_vol: float = 0.24
    flagship_intraday: bool = False


# 49 Core Multi-Asset Instruments: 22 NSE + 2 NSE_INDEX + 15 US_EQUITY + 10 CRYPTO
CORE_UNIVERSE: tuple[CoreInstrument, ...] = (
    # --- 22 NIFTY50 NSE Equities ---
    CoreInstrument("RELIANCE", "NSE", "Reliance Industries", "RELIANCE.NS", 1380.0, "ENERGY", "EQ", 1, 0.05, 9_500_000, 0.78, 0.35, 0.23, True),
    CoreInstrument("TCS", "NSE", "Tata Consultancy Services", "TCS.NS", 4120.0, "IT", "EQ", 1, 0.05, 2_800_000, 0.65, 0.48, 0.21, True),
    CoreInstrument("HDFCBANK", "NSE", "HDFC Bank", "HDFCBANK.NS", 1740.0, "BANKING", "EQ", 1, 0.05, 14_200_000, 0.82, 0.42, 0.22, True),
    CoreInstrument("INFY", "NSE", "Infosys", "INFY.NS", 1890.0, "IT", "EQ", 1, 0.05, 7_600_000, 0.68, 0.50, 0.24, True),
    CoreInstrument("ICICIBANK", "NSE", "ICICI Bank", "ICICIBANK.NS", 1290.0, "BANKING", "EQ", 1, 0.05, 12_500_000, 0.84, 0.45, 0.23, True),
    CoreInstrument("SBIN", "NSE", "State Bank of India", "SBIN.NS", 840.0, "BANKING", "EQ", 1, 0.05, 16_000_000, 0.80, 0.44, 0.28, True),
    CoreInstrument("BHARTIARTL", "NSE", "Bharti Airtel", "BHARTIARTL.NS", 1620.0, "TELECOM", "EQ", 1, 0.05, 5_400_000, 0.66, 0.25, 0.22, False),
    CoreInstrument("ITC", "NSE", "ITC Limited", "ITC.NS", 475.0, "CONSUMER", "EQ", 1, 0.05, 13_400_000, 0.55, 0.32, 0.19, False),
    CoreInstrument("LT", "NSE", "Larsen & Toubro", "LT.NS", 3680.0, "INFRA", "EQ", 1, 0.05, 2_300_000, 0.79, 0.36, 0.25, False),
    CoreInstrument("AXISBANK", "NSE", "Axis Bank", "AXISBANK.NS", 1185.0, "BANKING", "EQ", 1, 0.05, 9_800_000, 0.81, 0.46, 0.26, False),
    CoreInstrument("KOTAKBANK", "NSE", "Kotak Mahindra Bank", "KOTAKBANK.NS", 1785.0, "BANKING", "EQ", 1, 0.05, 4_700_000, 0.74, 0.43, 0.24, False),
    CoreInstrument("BAJFINANCE", "NSE", "Bajaj Finance", "BAJFINANCE.NS", 7150.0, "BANKING", "EQ", 1, 0.05, 1_400_000, 0.85, 0.40, 0.29, False),
    CoreInstrument("MARUTI", "NSE", "Maruti Suzuki India", "MARUTI.NS", 12450.0, "AUTO", "EQ", 1, 0.05, 520_000, 0.69, 0.34, 0.23, False),
    CoreInstrument("SUNPHARMA", "NSE", "Sun Pharmaceutical", "SUNPHARMA.NS", 1840.0, "PHARMA", "EQ", 1, 0.05, 2_400_000, 0.52, 0.38, 0.22, False),
    CoreInstrument("TITAN", "NSE", "Titan Company", "TITAN.NS", 3420.0, "CONSUMER", "EQ", 1, 0.05, 1_350_000, 0.67, 0.35, 0.25, False),
    CoreInstrument("HCLTECH", "NSE", "HCL Technologies", "HCLTECH.NS", 1815.0, "IT", "EQ", 1, 0.05, 3_100_000, 0.64, 0.49, 0.24, False),
    CoreInstrument("WIPRO", "NSE", "Wipro", "WIPRO.NS", 565.0, "IT", "EQ", 1, 0.05, 8_200_000, 0.66, 0.47, 0.25, False),
    CoreInstrument("HINDUNILVR", "NSE", "Hindustan Unilever", "HINDUNILVR.NS", 2520.0, "CONSUMER", "EQ", 1, 0.05, 1_900_000, 0.48, 0.36, 0.19, False),
    CoreInstrument("ASIANPAINT", "NSE", "Asian Paints", "ASIANPAINT.NS", 2890.0, "CONSUMER", "EQ", 1, 0.05, 1_600_000, 0.56, 0.34, 0.24, False),
    CoreInstrument("NTPC", "NSE", "NTPC Limited", "NTPC.NS", 395.0, "ENERGY", "EQ", 1, 0.05, 15_500_000, 0.71, 0.38, 0.26, False),
    CoreInstrument("ONGC", "NSE", "Oil & Natural Gas Corp", "ONGC.NS", 275.0, "ENERGY", "EQ", 1, 0.05, 18_200_000, 0.72, 0.42, 0.29, False),
    CoreInstrument("TATASTEEL", "NSE", "Tata Steel", "TATASTEEL.NS", 152.0, "METALS", "EQ", 1, 0.05, 34_000_000, 0.83, 0.35, 0.31, False),
    # --- 5 Indian Benchmark Indices (NSE_INDEX + BSE_INDEX) ---
    CoreInstrument("NIFTY", "NSE_INDEX", "NIFTY 50", "^NSEI", 25800.0, "INDEX_IN", "INDEX", 1, 0.05, 0, 0.96, 0.05, 0.14, True),
    CoreInstrument("BANKNIFTY", "NSE_INDEX", "NIFTY BANK", "^NSEBANK", 64600.0, "BANKING", "INDEX", 1, 0.05, 0, 0.90, 0.36, 0.18, True),
    CoreInstrument("FINNIFTY", "NSE_INDEX", "NIFTY FIN SERVICE", "^CNXFIN", 24200.0, "BANKING", "INDEX", 1, 0.05, 0, 0.89, 0.32, 0.16, False),
    CoreInstrument("MIDCPNIFTY", "NSE_INDEX", "NIFTY MIDCAP SELECT", "^NSEMDCP50", 12850.0, "INDEX_IN", "INDEX", 1, 0.05, 0, 0.85, 0.25, 0.18, False),
    CoreInstrument("SENSEX", "BSE_INDEX", "BSE SENSEX", "^BSESN", 84500.0, "INDEX_IN", "INDEX", 1, 0.05, 0, 0.96, 0.05, 0.14, False),
    # --- 15 US Equities & ETFs ---
    CoreInstrument("AAPL", "US_EQUITY", "Apple Inc.", "AAPL", 230.0, "MEGACAP_TECH", "EQ", 1, 0.01, 48_000_000, 0.78, 0.42, 0.24, True),
    CoreInstrument("MSFT", "US_EQUITY", "Microsoft Corp.", "MSFT", 425.0, "MEGACAP_TECH", "EQ", 1, 0.01, 22_000_000, 0.79, 0.44, 0.23, True),
    CoreInstrument("NVDA", "US_EQUITY", "NVIDIA Corp.", "NVDA", 126.0, "SEMIS", "EQ", 1, 0.01, 210_000_000, 0.84, 0.46, 0.46, True),
    CoreInstrument("GOOGL", "US_EQUITY", "Alphabet Inc.", "GOOGL", 178.0, "MEGACAP_TECH", "EQ", 1, 0.01, 25_000_000, 0.77, 0.40, 0.27, False),
    CoreInstrument("AMZN", "US_EQUITY", "Amazon.com Inc.", "AMZN", 206.0, "MEGACAP_TECH", "EQ", 1, 0.01, 36_000_000, 0.80, 0.39, 0.29, False),
    CoreInstrument("META", "US_EQUITY", "Meta Platforms Inc.", "META", 585.0, "MEGACAP_TECH", "EQ", 1, 0.01, 14_000_000, 0.78, 0.41, 0.34, False),
    CoreInstrument("TSLA", "US_EQUITY", "Tesla Inc.", "TSLA", 325.0, "EV_TECH", "EQ", 1, 0.01, 78_000_000, 0.74, 0.30, 0.54, True),
    CoreInstrument("AMD", "US_EQUITY", "Advanced Micro Devices", "AMD", 142.0, "SEMIS", "EQ", 1, 0.01, 44_000_000, 0.82, 0.48, 0.44, False),
    CoreInstrument("NFLX", "US_EQUITY", "Netflix Inc.", "NFLX", 845.0, "MEGACAP_TECH", "EQ", 1, 0.01, 3_600_000, 0.68, 0.32, 0.33, False),
    CoreInstrument("AVGO", "US_EQUITY", "Broadcom Inc.", "AVGO", 172.0, "SEMIS", "EQ", 1, 0.01, 26_000_000, 0.81, 0.45, 0.36, False),
    CoreInstrument("JPM", "US_EQUITY", "JPMorgan Chase & Co.", "JPM", 242.0, "US_FIN", "EQ", 1, 0.01, 9_500_000, 0.76, 0.38, 0.22, False),
    CoreInstrument("V", "US_EQUITY", "Visa Inc.", "V", 308.0, "US_FIN", "EQ", 1, 0.01, 6_400_000, 0.72, 0.34, 0.20, False),
    CoreInstrument("SPY", "US_EQUITY", "SPDR S&P 500 ETF", "SPY", 600.0, "US_ETF", "EQ", 1, 0.01, 56_000_000, 0.97, 0.05, 0.15, True),
    CoreInstrument("QQQ", "US_EQUITY", "Invesco QQQ Trust", "QQQ", 510.0, "MEGACAP_TECH", "EQ", 1, 0.01, 34_000_000, 0.92, 0.30, 0.20, False),
    CoreInstrument("PLTR", "US_EQUITY", "Palantir Technologies", "PLTR", 62.0, "EV_TECH", "EQ", 1, 0.01, 68_000_000, 0.72, 0.34, 0.56, False),
    # --- 10 Crypto USDT Pairs ---
    CoreInstrument("BTCUSDT", "CRYPTO", "Bitcoin / USDT", "BTC-USD", 60150.0, "L1_CRYPTO", "PERPFUT", 1, 0.01, 32_000, 0.94, 0.18, 0.52, True),
    CoreInstrument("ETHUSDT", "CRYPTO", "Ethereum / USDT", "ETH-USD", 3150.0, "L1_CRYPTO", "PERPFUT", 1, 0.01, 240_000, 0.88, 0.32, 0.60, True),
    CoreInstrument("SOLUSDT", "CRYPTO", "Solana / USDT", "SOL-USD", 195.0, "L1_CRYPTO", "PERPFUT", 1, 0.01, 4_200_000, 0.82, 0.38, 0.74, True),
    CoreInstrument("BNBUSDT", "CRYPTO", "BNB / USDT", "BNB-USD", 615.0, "L1_CRYPTO", "PERPFUT", 1, 0.01, 520_000, 0.80, 0.30, 0.48, False),
    CoreInstrument("XRPUSDT", "CRYPTO", "XRP / USDT", "XRP-USD", 1.12, "PAY_CRYPTO", "PERPFUT", 1, 0.01, 480_000_000, 0.74, 0.34, 0.68, False),
    CoreInstrument("ADAUSDT", "CRYPTO", "Cardano / USDT", "ADA-USD", 0.78, "L1_CRYPTO", "PERPFUT", 1, 0.01, 360_000_000, 0.78, 0.36, 0.66, False),
    CoreInstrument("DOGEUSDT", "CRYPTO", "Dogecoin / USDT", "DOGE-USD", 0.36, "PAY_CRYPTO", "PERPFUT", 1, 0.01, 1_400_000_000, 0.70, 0.32, 0.82, False),
    CoreInstrument("AVAXUSDT", "CRYPTO", "Avalanche / USDT", "AVAX-USD", 34.5, "L1_CRYPTO", "PERPFUT", 1, 0.01, 8_500_000, 0.81, 0.38, 0.72, False),
    CoreInstrument("LINKUSDT", "CRYPTO", "Chainlink / USDT", "LINK-USD", 15.2, "DEFI_CRYPTO", "PERPFUT", 1, 0.01, 18_000_000, 0.79, 0.35, 0.65, False),
    CoreInstrument("LTCUSDT", "CRYPTO", "Litecoin / USDT", "LTC-USD", 88.5, "PAY_CRYPTO", "PERPFUT", 1, 0.01, 2_100_000, 0.78, 0.30, 0.56, False),
)

_MARKET_GROUP_FOR_EXCHANGE = {
    "NSE": "INDIA",
    "NSE_INDEX": "INDIA",
    "BSE": "INDIA",
    "BSE_INDEX": "INDIA",
    "NFO": "INDIA",
    "BFO": "INDIA",
    "US_EQUITY": "US",
    "CRYPTO": "CRYPTO",
}


def _seed_int(key: str) -> int:
    return int.from_bytes(hashlib.sha256(key.encode("utf-8")).digest()[:8], "big")


def _round_price(value: float, tick: float) -> float:
    if tick <= 0:
        return round(float(value), 2)
    decimals = 4 if tick < 0.01 else 2
    return max(tick, round(round(float(value) / tick) * tick, decimals))


def _is_truthy(val: str | None) -> bool:
    return str(val or "").strip().lower() in _TRUTHY


def _is_falsy(val: str | None) -> bool:
    return str(val or "").strip().lower() in _FALSY


# =============================================================================
# 1. Hybrid Online Yahoo Finance v8 Fetcher (stdlib urllib — NO httpx NO_PROXY crash!)
# =============================================================================


def fetch_yahoo_ohlcv(
    yahoo_ticker: str,
    interval: str = "1d",
    range_str: str = "3y",
    timeout: float = 4.0,
) -> pd.DataFrame | None:
    """Fetch real OHLCV candles from Yahoo Finance v8 Chart API via stdlib ``urllib.request``.

    Avoids ``httpx`` because VM ``NO_PROXY`` entries containing unbracketed ``::1``
    cause ``httpx`` URL parsing errors. Returns a clean DataFrame with columns
    ``["timestamp", "open", "high", "low", "close", "volume", "oi"]`` or ``None``
    if the request fails or yields insufficient clean bars.
    """
    encoded = urllib.parse.quote(yahoo_ticker, safe="")
    url = (
        f"https://query1.finance.yahoo.com/v8/finance/chart/{encoded}"
        f"?interval={urllib.parse.quote(interval)}&range={urllib.parse.quote(range_str)}"
    )
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug(f"[SandboxSeed] Yahoo fetch failed for {yahoo_ticker} ({interval}): {exc}")
        return None

    chart = payload.get("chart") if isinstance(payload, dict) else None
    results = chart.get("result") if isinstance(chart, dict) else None
    if not results or not isinstance(results, list):
        return None

    res0 = results[0]
    timestamps = res0.get("timestamp") or []
    indicators = (res0.get("indicators") or {}).get("quote") or []
    if not timestamps or not indicators:
        return None

    quote = indicators[0]
    opens = quote.get("open") or []
    highs = quote.get("high") or []
    lows = quote.get("low") or []
    closes = quote.get("close") or []
    volumes = quote.get("volume") or []

    n = min(len(timestamps), len(opens), len(highs), len(lows), len(closes))
    rows: list[dict[str, Any]] = []
    for i in range(n):
        o, h, low_val, c = opens[i], highs[i], lows[i], closes[i]
        ts = timestamps[i]
        if ts is None or o is None or h is None or low_val is None or c is None:
            continue
        try:
            o_f, h_f, l_f, c_f = float(o), float(h), float(low_val), float(c)
            ts_i = int(ts)
        except (TypeError, ValueError):
            continue
        if (
            ts_i <= 0
            or not (math.isfinite(o_f) and math.isfinite(h_f) and math.isfinite(l_f) and math.isfinite(c_f))
            or o_f <= 0
            or h_f <= 0
            or l_f <= 0
            or c_f <= 0
        ):
            continue
        h_f = max(h_f, o_f, c_f)
        l_f = min(l_f, o_f, c_f)
        raw_vol = volumes[i] if i < len(volumes) else 0
        try:
            vol_i = max(0, int(raw_vol or 0))
        except (TypeError, ValueError):
            vol_i = 0
        rows.append(
            {
                "timestamp": ts_i,
                "open": round(o_f, 4),
                "high": round(h_f, 4),
                "low": round(l_f, 4),
                "close": round(c_f, 4),
                "volume": vol_i,
                "oi": 0,
            }
        )

    if not rows:
        return None

    df = pd.DataFrame(rows, columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])
    df["timestamp"] = df["timestamp"].astype("int64")
    df["volume"] = df["volume"].astype("int64")
    df["oi"] = df["oi"].astype("int64")
    df = df.sort_values("timestamp").drop_duplicates(subset=["timestamp"], keep="last").reset_index(drop=True)
    return df


# =============================================================================
# 2. Deterministic Zero-Trig Institutional OHLCV Generator
#    PCG64 + Latent Market/Sector Factors + 3-State Markov Regime + GARCH(1,1) + Jumps
# =============================================================================


def _generate_latent_factor(key: str, length: int) -> np.ndarray:
    rng = np.random.Generator(np.random.PCG64(_seed_int(f"factor:{key}")))
    # Student-t-like mixture (92% standard normal + 8% wider shock) for authentic tail behavior
    z = rng.normal(0.0, 1.0, size=length)
    tail_mask = rng.random(length) < 0.08
    z[tail_mask] *= 2.1
    return z


def _daily_timestamps(exchange: str, n_bars: int, end_date: date | None = None) -> list[int]:
    """Generate ascending UTC epoch-second timestamps for ``n_bars`` trading/calendar days."""
    anchor = end_date or datetime.now(UTC).date()
    is_crypto = exchange.upper() == "CRYPTO"
    days: list[date] = []
    cur = anchor
    while len(days) < n_bars:
        if is_crypto or cur.weekday() < 5:
            days.append(cur)
        cur -= timedelta(days=1)
    days.reverse()
    # Close-of-session UTC hour: 10:00 UTC for NSE (15:30 IST), 21:00 UTC for US, 00:00 UTC for Crypto
    hour = 0 if is_crypto else (10 if exchange.upper() in {"NSE", "NSE_INDEX", "BSE", "NFO"} else 21)
    return [int(datetime(d.year, d.month, d.day, hour, 0, tzinfo=UTC).timestamp()) for d in days]


def _intraday_1m_timestamps(exchange: str, n_bars: int, end_epoch: int | None = None) -> list[int]:
    """Generate ascending 1-minute UTC epoch-second timestamps ending near ``end_epoch``."""
    if end_epoch is None:
        now = datetime.now(UTC).replace(second=0, microsecond=0)
        end_epoch = int(now.timestamp())
    end_aligned = (int(end_epoch) // 60) * 60
    return [end_aligned - (n_bars - 1 - i) * 60 for i in range(n_bars)]


def generate_institutional_ohlcv(
    instrument: CoreInstrument,
    *,
    interval: str = "D",
    n_bars: int = 750,
    market_factors: dict[str, np.ndarray] | None = None,
    sector_factors: dict[str, np.ndarray] | None = None,
    anchor_final_close: float | None = None,
    end_epoch: int | None = None,
) -> pd.DataFrame:
    """Generate realistic, deterministic OHLCV bars with strictly ZERO trig functions.

    Model:
    - PRNG: ``numpy.random.Generator(PCG64(sha256_seed))``
    - Cross-asset structure: shared latent market factor + sector factor + idiosyncratic shock
    - 3-state Markov regime switching (low-vol trend, range-bound, high-vol drawdown)
    - GARCH(1,1) conditional variance clustering (alpha=0.09, beta=0.88)
    - Merton compound Poisson jumps (p=0.015 daily, N(-0.004, 0.028))
    - Realistic Half-Normal wicks & overnight gaps strictly obeying low <= open,close <= high
    - Lognormal volume with volatility elasticity & quadratic U-shaped intraday session curve
    """
    rng = np.random.Generator(
        np.random.PCG64(_seed_int(f"chirify:{instrument.symbol}:{instrument.exchange}:{interval}"))
    )

    is_daily = interval == "D"
    mkt_key = _MARKET_GROUP_FOR_EXCHANGE.get(instrument.exchange.upper(), "GLOBAL")
    z_mkt = (
        market_factors[mkt_key]
        if market_factors is not None and mkt_key in market_factors and len(market_factors[mkt_key]) == n_bars
        else _generate_latent_factor(f"mkt:{mkt_key}:{interval}", n_bars)
    )
    sec_key = f"{mkt_key}:{instrument.sector}"
    z_sec = (
        sector_factors[sec_key]
        if sector_factors is not None and sec_key in sector_factors and len(sector_factors[sec_key]) == n_bars
        else _generate_latent_factor(f"sec:{sec_key}:{interval}", n_bars)
    )

    # 3-state sticky Markov regime chain
    trans = np.array(
        [
            [0.97, 0.022, 0.008],  # State 0: calm uptrend
            [0.028, 0.95, 0.022],  # State 1: range-bound chop
            [0.035, 0.045, 0.92],  # State 2: high-vol stress
        ],
        dtype=float,
    )
    # Per-bar scaling
    periods_per_year = 252.0 if is_daily else (252.0 * 375.0)
    base_sigma = instrument.ann_vol / math.sqrt(periods_per_year)
    regime_mu = np.array([0.11 / periods_per_year, 0.01 / periods_per_year, -0.18 / periods_per_year])
    regime_vol_mult = np.array([0.78, 1.00, 1.65])

    beta_m = instrument.beta_mkt
    beta_s = instrument.beta_sec
    idio_w = math.sqrt(max(0.05, 1.0 - beta_m * beta_m - beta_s * beta_s))

    eps = rng.normal(0.0, 1.0, size=n_bars)
    u_markov = rng.random(n_bars)
    jump_prob = 0.015 if is_daily else 0.0018
    jump_hits = rng.random(n_bars) < jump_prob
    jump_sizes = rng.normal(-0.004 if is_daily else -0.0005, 0.028 if is_daily else 0.0035, size=n_bars)

    var_min = (0.08 / math.sqrt(periods_per_year)) ** 2
    var_max = (0.95 / math.sqrt(periods_per_year)) ** 2
    var_t = base_sigma * base_sigma
    state = int(rng.integers(0, 2))

    returns = np.empty(n_bars, dtype=float)
    sigmas = np.empty(n_bars, dtype=float)

    prev_shock = 0.0
    for t in range(n_bars):
        # Markov transition
        probs = trans[state]
        if u_markov[t] < probs[0]:
            state = 0
        elif u_markov[t] < probs[0] + probs[1]:
            state = 1
        else:
            state = 2

        target_var = (base_sigma * regime_vol_mult[state]) ** 2
        omega_s = 0.03 * target_var
        var_t = omega_s + 0.09 * (prev_shock * prev_shock) + 0.88 * var_t
        var_t = min(var_max, max(var_min, var_t))
        sigma_t = math.sqrt(var_t)
        sigmas[t] = sigma_t

        comp_z = beta_m * z_mkt[t] + beta_s * z_sec[t] + idio_w * eps[t]
        j_t = jump_sizes[t] if jump_hits[t] else 0.0
        r_t = regime_mu[state] + sigma_t * comp_z + j_t
        # Realistic circuit clamp so synthetic bars never explode
        cap = 0.14 if is_daily else 0.018
        r_t = max(-cap, min(cap, r_t))
        returns[t] = r_t
        prev_shock = r_t - regime_mu[state]

    # Build close path anchored cleanly at target_final_close (exact latest daily close or anchor_price)
    target_close = float(anchor_final_close if anchor_final_close and anchor_final_close > 0 else instrument.anchor_price)
    cum_log = np.cumsum(returns)
    log_closes = math.log(target_close) + (cum_log - cum_log[-1])
    closes_raw = np.exp(log_closes)

    # Overnight gap (daily) or tiny microstructure open noise (1m)
    gap_scale = 0.25 if is_daily else 0.05
    gaps = rng.normal(0.0, 1.0, size=n_bars) * sigmas * gap_scale
    wick_up = np.abs(rng.normal(0.0, 1.0, size=n_bars)) * sigmas * 0.55
    wick_dn = np.abs(rng.normal(0.0, 1.0, size=n_bars)) * sigmas * 0.55

    # Volume model (zero trig: lognormal × volatility elasticity × quadratic U-curve intraday)
    vol_base = float(instrument.base_volume)
    if not is_daily and vol_base > 0:
        vol_base = max(50.0, vol_base / 375.0)
    logn_noise = np.exp(rng.normal(0.0, 0.35, size=n_bars))
    shock_mult = 1.0 + 1.8 * np.abs(returns) / np.maximum(sigmas, 1e-6)
    if not is_daily:
        f_pos = np.linspace(0.0, 1.0, n_bars)
        u_curve = 0.65 + 1.45 * np.square(2.0 * f_pos - 1.0)
    else:
        u_curve = np.ones(n_bars, dtype=float)
    volumes_raw = vol_base * logn_noise * shock_mult * u_curve

    timestamps = (
        _daily_timestamps(instrument.exchange, n_bars)
        if is_daily
        else _intraday_1m_timestamps(instrument.exchange, n_bars, end_epoch=end_epoch)
    )

    tick = instrument.tick_size
    rows: list[dict[str, Any]] = []
    prev_c = float(closes_raw[0] * math.exp(-returns[0]))
    for i in range(n_bars):
        c_val = _round_price(float(closes_raw[i]), tick)
        if i == n_bars - 1:
            c_val = _round_price(target_close, tick)
        o_raw = prev_c * math.exp(float(gaps[i]))
        o_val = _round_price(o_raw, tick)
        hi_body = max(o_val, c_val)
        lo_body = min(o_val, c_val)
        h_val = _round_price(hi_body * math.exp(float(wick_up[i])), tick)
        l_val = _round_price(max(tick, lo_body * math.exp(-float(wick_dn[i]))), tick)
        h_val = max(h_val, hi_body)
        l_val = min(l_val, lo_body)
        vol_i = 0 if instrument.instrumenttype == "INDEX" else max(1, int(round(float(volumes_raw[i]))))
        rows.append(
            {
                "timestamp": int(timestamps[i]),
                "open": float(o_val),
                "high": float(h_val),
                "low": float(l_val),
                "close": float(c_val),
                "volume": vol_i,
                "oi": 0,
            }
        )
        prev_c = c_val

    df = pd.DataFrame(rows, columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])
    df["timestamp"] = df["timestamp"].astype("int64")
    df["volume"] = df["volume"].astype("int64")
    df["oi"] = df["oi"].astype("int64")
    return df


# =============================================================================
# 3. Historify Multi-Asset Seeding Orchestrator
# =============================================================================


def _resolve_seed_mode(seed_mode: str | None = None, env: Mapping[str, str] | None = None) -> str:
    source = env if env is not None else os.environ
    if seed_mode and seed_mode.strip():
        return seed_mode.strip().lower()
    env_mode = str(source.get("CHIRIFY_SANDBOX_SEED_MODE") or "").strip().lower()
    if env_mode in ("auto", "online", "synthetic"):
        return env_mode
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return "synthetic"
    return "auto"


def seed_historify_market_data(
    *,
    seed_mode: str | None = None,
    force_reseed: bool = False,
    daily_bars: int = 750,
    intraday_bars: int = 390,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Idempotently seed DuckDB 1.5.5 Historify tables with 49 multi-asset symbols."""
    from database import historify_db

    mode = _resolve_seed_mode(seed_mode, env)
    use_online = mode in ("auto", "online")

    historify_db.init_database()

    # Check existing catalog counts for fast idempotency
    existing_counts: dict[tuple[str, str, str], int] = {}
    existing_last_close: dict[tuple[str, str], float] = {}
    if not force_reseed:
        try:
            with historify_db.get_connection() as conn:
                for sym, ex, iv, cnt in conn.execute(
                    "SELECT UPPER(symbol), UPPER(exchange), interval, record_count FROM data_catalog"
                ).fetchall():
                    existing_counts[(str(sym), str(ex), str(iv))] = int(cnt or 0)
                for sym, ex, close_v in conn.execute(
                    """
                    SELECT UPPER(symbol), UPPER(exchange), close
                    FROM (
                        SELECT symbol, exchange, close,
                               ROW_NUMBER() OVER (PARTITION BY UPPER(symbol), UPPER(exchange) ORDER BY timestamp DESC) AS rn
                        FROM market_data
                        WHERE interval = 'D'
                    )
                    WHERE rn = 1
                    """
                ).fetchall():
                    existing_last_close[(str(sym), str(ex))] = float(close_v)
        except Exception as exc:
            logger.debug(f"[SandboxSeed] Existing catalog scan skipped: {exc}")

    # Pre-generate shared latent market & sector factors for deterministic cross-sectional realism
    mkt_factors_d = {
        m: _generate_latent_factor(f"mkt:{m}:D", daily_bars)
        for m in ("INDIA", "US", "CRYPTO", "GLOBAL")
    }
    sec_factors_d = {
        f"{_MARKET_GROUP_FOR_EXCHANGE.get(inst.exchange, 'GLOBAL')}:{inst.sector}": _generate_latent_factor(
            f"sec:{_MARKET_GROUP_FOR_EXCHANGE.get(inst.exchange, 'GLOBAL')}:{inst.sector}:D",
            daily_bars,
        )
        for inst in CORE_UNIVERSE
    }
    mkt_factors_1m = {
        m: _generate_latent_factor(f"mkt:{m}:1m", intraday_bars)
        for m in ("INDIA", "US", "CRYPTO", "GLOBAL")
    }
    sec_factors_1m = {
        f"{_MARKET_GROUP_FOR_EXCHANGE.get(inst.exchange, 'GLOBAL')}:{inst.sector}": _generate_latent_factor(
            f"sec:{_MARKET_GROUP_FOR_EXCHANGE.get(inst.exchange, 'GLOBAL')}:{inst.sector}:1m",
            intraday_bars,
        )
        for inst in CORE_UNIVERSE
        if inst.flagship_intraday
    }

    need_daily = [
        inst
        for inst in CORE_UNIVERSE
        if force_reseed or existing_counts.get((inst.symbol, inst.exchange, "D"), 0) < 250
    ]
    need_intraday = [
        inst
        for inst in CORE_UNIVERSE
        if inst.flagship_intraday
        and (force_reseed or existing_counts.get((inst.symbol, inst.exchange, "1m"), 0) < 300)
    ]

    online_daily_map: dict[tuple[str, str], pd.DataFrame] = {}
    online_intraday_map: dict[tuple[str, str], pd.DataFrame] = {}

    if use_online and (need_daily or need_intraday):
        def _fetch_job(inst: CoreInstrument, iv_kind: str) -> tuple[str, str, str, pd.DataFrame | None]:
            if iv_kind == "D":
                df = fetch_yahoo_ohlcv(inst.yahoo_ticker, interval="1d", range_str="3y", timeout=4.0)
                if df is not None and len(df) >= 200:
                    return inst.symbol, inst.exchange, "D", df
                return inst.symbol, inst.exchange, "D", None
            df = fetch_yahoo_ohlcv(inst.yahoo_ticker, interval="1m", range_str="5d", timeout=4.0)
            if df is not None and len(df) >= 300:
                return inst.symbol, inst.exchange, "1m", df.tail(max(intraday_bars, 450)).reset_index(drop=True)
            return inst.symbol, inst.exchange, "1m", None

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(_fetch_job, inst, "D") for inst in need_daily]
            futs.extend(pool.submit(_fetch_job, inst, "1m") for inst in need_intraday)
            for fut in as_completed(futs):
                try:
                    sym, ex, iv_kind, df = fut.result()
                    if df is not None and not df.empty:
                        if iv_kind == "D":
                            online_daily_map[(sym, ex)] = df
                        else:
                            online_intraday_map[(sym, ex)] = df
                except Exception:
                    pass

    daily_seeded = 0
    intraday_seeded = 0
    online_hits = 0
    synthetic_hits = 0
    latest_spot_map: dict[tuple[str, str], float] = dict(existing_last_close)
    latest_ts_map: dict[tuple[str, str], int] = {}

    for inst in need_daily:
        key = (inst.symbol, inst.exchange)
        df_d = online_daily_map.get(key)
        if df_d is not None and not df_d.empty:
            online_hits += 1
        else:
            synthetic_hits += 1
            df_d = generate_institutional_ohlcv(
                inst,
                interval="D",
                n_bars=daily_bars,
                market_factors=mkt_factors_d,
                sector_factors=sec_factors_d,
            )
        historify_db.upsert_market_data(df_d, inst.symbol, inst.exchange, "D")
        latest_spot_map[key] = float(df_d["close"].iloc[-1])
        latest_ts_map[key] = int(df_d["timestamp"].iloc[-1])
        daily_seeded += 1

    for inst in need_intraday:
        key = (inst.symbol, inst.exchange)
        daily_close = latest_spot_map.get(key, inst.anchor_price)
        df_1m = online_intraday_map.get(key)
        if df_1m is not None and not df_1m.empty:
            online_hits += 1
            # Ensure intraday last close is coherent with daily close if daily came from synthetic fallback
            if key not in online_daily_map and daily_close > 0:
                scale = daily_close / max(float(df_1m["close"].iloc[-1]), 1e-6)
                for col in ("open", "high", "low", "close"):
                    df_1m[col] = (df_1m[col] * scale).round(4)
                df_1m["high"] = df_1m[["high", "open", "close"]].max(axis=1)
                df_1m["low"] = df_1m[["low", "open", "close"]].min(axis=1)
        else:
            synthetic_hits += 1
            df_1m = generate_institutional_ohlcv(
                inst,
                interval="1m",
                n_bars=intraday_bars,
                market_factors=mkt_factors_1m,
                sector_factors=sec_factors_1m,
                anchor_final_close=daily_close,
                end_epoch=latest_ts_map.get(key),
            )
        historify_db.upsert_market_data(df_1m, inst.symbol, inst.exchange, "1m")
        intraday_seeded += 1

    # Populate watchlist & symbol_metadata idempotently for all 49 core instruments
    watchlist_payload = [
        {"symbol": inst.symbol, "exchange": inst.exchange, "display_name": inst.name}
        for inst in CORE_UNIVERSE
    ]
    try:
        historify_db.bulk_add_to_watchlist(watchlist_payload)
    except Exception as exc:
        logger.debug(f"[SandboxSeed] Watchlist sync skipped: {exc}")

    metadata_payload = [
        {
            "symbol": inst.symbol,
            "exchange": inst.exchange,
            "name": inst.name,
            "expiry": "",
            "strike": 0.0,
            "lotsize": inst.lotsize,
            "instrumenttype": inst.instrumenttype,
            "tick_size": inst.tick_size,
        }
        for inst in CORE_UNIVERSE
    ]
    try:
        historify_db.upsert_symbol_metadata(metadata_payload)
    except Exception as exc:
        logger.debug(f"[SandboxSeed] symbol_metadata sync skipped: {exc}")

    # Clear live quote cache so BrokerData picks up freshly seeded Historify anchors
    try:
        from broker.chirify_sandbox.api.data import get_sandbox_market_feed

        get_sandbox_market_feed().clear_cache()
    except Exception:
        pass

    return {
        "seed_mode": mode,
        "core_universe_count": len(CORE_UNIVERSE),
        "daily_seeded": daily_seeded,
        "intraday_seeded": intraday_seeded,
        "online_series": online_hits,
        "synthetic_series": synthetic_hits,
        "latest_spots": {f"{ex}:{sym}": px for (sym, ex), px in latest_spot_map.items()},
        "db_path": historify_db.get_db_path(),
    }


# =============================================================================
# 4. Dynamic Future-Dated NFO Option Chains + Core SymToken Seeding
# =============================================================================


def _last_thursday_of_month(year: int, month: int) -> date:
    last_day = calendar.monthrange(year, month)[1]
    d = date(year, month, last_day)
    while d.weekday() != 3:  # Thursday == 3
        d -= timedelta(days=1)
    return d


def compute_future_nfo_expiries(reference_date: date | None = None, count: int = 3) -> list[date]:
    """Return ``>= count`` upcoming NFO Thursday expiries strictly ``> reference_date``.

    Includes the next 2 weekly Thursdays plus the next monthly last-Thursday
    (deduplicated and sorted ascending). Guarantees option contracts never expire
    on the day of seeding regardless of host system clock.
    """
    today = reference_date or datetime.now(_IST).date()
    days_to_thu = (3 - today.weekday()) % 7
    if days_to_thu == 0:
        days_to_thu = 7
    first_thu = today + timedelta(days=days_to_thu)
    second_thu = first_thu + timedelta(days=7)

    expiries: set[date] = {first_thu, second_thu}

    # Add upcoming monthly last-Thursday strictly after today
    y, m = today.year, today.month
    monthly = _last_thursday_of_month(y, m)
    if monthly <= today:
        m += 1
        if m > 12:
            m = 1
            y += 1
        monthly = _last_thursday_of_month(y, m)
    expiries.add(monthly)

    # If monthly collided with first_thu/second_thu, also include next month's last Thursday
    while len(expiries) < count:
        m += 1
        if m > 12:
            m = 1
            y += 1
        expiries.add(_last_thursday_of_month(y, m))

    return sorted(expiries)[: max(count, 3)]


def _build_sandbox_symtoken_rows(
    latest_spot_map: Mapping[tuple[str, str], float] | None = None,
    *,
    reference_date: date | None = None,
) -> list[dict[str, Any]]:
    spots = dict(latest_spot_map or {})
    rows: list[dict[str, Any]] = []

    # 1. Core 49 instruments with globally unique deterministic numeric tokens
    nse_idx = 910001
    idx_idx = 920001
    us_idx = 940001
    crypto_idx = 950001
    for inst in CORE_UNIVERSE:
        if inst.exchange == "NSE":
            tok = str(nse_idx)
            nse_idx += 1
        elif inst.exchange == "NSE_INDEX":
            tok = str(idx_idx)
            idx_idx += 1
        elif inst.exchange == "US_EQUITY":
            tok = str(us_idx)
            us_idx += 1
        else:
            tok = str(crypto_idx)
            crypto_idx += 1

        rows.append(
            {
                "symbol": inst.symbol,
                "brsymbol": inst.symbol,
                "name": inst.name,
                "exchange": inst.exchange,
                "brexchange": inst.exchange,
                "token": tok,
                "expiry": "",
                "strike": 0.0,
                "lotsize": inst.lotsize,
                "instrumenttype": inst.instrumenttype,
                "tick_size": inst.tick_size,
                "contract_value": 1.0,
            }
        )

    # 2. Dynamic future-dated NFO & BFO Options + Futures for NIFTY, BANKNIFTY, FINNIFTY, MIDCPNIFTY & SENSEX
    expiries = compute_future_nfo_expiries(reference_date=reference_date, count=3)
    nfo_tok = 930001
    derivative_specs = (
        ("NIFTY", "NFO", spots.get(("NIFTY", "NSE_INDEX"), 25800.0), 50, 75),
        ("BANKNIFTY", "NFO", spots.get(("BANKNIFTY", "NSE_INDEX"), 64600.0), 100, 30),
        ("FINNIFTY", "NFO", spots.get(("FINNIFTY", "NSE_INDEX"), 24200.0), 50, 65),
        ("MIDCPNIFTY", "NFO", spots.get(("MIDCPNIFTY", "NSE_INDEX"), 12850.0), 25, 120),
        ("SENSEX", "BFO", spots.get(("SENSEX", "BSE_INDEX"), 84500.0), 100, 20),
    )

    for underlying, deriv_exch, spot_px, step, lotsize in derivative_specs:
        atm = int(round(float(spot_px) / step) * step)
        strikes = [atm + offset * step for offset in range(-7, 8)]  # 15 strikes around spot
        for exp_dt in expiries:
            exp_sym = exp_dt.strftime("%d%b%y").upper()  # e.g. 26NOV26
            exp_db = exp_dt.strftime("%d-%b-%y").upper()  # e.g. 26-NOV-26

            # Near/mid/far future contract
            fut_sym = f"{underlying}{exp_sym}FUT"
            rows.append(
                {
                    "symbol": fut_sym,
                    "brsymbol": fut_sym,
                    "name": underlying,
                    "exchange": deriv_exch,
                    "brexchange": deriv_exch,
                    "token": str(nfo_tok),
                    "expiry": exp_db,
                    "strike": 0.0,
                    "lotsize": lotsize,
                    "instrumenttype": "FUT",
                    "tick_size": 0.05,
                    "contract_value": 1.0,
                }
            )
            nfo_tok += 1

            # 15 strikes × CE & PE
            for strike in strikes:
                for opt_type in ("CE", "PE"):
                    opt_sym = f"{underlying}{exp_sym}{int(strike)}{opt_type}"
                    rows.append(
                        {
                            "symbol": opt_sym,
                            "brsymbol": opt_sym,
                            "name": underlying,
                            "exchange": deriv_exch,
                            "brexchange": deriv_exch,
                            "token": str(nfo_tok),
                            "expiry": exp_db,
                            "strike": float(strike),
                            "lotsize": lotsize,
                            "instrumenttype": opt_type,
                            "tick_size": 0.05,
                            "contract_value": 1.0,
                        }
                    )
                    nfo_tok += 1

    return rows


def seed_sandbox_symtokens(
    latest_spot_map: Mapping[tuple[str, str], float] | None = None,
    *,
    reference_date: date | None = None,
    refresh_cache: bool = True,
) -> dict[str, Any]:
    """Idempotently seed all 49 core + dynamic NFO derivative ``SymToken`` rows."""
    from database import symbol as symbol_db
    from database.symbol import SymToken

    symbol_db.Base.metadata.create_all(symbol_db.engine)

    desired = _build_sandbox_symtoken_rows(latest_spot_map, reference_date=reference_date)

    existing_keys = {
        (str(sym).upper(), str(ex).upper())
        for sym, ex in symbol_db.db_session.query(SymToken.symbol, SymToken.exchange).all()
    }
    to_insert = [
        SymToken(**row)
        for row in desired
        if (row["symbol"].upper(), row["exchange"].upper()) not in existing_keys
    ]

    inserted = 0
    if to_insert:
        try:
            symbol_db.db_session.bulk_save_objects(to_insert)
            symbol_db.db_session.commit()
            inserted = len(to_insert)
        except Exception:
            symbol_db.db_session.rollback()
            raise

    total = int(symbol_db.db_session.query(SymToken).count())

    if refresh_cache:
        try:
            from database.token_db import load_cache_for_broker
            from database.token_db_enhanced import clear_cache
            from services.option_symbol_service import clear_strikes_cache

            clear_cache()
            load_cache_for_broker("chirify_sandbox")
            clear_strikes_cache()
        except Exception as exc:
            logger.debug(f"[SandboxSeed] Post-seed cache refresh warning: {exc}")

    return {
        "inserted": inserted,
        "total_symtokens": total,
        "expected_min": len(desired),
    }


# =============================================================================
# 5. Idempotent Sandbox Auth & SandboxFunds Provisioning
# =============================================================================


def ensure_sandbox_auth(
    username: str,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Provision ``Auth(broker='chirify_sandbox')`` ONLY if no active ``Auth`` row exists.

    NEVER overwrites an active live broker connection (e.g. zerodha, alpaca, ibkr, ccxt).
    """
    from database import auth_db

    auth_db.init_db()
    existing_active = (
        auth_db.Auth.query.filter_by(name=username, is_revoked=False).first()
        or auth_db.Auth.query.filter_by(is_revoked=False).first()
    )
    if existing_active is not None:
        return {
            "auth_provisioned": False,
            "already_active": True,
            "broker": existing_active.broker,
        }

    sandbox_token = f"chirify_sandbox_auth_{secrets.token_hex(24)}"
    sandbox_feed = f"chirify_sandbox_feed_{secrets.token_hex(24)}"
    auth_db.upsert_auth(
        name=username,
        auth_token=sandbox_token,
        broker="chirify_sandbox",
        feed_token=sandbox_feed,
        user_id=tenant_id or username,
        revoke=False,
    )
    del sandbox_token, sandbox_feed
    return {
        "auth_provisioned": True,
        "already_active": False,
        "broker": "chirify_sandbox",
    }


def _ensure_sqlite_parent(url: str | None) -> None:
    raw = str(url or "").strip()
    if raw.startswith("sqlite:///"):
        path = raw[len("sqlite:///") :]
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)


def ensure_sandbox_funds(
    username: str,
    *,
    starting_capital: str | None = None,
    enable_24x7: bool | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Idempotently initialize Sandbox capital and 24/7 config without overwriting live balances."""
    from database import sandbox_db
    from sandbox.fund_manager import FundManager

    source = env if env is not None else os.environ
    _ensure_sqlite_parent(source.get("SANDBOX_DATABASE_URL") or sandbox_db.SANDBOX_DATABASE_URL)
    sandbox_db.init_db()

    if enable_24x7 is None:
        enable_24x7 = _is_truthy(source.get("CHIRIFY_SANDBOX_24X7"))
    if enable_24x7:
        sandbox_db.set_config(
            "sandbox_24x7",
            "true",
            "Allow 24/7 Analyzer Sandbox MIS/intraday orders and MTM updates",
        )

    existing = sandbox_db.SandboxFunds.query.filter_by(user_id=username).first()
    if existing is not None:
        return {
            "funds_initialized": False,
            "already_existed": True,
            "available_balance": float(existing.available_balance),
            "sandbox_24x7": sandbox_db.is_24x7_sandbox_enabled(),
        }

    if starting_capital is None:
        configured = str(source.get("CHIRIFY_SANDBOX_STARTING_CAPITAL") or "").strip()
        if configured:
            starting_capital = configured
        elif str(source.get("CHIRIFY_SANDBOX_CURRENCY") or "").strip().upper() == "USD":
            starting_capital = "100000.00"
        else:
            starting_capital = "1000000.00"

    sandbox_db.set_config("starting_capital", str(starting_capital))
    fm = FundManager(username)
    fm.initialize_funds()
    created = sandbox_db.SandboxFunds.query.filter_by(user_id=username).first()
    return {
        "funds_initialized": True,
        "already_existed": False,
        "available_balance": float(created.available_balance) if created else float(starting_capital),
        "sandbox_24x7": sandbox_db.is_24x7_sandbox_enabled(),
    }


# =============================================================================
# 6. Master Orchestrator & CLI Entrypoint
# =============================================================================


def bootstrap_sandbox_environment(
    *,
    username: str | None = None,
    tenant_id: str | None = None,
    env: Mapping[str, str] | None = None,
    seed_historify: bool = True,
    seed_symtokens: bool = True,
    seed_funds: bool = True,
    seed_mode: str | None = None,
    force_reseed: bool = False,
    starting_capital: str | None = None,
    auth_engine: Any = None,
) -> dict[str, Any]:
    """Idempotently provision Sandbox Auth, Historify OHLCV, SymToken, and SandboxFunds.

    Note: Intentionally emits ZERO WORM audit events so ``bootstrap_managed_tenant()``
    preserves its exact single-WORM-record contract.
    """
    from database import auth_db, user_db
    from database import symbol as symbol_db

    source = env if env is not None else os.environ

    resolved_user = username
    if not resolved_user:
        u = user_db.find_user_by_username()
        if u is not None and u.username:
            resolved_user = u.username
        else:
            k = auth_db.ApiKeys.query.first()
            resolved_user = k.user_id if k is not None and k.user_id else "trader"

    resolved_tenant = tenant_id or str(source.get("CHIRIFY_TENANT_ID") or "").strip() or resolved_user

    # 1. Auth row (always safe; respects active live broker!)
    auth_summary = ensure_sandbox_auth(resolved_user, resolved_tenant)

    # 2. Historify multi-asset DuckDB seeding
    historify_summary: dict[str, Any] | None = None
    latest_spots: dict[tuple[str, str], float] = {}
    if seed_historify:
        historify_summary = seed_historify_market_data(
            seed_mode=seed_mode,
            force_reseed=force_reseed,
            env=source,
        )
        for key_str, px in (historify_summary.get("latest_spots") or {}).items():
            if ":" in key_str:
                ex, sym = key_str.split(":", 1)
                latest_spots[(sym, ex)] = float(px)

    # 3. SymToken seeding (guard against monkeypatched unit-test DB mismatch!)
    symtoken_summary: dict[str, Any] | None = None
    if seed_symtokens:
        engine_mismatch = (
            auth_engine is not None and str(symbol_db.engine.url) != str(auth_engine.url)
        )
        if engine_mismatch:
            symtoken_summary = {"skipped": True, "reason": "isolated_test_engine_mismatch"}
        else:
            symtoken_summary = seed_sandbox_symtokens(latest_spots)
            try:
                from database import master_contract_status_db

                if str(master_contract_status_db.engine.url) == str(symbol_db.engine.url):
                    master_contract_status_db.update_status(
                        "chirify_sandbox",
                        "success",
                        "Chirify Sandbox multi-asset contracts ready",
                        total_symbols=(symtoken_summary or {}).get("total_symtokens", 0),
                    )
            except Exception as mc_err:
                logger.debug("Master contract status update skipped: %s", mc_err)

    # 4. Sandbox funds & 24/7 config
    funds_summary: dict[str, Any] | None = None
    if seed_funds:
        funds_summary = ensure_sandbox_funds(
            resolved_user,
            starting_capital=starting_capital,
            env=source,
        )

    return {
        "username": resolved_user,
        "tenant_id": resolved_tenant,
        "auth": auth_summary,
        "historify": historify_summary,
        "symtokens": symtoken_summary,
        "funds": funds_summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Idempotently bootstrap Chirify Analyzer Sandbox & Historify DuckDB."
    )
    parser.add_argument(
        "--seed-mode",
        choices=("auto", "online", "synthetic"),
        default=None,
        help="Historify seeding mode (default: auto, or synthetic under pytest).",
    )
    parser.add_argument(
        "--force-reseed",
        action="store_true",
        help="Force re-seeding Historify OHLCV even if rows already exist.",
    )
    parser.add_argument(
        "--capital",
        default=None,
        help="Initial Sandbox starting capital (e.g. 1000000.00).",
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Explicit OpenAlgo username (defaults to provisioned tenant admin).",
    )
    args = parser.parse_args(argv)

    try:
        result = bootstrap_sandbox_environment(
            username=args.username,
            seed_historify=True,
            seed_symtokens=True,
            seed_funds=True,
            seed_mode=args.seed_mode,
            force_reseed=args.force_reseed,
            starting_capital=args.capital,
        )
    except Exception as exc:
        print(f"[OpenAlgo] CHIRIFY SANDBOX BOOTSTRAP FAILURE: {exc}", file=sys.stderr)
        return 1

    hist = result.get("historify") or {}
    syms = result.get("symtokens") or {}
    funds = result.get("funds") or {}
    auth = result.get("auth") or {}
    print(
        "[OpenAlgo] Chirify Sandbox bootstrap ok: "
        f"user={result.get('username')} broker={auth.get('broker')} "
        f"symtokens={syms.get('total_symtokens')} "
        f"historify_daily_seeded={hist.get('daily_seeded')} "
        f"historify_1m_seeded={hist.get('intraday_seeded')} "
        f"online={hist.get('online_series')} synthetic={hist.get('synthetic_series')} "
        f"balance={funds.get('available_balance')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
