"""Historify-Backed Market Data, L2 Depth, History & Option Pricing Provider for Chirify Sandbox.

Shares a process-wide :class:`SandboxMarketFeed` singleton with
:class:`broker.chirify_sandbox.streaming.chirify_sandbox_adapter.Chirify_sandboxWebSocketAdapter`
so REST ``/api/v1/quotes``, ``/api/v1/depth``, ``/api/v1/optionchain``, Sandbox
order fills, and WebSocket ``:8765`` ticks all observe one coherent,
Historify-anchored price state.

Invariants:
- Zero ``math.sin()`` / ``math.cos()`` synthetic wave generation.
- Every quote and tick strictly satisfies ``low <= ltp <= high`` and
  ``bid < ltp < ask`` so ``sandbox.execution_engine.quote_looks_stale`` never
  defers fills.
- Automatically detects DuckDB path switches (e.g. across pytest fixtures) and
  re-anchors cleanly from the active Historify DuckDB file.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd

from database import historify_db
from utils import black_scholes
from utils.logging import get_logger

logger = get_logger(__name__)

_OPTION_SYMBOL_RE = re.compile(
    r"^([A-Z0-9&-]+?)(\d{2})(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)(\d{2})(\d+(?:\.\d+)?)(CE|PE)$"
)
_FUTURE_SYMBOL_RE = re.compile(
    r"^([A-Z0-9&-]+?)(\d{2})(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)(\d{2})FUT$"
)

_MONTH_MAP: dict[str, int] = {
    "JAN": 1,
    "FEB": 2,
    "MAR": 3,
    "APR": 4,
    "MAY": 5,
    "JUN": 6,
    "JUL": 7,
    "AUG": 8,
    "SEP": 9,
    "OCT": 10,
    "NOV": 11,
    "DEC": 12,
}

_INDEX_UNDERLYINGS: frozenset[str] = frozenset(
    {"NIFTY", "BANKNIFTY", "FINNIFTY", "MIDCPNIFTY", "NIFTYNXT50"}
)
_BSE_INDEX_UNDERLYINGS: frozenset[str] = frozenset({"SENSEX", "BANKEX"})

_FALLBACK_SPOT_ANCHORS: dict[str, float] = {
    "NIFTY": 25800.0,
    "BANKNIFTY": 64600.0,
    "FINNIFTY": 24200.0,
    "MIDCPNIFTY": 12850.0,
    "SENSEX": 84500.0,
    "RELIANCE": 1380.0,
    "TCS": 4120.0,
    "HDFCBANK": 1740.0,
    "INFY": 1890.0,
    "ICICIBANK": 1290.0,
    "SBIN": 840.0,
    "AAPL": 230.0,
    "MSFT": 425.0,
    "NVDA": 126.0,
    "SPY": 600.0,
    "BTCUSDT": 60150.0,
    "ETHUSDT": 3150.0,
    "SOLUSDT": 195.0,
}

_DERIVATIVE_LOT_SIZES: dict[str, int] = {
    "NIFTY": 75,
    "BANKNIFTY": 30,
    "FINNIFTY": 65,
    "MIDCPNIFTY": 120,
    "SENSEX": 20,
}

_DERIVATIVE_BASE_IV: dict[str, float] = {
    "NIFTY": 0.145,
    "BANKNIFTY": 0.172,
    "FINNIFTY": 0.162,
    "MIDCPNIFTY": 0.184,
    "SENSEX": 0.142,
}


def _tick_size_for(symbol: str, exchange: str) -> float:
    ex = (exchange or "").upper()
    if ex in {"NSE", "NFO", "BSE", "BFO", "NSE_INDEX", "BSE_INDEX", "MCX"}:
        return 0.05
    if ex in {"CDS", "BCD"}:
        return 0.0025
    return 0.01


def _round_tick(price: float, tick: float) -> float:
    if tick <= 0:
        return round(float(price), 2)
    decimals = 4 if tick < 0.01 else 2
    rounded = round(round(float(price) / tick) * tick, decimals)
    return max(tick, rounded)


def _deterministic_seed(key: str) -> int:
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _parse_option_contract(symbol: str) -> tuple[str, datetime, float, str] | None:
    m = _OPTION_SYMBOL_RE.match((symbol or "").strip().upper())
    if not m:
        return None
    underlying, dd, mmm, yy, strike_s, opt_type = m.groups()
    try:
        expiry_dt = datetime(
            2000 + int(yy),
            _MONTH_MAP[mmm],
            int(dd),
            10,
            0,  # 15:30 IST == 10:00 UTC
            tzinfo=UTC,
        )
        strike = float(strike_s)
        return underlying, expiry_dt, strike, opt_type
    except (ValueError, KeyError):
        return None


def _parse_future_contract(symbol: str) -> tuple[str, datetime] | None:
    m = _FUTURE_SYMBOL_RE.match((symbol or "").strip().upper())
    if not m:
        return None
    underlying, dd, mmm, yy = m.groups()
    try:
        expiry_dt = datetime(2000 + int(yy), _MONTH_MAP[mmm], int(dd), 10, 0, tzinfo=UTC)
        return underlying, expiry_dt
    except (ValueError, KeyError):
        return None


class SandboxMarketFeed:
    """Thread-safe shared live state anchored to Historify DuckDB & Black-76 option pricing."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state: dict[tuple[str, str], dict[str, Any]] = {}
        self._rngs: dict[tuple[str, str], np.random.Generator] = {}
        self._last_db_path: str | None = None

    def _sync_db_path(self) -> None:
        try:
            current_path = historify_db.get_db_path()
        except Exception:
            return
        if self._last_db_path is not None and current_path != self._last_db_path:
            self._state.clear()
            self._rngs.clear()
        self._last_db_path = current_path

    def clear_cache(self) -> None:
        with self._lock:
            self._state.clear()
            self._rngs.clear()

    def _rng_for(self, symbol: str, exchange: str) -> np.random.Generator:
        key = (symbol.upper(), exchange.upper())
        rng = self._rngs.get(key)
        if rng is None:
            rng = np.random.default_rng(_deterministic_seed(f"chirify_feed:{exchange}:{symbol}"))
            self._rngs[key] = rng
        return rng

    def _load_historify_anchor(self, symbol: str, exchange: str) -> dict[str, Any] | None:
        """Read latest daily/1m OHLCV bar for ``(symbol, exchange)`` from Historify DuckDB."""
        sym = symbol.upper()
        ex = exchange.upper()
        try:
            with historify_db.get_connection() as conn:
                # Prefer latest daily bars for session OHLC + prev_close
                daily_rows = conn.execute(
                    """
                    SELECT timestamp, open, high, low, close, volume, COALESCE(oi, 0)
                    FROM market_data
                    WHERE UPPER(symbol) = ? AND UPPER(exchange) = ? AND interval = 'D'
                    ORDER BY timestamp DESC
                    LIMIT 2
                    """,
                    [sym, ex],
                ).fetchall()

                intraday_row = conn.execute(
                    """
                    SELECT timestamp, open, high, low, close, volume, COALESCE(oi, 0)
                    FROM market_data
                    WHERE UPPER(symbol) = ? AND UPPER(exchange) = ? AND interval = '1m'
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    [sym, ex],
                ).fetchone()

                if not daily_rows and not intraday_row:
                    # Fallback: any interval stored for this symbol/exchange
                    any_rows = conn.execute(
                        """
                        SELECT timestamp, open, high, low, close, volume, COALESCE(oi, 0)
                        FROM market_data
                        WHERE UPPER(symbol) = ? AND UPPER(exchange) = ?
                        ORDER BY timestamp DESC
                        LIMIT 2
                        """,
                        [sym, ex],
                    ).fetchall()
                    daily_rows = any_rows
        except Exception:
            return None

        if not daily_rows and not intraday_row:
            return None

        if daily_rows:
            latest = daily_rows[0]
            prev = daily_rows[1] if len(daily_rows) > 1 else latest
            open_p = float(latest[1])
            high_p = float(latest[2])
            low_p = float(latest[3])
            close_p = float(latest[4])
            prev_close = float(prev[4])
            volume = int(latest[5] or 0)
            oi = int(latest[6] or 0)
            if intraday_row is not None and float(intraday_row[4]) > 0:
                ltp = float(intraday_row[4])
                high_p = max(high_p, ltp)
                low_p = min(low_p, ltp)
            else:
                ltp = close_p
        else:
            assert intraday_row is not None
            open_p = float(intraday_row[1])
            high_p = float(intraday_row[2])
            low_p = float(intraday_row[3])
            ltp = float(intraday_row[4])
            prev_close = open_p
            volume = int(intraday_row[5] or 0)
            oi = int(intraday_row[6] or 0)

        high_p = max(high_p, open_p, ltp)
        low_p = min(low_p, open_p, ltp)
        return {
            "anchor": ltp,
            "ltp": ltp,
            "open": open_p,
            "high": high_p,
            "low": low_p,
            "prev_close": prev_close,
            "volume": max(volume, 1000),
            "oi": max(oi, 0),
        }

    def _resolve_underlying_spot(self, underlying: str, deriv_exchange: str) -> float:
        u = underlying.upper()
        ex_candidates: list[str] = []
        if u in _INDEX_UNDERLYINGS:
            ex_candidates.extend(["NSE_INDEX", "NSE"])
        elif u in _BSE_INDEX_UNDERLYINGS:
            ex_candidates.extend(["BSE_INDEX", "BSE"])
        elif deriv_exchange == "US_OPTIONS":
            ex_candidates.append("US_EQUITY")
        elif deriv_exchange == "CRYPTO_OPTIONS":
            ex_candidates.append("CRYPTO")
        else:
            ex_candidates.extend(["NSE", "NSE_INDEX", "BSE"])

        for ex in ex_candidates:
            st = self._state.get((u, ex))
            if st and st.get("ltp", 0) > 0:
                return float(st["ltp"])
            anchor = self._load_historify_anchor(u, ex)
            if anchor and anchor.get("ltp", 0) > 0:
                return float(anchor["ltp"])

        return _FALLBACK_SPOT_ANCHORS.get(u, 1000.0)

    def _build_option_state(self, symbol: str, exchange: str) -> dict[str, Any] | None:
        parsed = _parse_option_contract(symbol)
        if parsed is None:
            return None
        underlying, expiry_dt, strike, opt_type = parsed
        spot = self._resolve_underlying_spot(underlying, exchange.upper())
        now_utc = datetime.now(UTC)
        seconds_left = max((expiry_dt - now_utc).total_seconds(), 86400.0)
        t_years = seconds_left / (365.0 * 86400.0)

        # Realistic volatility smile: calibrated ATM IV per benchmark index, skew on OTM puts + convexity wing
        base_atm_iv = _DERIVATIVE_BASE_IV.get(underlying, 0.24)
        moneyness = (strike - spot) / max(spot, 1.0)
        # Put skew: lower strikes (moneyness < 0) carry higher IV; wing convexity adds smile curvature
        smile_iv = base_atm_iv - 0.35 * moneyness + 1.85 * (moneyness * moneyness)
        # Small deterministic per-strike micro-variation so CE/PE IVs differ realistically
        det_rng = np.random.default_rng(_deterministic_seed(f"opt_smile:{symbol}"))
        wing_jitter = float(det_rng.uniform(-0.004, 0.004))
        if opt_type == "PE":
            smile_iv += 0.0035
        sigma = max(0.06, min(1.25, smile_iv + wing_jitter))

        rate = 0.0
        flag = "c" if opt_type == "CE" else "p"
        theo_price = black_scholes.price(flag, spot, strike, t_years, rate, sigma)
        tick = _tick_size_for(symbol, exchange)
        ltp = _round_tick(max(tick, theo_price), tick)

        # Realistic OI peaking near ATM & round strikes; slightly heavier put OI near/below ATM (PCR ~1.05-1.20)
        width = 0.025 if underlying in _DERIVATIVE_LOT_SIZES else 0.05
        bell = math.exp(-0.5 * (moneyness / width) ** 2)
        round_boost = 1.45 if (int(round(strike)) % 500 == 0) else (1.15 if int(round(strike)) % 100 == 0 else 1.0)
        side_tilt = (1.18 if (opt_type == "PE" and strike <= spot) else 1.12 if (opt_type == "CE" and strike >= spot) else 0.72)
        lot_size = _DERIVATIVE_LOT_SIZES.get(underlying, 1)
        base_lots = int(max(120, round(42000 * bell * round_boost * side_tilt * float(det_rng.uniform(0.82, 1.18)))))
        oi = base_lots * lot_size
        volume = int(max(lot_size * 10, round(oi * float(det_rng.uniform(0.18, 0.48)))))

        prev_close = _round_tick(max(tick, ltp * float(det_rng.uniform(0.96, 1.04))), tick)
        open_p = _round_tick(max(tick, ltp * float(det_rng.uniform(0.985, 1.015))), tick)
        high_p = _round_tick(max(ltp, open_p, prev_close) * 1.03, tick)
        low_p = _round_tick(max(tick, min(ltp, open_p, prev_close) * 0.97), tick)

        return {
            "anchor": ltp,
            "ltp": ltp,
            "open": open_p,
            "high": max(high_p, ltp, open_p),
            "low": min(low_p, ltp, open_p),
            "prev_close": prev_close,
            "volume": volume,
            "oi": oi,
            "is_option": True,
        }

    def _build_future_state(self, symbol: str, exchange: str) -> dict[str, Any] | None:
        parsed = _parse_future_contract(symbol)
        if parsed is None:
            return None
        underlying, expiry_dt = parsed
        spot = self._resolve_underlying_spot(underlying, exchange.upper())
        seconds_left = max((expiry_dt - datetime.now(UTC)).total_seconds(), 86400.0)
        t_years = seconds_left / (365.0 * 86400.0)
        carry_price = spot * math.exp(0.065 * t_years)
        tick = _tick_size_for(symbol, exchange)
        ltp = _round_tick(carry_price, tick)
        open_p = _round_tick(ltp * 0.9985, tick)
        high_p = _round_tick(max(ltp, open_p) * 1.006, tick)
        low_p = _round_tick(min(ltp, open_p) * 0.994, tick)
        lot_size = _DERIVATIVE_LOT_SIZES.get(underlying, 1)
        return {
            "anchor": ltp,
            "ltp": ltp,
            "open": open_p,
            "high": max(high_p, ltp, open_p),
            "low": min(low_p, ltp, open_p),
            "prev_close": open_p,
            "volume": lot_size * 85000,
            "oi": lot_size * 180000,
            "is_option": False,
        }

    def _ensure_state(self, symbol: str, exchange: str) -> dict[str, Any]:
        self._sync_db_path()
        sym = symbol.strip().upper()
        ex = exchange.strip().upper()
        key = (sym, ex)
        st = self._state.get(key)
        if st is not None:
            return st

        loaded = self._load_historify_anchor(sym, ex)
        if loaded is None:
            loaded = self._build_option_state(sym, ex)
        if loaded is None:
            loaded = self._build_future_state(sym, ex)
        if loaded is None:
            tick = _tick_size_for(sym, ex)
            rng = self._rng_for(sym, ex)
            base = _FALLBACK_SPOT_ANCHORS.get(sym, float(rng.uniform(120.0, 2400.0)))
            ltp = _round_tick(base, tick)
            loaded = {
                "anchor": ltp,
                "ltp": ltp,
                "open": _round_tick(ltp * 0.997, tick),
                "high": _round_tick(ltp * 1.012, tick),
                "low": _round_tick(ltp * 0.988, tick),
                "prev_close": _round_tick(ltp * 0.996, tick),
                "volume": int(rng.integers(50_000, 1_500_000)),
                "oi": 0,
            }

        # Guarantee strict low <= ltp <= high invariant
        loaded["high"] = max(loaded["high"], loaded["open"], loaded["ltp"])
        loaded["low"] = min(loaded["low"], loaded["open"], loaded["ltp"])
        self._state[key] = loaded
        return loaded

    def _format_quote_dict(self, symbol: str, exchange: str, st: dict[str, Any]) -> dict[str, Any]:
        tick = _tick_size_for(symbol, exchange)
        ltp = _round_tick(st["ltp"], tick)
        open_p = _round_tick(st["open"], tick)
        high_p = _round_tick(max(st["high"], ltp, open_p), tick)
        low_p = _round_tick(min(st["low"], ltp, open_p), tick)
        prev_close = _round_tick(st["prev_close"], tick)

        # Realistic tight spread: 1-2 ticks or ~3 bps, ensuring bid < ltp < ask when possible
        bps_half = ltp * 0.0003
        half_spread = max(tick, _round_tick(bps_half, tick))
        bid = _round_tick(max(tick, ltp - half_spread), tick)
        ask = _round_tick(ltp + half_spread, tick)
        if bid >= ltp and ltp > tick:
            bid = _round_tick(ltp - tick, tick)
        if ask <= ltp:
            ask = _round_tick(ltp + tick, tick)

        rng = self._rng_for(symbol, exchange)
        bid_qty = int(rng.integers(25, 650))
        ask_qty = int(rng.integers(25, 650))

        return {
            "ltp": float(ltp),
            "open": float(open_p),
            "high": float(high_p),
            "low": float(low_p),
            "close": float(prev_close),
            "prev_close": float(prev_close),
            "bid": float(bid),
            "ask": float(ask),
            "bid_qty": bid_qty,
            "ask_qty": ask_qty,
            "volume": int(st["volume"]),
            "oi": int(st.get("oi", 0)),
        }

    def get_quote(self, symbol: str, exchange: str) -> dict[str, Any]:
        with self._lock:
            st = self._ensure_state(symbol, exchange)
            return self._format_quote_dict(symbol, exchange, st)

    def advance_tick(self, symbol: str, exchange: str) -> dict[str, Any]:
        """Advance live price by one bounded Ornstein-Uhlenbeck micro-tick (zero trig)."""
        with self._lock:
            st = self._ensure_state(symbol, exchange)
            tick = _tick_size_for(symbol, exchange)
            rng = self._rng_for(symbol, exchange)

            anchor = float(st["anchor"])
            curr = float(st["ltp"])
            vol_step = 0.0022 if st.get("is_option") else 0.0007
            # Mean reversion toward Historify anchor keeps quotes realistic and bounded
            reversion = 0.14 * (anchor - curr)
            shock = float(rng.normal(0.0, max(curr * vol_step, tick)))
            next_price = curr + reversion + shock
            floor_p = max(tick, anchor * 0.96)
            ceil_p = max(floor_p + tick, anchor * 1.04)
            next_ltp = _round_tick(max(floor_p, min(ceil_p, next_price)), tick)

            st["ltp"] = next_ltp
            st["high"] = max(float(st["high"]), next_ltp, float(st["open"]))
            st["low"] = min(float(st["low"]), next_ltp, float(st["open"]))
            st["volume"] = int(st["volume"]) + int(rng.integers(5, 450))
            return self._format_quote_dict(symbol, exchange, st)

    def get_depth(self, symbol: str, exchange: str, levels: int = 5) -> dict[str, Any]:
        with self._lock:
            quote = self.get_quote(symbol, exchange)
            tick = _tick_size_for(symbol, exchange)
            rng = self._rng_for(symbol, exchange)

            best_bid = float(quote["bid"])
            best_ask = float(quote["ask"])
            step = max(tick, _round_tick(quote["ltp"] * 0.00025, tick))

            bids = []
            asks = []
            for lvl in range(levels):
                b_price = _round_tick(max(tick, best_bid - lvl * step), tick)
                a_price = _round_tick(best_ask + lvl * step, tick)
                scale = 1.0 + 0.35 * lvl
                b_qty = int(rng.integers(40, 420) * scale)
                a_qty = int(rng.integers(40, 420) * scale)
                bids.append(
                    {"price": float(b_price), "quantity": b_qty, "orders": int(rng.integers(1, 14))}
                )
                asks.append(
                    {"price": float(a_price), "quantity": a_qty, "orders": int(rng.integers(1, 14))}
                )

            return {
                "bids": bids,
                "asks": asks,
                "ltp": quote["ltp"],
                "ltq": int(rng.integers(1, 120)),
                "open": quote["open"],
                "high": quote["high"],
                "low": quote["low"],
                "prev_close": quote["prev_close"],
                "volume": quote["volume"],
                "oi": quote["oi"],
                "totalbuyqty": sum(level["quantity"] for level in bids),
                "totalsellqty": sum(level["quantity"] for level in asks),
            }


_FEED_SINGLETON: SandboxMarketFeed | None = None
_FEED_LOCK = threading.Lock()


def get_sandbox_market_feed() -> SandboxMarketFeed:
    global _FEED_SINGLETON
    with _FEED_LOCK:
        if _FEED_SINGLETON is None:
            _FEED_SINGLETON = SandboxMarketFeed()
        return _FEED_SINGLETON


def _parse_date_to_epoch(raw: str | int | float | None, *, end_of_day: bool = False) -> int | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        val = int(raw)
        return val // 1000 if abs(val) > 100_000_000_000 else val
    s = str(raw).strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        if len(s) == 10 and end_of_day:
            dt = dt + timedelta(hours=23, minutes=59, seconds=59)
        return int(dt.timestamp())
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=UTC)
            if end_of_day:
                dt = dt + timedelta(hours=23, minutes=59, seconds=59)
            return int(dt.timestamp())
        except ValueError:
            continue
    return None


def _synthesize_intraday_from_daily(
    daily_df: pd.DataFrame,
    symbol: str,
    exchange: str,
    interval: str,
) -> pd.DataFrame:
    """Deterministically disaggregate recent daily OHLCV into intraday bars via Brownian bridge."""
    parsed = historify_db.parse_interval(interval)
    if parsed is None:
        return daily_df
    if isinstance(parsed, dict):
        if parsed.get("type") != "intraday":
            return daily_df
        bar_minutes = int(parsed.get("minutes") or 0)
    else:
        if parsed[1] not in ("m", "h"):
            return daily_df
        unit_value, unit_type = parsed
        bar_minutes = int(unit_value) * (60 if unit_type == "h" else 1)
    if bar_minutes <= 0:
        return daily_df

    bars_per_day = max(1, min(375, 375 // bar_minutes))
    recent = daily_df.tail(10).reset_index(drop=True)
    tick = _tick_size_for(symbol, exchange)
    rng = np.random.default_rng(_deterministic_seed(f"intraday_bridge:{exchange}:{symbol}:{interval}"))

    rows: list[dict[str, Any]] = []
    for _, drow in recent.iterrows():
        day_ts = int(drow["timestamp"])
        d_open = float(drow["open"])
        d_high = float(drow["high"])
        d_low = float(drow["low"])
        d_close = float(drow["close"])
        d_vol = max(1, int(drow["volume"]))
        d_oi = int(drow.get("oi", 0) or 0)

        # Brownian bridge from d_open to d_close bounded by [d_low, d_high]
        n = bars_per_day
        if n == 1:
            rows.append(
                {
                    "timestamp": day_ts,
                    "open": d_open,
                    "high": d_high,
                    "low": d_low,
                    "close": d_close,
                    "volume": d_vol,
                    "oi": d_oi,
                }
            )
            continue

        span = max(d_high - d_low, d_open * 0.002, tick)
        increments = rng.normal(0.0, span / math.sqrt(n) * 0.35, size=n)
        walk = np.cumsum(increments)
        t_frac = np.linspace(1.0 / n, 1.0, n)
        bridge = d_open + (d_close - d_open) * t_frac + (walk - t_frac * walk[-1])
        bridge = np.clip(bridge, max(tick, d_low), max(d_high, tick))
        bridge[-1] = d_close

        # Quadratic U-shaped volume allocation (strictly zero trig)
        u_weights = 0.65 + 1.45 * np.square(2.0 * np.linspace(0.0, 1.0, n) - 1.0)
        u_weights = u_weights / u_weights.sum()

        prev_c = d_open
        # Session start at day_ts + 03:45 UTC (09:15 IST) or day_ts directly
        base_ts = day_ts - (day_ts % 86400) + 13500
        for i in range(n):
            c_val = _round_tick(float(bridge[i]), tick)
            o_val = _round_tick(prev_c, tick)
            wick = abs(float(rng.normal(0.0, span * 0.04)))
            h_val = _round_tick(min(d_high, max(o_val, c_val) + wick), tick)
            l_val = _round_tick(max(tick, d_low, min(o_val, c_val) - wick), tick)
            h_val = max(h_val, o_val, c_val)
            l_val = min(l_val, o_val, c_val)
            rows.append(
                {
                    "timestamp": int(base_ts + i * bar_minutes * 60),
                    "open": float(o_val),
                    "high": float(h_val),
                    "low": float(l_val),
                    "close": float(c_val),
                    "volume": max(1, int(round(d_vol * float(u_weights[i])))),
                    "oi": d_oi,
                }
            )
            prev_c = c_val

    return pd.DataFrame(rows, columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])


class BrokerData:
    """OpenAlgo BrokerData implementation backed by Historify DuckDB & SandboxMarketFeed."""

    def __init__(
        self,
        auth_token: str = "",
        feed_token: str | None = None,
        user_id: str | None = None,
    ) -> None:
        self.auth_token = auth_token
        self.feed_token = feed_token
        self.user_id = user_id
        self.timeframe_map: dict[str, str] = {
            "1m": "1m",
            "3m": "3m",
            "5m": "5m",
            "10m": "10m",
            "15m": "15m",
            "30m": "30m",
            "1h": "1h",
            "D": "D",
            "W": "W",
            "M": "M",
        }
        self._feed = get_sandbox_market_feed()

    def get_quotes(self, symbol: str, exchange: str) -> dict[str, Any]:
        return self._feed.get_quote(symbol, exchange)

    def get_multiquotes(self, symbols: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for item in symbols or []:
            sym = str(item.get("symbol") or "").strip()
            ex = str(item.get("exchange") or "").strip()
            if not sym or not ex:
                continue
            try:
                quote = self._feed.get_quote(sym, ex)
                results.append({"symbol": sym, "exchange": ex, "data": quote})
            except Exception as exc:
                results.append({"symbol": sym, "exchange": ex, "error": str(exc)})
        return results

    def get_depth(self, symbol: str, exchange: str) -> dict[str, Any]:
        return self._feed.get_depth(symbol, exchange, levels=5)

    def get_market_depth(self, symbol: str, exchange: str) -> dict[str, Any]:
        return self.get_depth(symbol, exchange)

    def get_history(
        self,
        symbol: str,
        exchange: str,
        interval: str,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> pd.DataFrame:
        sym = symbol.strip().upper()
        ex = exchange.strip().upper()
        iv = (interval or "D").strip()
        if iv in ("1d", "1D", "day", "DAY"):
            iv = "D"

        start_ts = _parse_date_to_epoch(start_date, end_of_day=False)
        end_ts = _parse_date_to_epoch(end_date, end_of_day=True)

        df = historify_db.get_ohlcv(
            symbol=sym,
            exchange=ex,
            interval=iv,
            start_timestamp=start_ts,
            end_timestamp=end_ts,
        )

        # If intraday interval wasn't seeded directly for this symbol, disaggregate daily bars cleanly
        if (df is None or df.empty) and iv not in ("D", "W", "M", "Q", "Y"):
            daily_df = historify_db.get_ohlcv(
                symbol=sym,
                exchange=ex,
                interval="D",
                start_timestamp=start_ts,
                end_timestamp=end_ts,
            )
            if daily_df is None or daily_df.empty:
                daily_df = historify_db.get_ohlcv(symbol=sym, exchange=ex, interval="D")
            if daily_df is not None and not daily_df.empty:
                df = _synthesize_intraday_from_daily(daily_df, sym, ex, iv)
                if start_ts is not None:
                    df = df[df["timestamp"] >= start_ts]
                if end_ts is not None:
                    df = df[df["timestamp"] <= end_ts]

        if df is None or df.empty:
            return pd.DataFrame(columns=["timestamp", "open", "high", "low", "close", "volume", "oi"])

        out = df.copy()
        if "oi" not in out.columns:
            out["oi"] = 0
        out = out[["timestamp", "open", "high", "low", "close", "volume", "oi"]]
        out["timestamp"] = out["timestamp"].astype("int64")
        out = out.sort_values("timestamp").drop_duplicates(subset=["timestamp"], keep="last").reset_index(drop=True)
        return out
