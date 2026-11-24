"""Pure-Python Analytical Black-76 Option Pricing, Greeks & Implied Volatility Engine.

Zero native binary dependencies (stdlib ``math`` + optional ``numpy`` for array
batch helpers). Implements the exact ``opengreeks.black76`` scalar and ``*_array``
function signatures and trader-friendly units so OpenAlgo's option chain,
option Greeks, and internal options analytics services work seamlessly even
when ``opengreeks`` / ``py_vollib`` / ``scipy`` are not installed.

Units convention (matches ``services/option_greeks_service.py`` & ``opengreeks``):
- ``flag``: ``"c"`` for Call, ``"p"`` for Put (case-insensitive; ``"CE"``/``"PE"`` accepted).
- ``r``: risk-free interest rate as decimal (e.g. ``0.065`` for 6.5%).
- ``sigma``: annualized volatility as decimal (e.g. ``0.18`` for 18%).
- ``t``: time to expiry in years (``> 0``).
- ``delta``: dimensionless discounted forward sensitivity (Call in ``(0, 1]``, Put in ``[-1, 0)``).
- ``gamma``: second derivative w.r.t. forward price.
- ``vega``: price change per +1 percentage-point (0.01) IV move.
- ``theta``: daily calendar decay (annual theta divided by 365).
- ``rho``: price change per +1 percentage-point (0.01) interest-rate move.
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np

_SQRT_2 = math.sqrt(2.0)
_SQRT_2PI = math.sqrt(2.0 * math.pi)
_INV_SQRT_2PI = 1.0 / _SQRT_2PI

_SIGMA_MIN = 1e-4
_SIGMA_MAX = 5.0


def _norm_flag(flag: str) -> str:
    raw = str(flag or "").strip().lower()
    if raw in ("c", "ce", "call"):
        return "c"
    if raw in ("p", "pe", "put"):
        return "p"
    raise ValueError(f"Unsupported option flag: {flag!r} (expected 'c'/'p' or 'CE'/'PE')")


def norm_pdf(x: float) -> float:
    """Standard normal probability density function."""
    return _INV_SQRT_2PI * math.exp(-0.5 * x * x)


def norm_cdf(x: float) -> float:
    """Standard normal cumulative distribution function via ``math.erf``."""
    return 0.5 * (1.0 + math.erf(x / _SQRT_2))


def _d1_d2(F: float, K: float, t: float, sigma: float) -> tuple[float, float, float]:
    sqrt_t = math.sqrt(t)
    vol_sqrt_t = sigma * sqrt_t
    d1 = (math.log(F / K) + 0.5 * sigma * sigma * t) / vol_sqrt_t
    d2 = d1 - vol_sqrt_t
    return d1, d2, sqrt_t


def price(flag: str, F: float, K: float, t: float, r: float, sigma: float) -> float:
    """Compute Black-76 European option price on forward/futures ``F``."""
    f = _norm_flag(flag)
    if F <= 0.0 or K <= 0.0 or t <= 0.0 or sigma <= 0.0:
        intrinsic = max(F - K, 0.0) if f == "c" else max(K - F, 0.0)
        return math.exp(-r * max(t, 0.0)) * intrinsic
    disc = math.exp(-r * t)
    d1, d2, _ = _d1_d2(F, K, t, sigma)
    if f == "c":
        return disc * (F * norm_cdf(d1) - K * norm_cdf(d2))
    return disc * (K * norm_cdf(-d2) - F * norm_cdf(-d1))


def delta(flag: str, F: float, K: float, t: float, r: float, sigma: float) -> float:
    """Black-76 option delta."""
    f = _norm_flag(flag)
    if F <= 0.0 or K <= 0.0 or t <= 0.0 or sigma <= 0.0:
        if f == "c":
            return 1.0 if F > K else 0.0
        return -1.0 if K > F else 0.0
    disc = math.exp(-r * t)
    d1, _, _ = _d1_d2(F, K, t, sigma)
    if f == "c":
        return disc * norm_cdf(d1)
    return -disc * norm_cdf(-d1)


def gamma(flag: str, F: float, K: float, t: float, r: float, sigma: float) -> float:
    """Black-76 option gamma (identical for Calls and Puts)."""
    _norm_flag(flag)
    if F <= 0.0 or K <= 0.0 or t <= 0.0 or sigma <= 0.0:
        return 0.0
    disc = math.exp(-r * t)
    d1, _, sqrt_t = _d1_d2(F, K, t, sigma)
    return (disc * norm_pdf(d1)) / (F * sigma * sqrt_t)


def vega(flag: str, F: float, K: float, t: float, r: float, sigma: float) -> float:
    """Black-76 option vega per 1 percentage-point (0.01) move in IV."""
    _norm_flag(flag)
    if F <= 0.0 or K <= 0.0 or t <= 0.0 or sigma <= 0.0:
        return 0.0
    disc = math.exp(-r * t)
    d1, _, sqrt_t = _d1_d2(F, K, t, sigma)
    return (disc * F * norm_pdf(d1) * sqrt_t) / 100.0


def theta(flag: str, F: float, K: float, t: float, r: float, sigma: float) -> float:
    """Black-76 option daily calendar theta (annual theta divided by 365)."""
    f = _norm_flag(flag)
    if F <= 0.0 or K <= 0.0 or t <= 0.0 or sigma <= 0.0:
        return 0.0
    disc = math.exp(-r * t)
    d1, d2, sqrt_t = _d1_d2(F, K, t, sigma)
    time_decay = -(disc * F * norm_pdf(d1) * sigma) / (2.0 * sqrt_t)
    if f == "c":
        opt_val = disc * (F * norm_cdf(d1) - K * norm_cdf(d2))
    else:
        opt_val = disc * (K * norm_cdf(-d2) - F * norm_cdf(-d1))
    annual_theta = time_decay + r * opt_val
    return annual_theta / 365.0


def rho(flag: str, F: float, K: float, t: float, r: float, sigma: float) -> float:
    """Black-76 option rho per 1 percentage-point (0.01) move in interest rate."""
    opt_val = price(flag, F, K, t, r, sigma)
    return (-t * opt_val) / 100.0


def implied_volatility(
    option_price: float,
    F: float,
    K: float,
    r: float,
    t: float,
    flag: str,
    *,
    tol: float = 1e-7,
    max_iter: int = 64,
) -> float:
    """Solve Black-76 implied volatility (decimal) via safeguarded Newton-Raphson + bisection.

    Raises:
        ValueError: If price is non-positive, below intrinsic, above theoretical
            upper bound, or does not converge within ``[_SIGMA_MIN, _SIGMA_MAX]``.
    """
    f = _norm_flag(flag)
    if F <= 0.0 or K <= 0.0 or t <= 0.0 or option_price <= 0.0:
        raise ValueError("Invalid Black-76 inputs: F, K, t, and option_price must be positive.")

    disc = math.exp(-r * t)
    intrinsic = disc * (max(F - K, 0.0) if f == "c" else max(K - F, 0.0))
    upper_bound = disc * (F if f == "c" else K)
    if option_price <= intrinsic + 1e-12:
        raise ValueError("Option price is at or below discounted intrinsic value.")
    if option_price >= upper_bound:
        raise ValueError("Option price exceeds theoretical upper bound.")

    low = _SIGMA_MIN
    high = _SIGMA_MAX
    p_low = price(f, F, K, t, r, low) - option_price
    if p_low >= 0.0:
        return low
    p_high = price(f, F, K, t, r, high) - option_price
    if p_high <= 0.0:
        raise ValueError("Implied volatility convergence failed (exceeds upper vol bracket).")

    # Brenner-Subrahmanyam ATM seed clamped cleanly inside bracket
    sqrt_t = math.sqrt(t)
    sigma = (_SQRT_2PI / sqrt_t) * (option_price / F)
    if not math.isfinite(sigma) or sigma <= low or sigma >= high:
        sigma = 0.5 * (low + high)
    else:
        sigma = max(0.05, min(2.0, sigma))

    for _ in range(max_iter):
        val = price(f, F, K, t, r, sigma) - option_price
        if abs(val) < tol:
            return sigma

        if val < 0.0:
            low = sigma
        else:
            high = sigma

        d1, _, _ = _d1_d2(F, K, t, sigma)
        raw_vega = disc * F * norm_pdf(d1) * sqrt_t
        if raw_vega > 1e-10:
            candidate = sigma - (val / raw_vega)
            if low < candidate < high:
                sigma = candidate
                continue
        sigma = 0.5 * (low + high)
        if (high - low) < 1e-9:
            return sigma

    return sigma


def implied_volatility_array(
    prices: Any,
    forwards: Any,
    strikes: Any,
    r: float,
    tenors: Any,
    flag: str,
) -> np.ndarray:
    """Vectorized-compatible Black-76 IV solver returning ``np.nan`` on non-convergent legs."""
    p_arr = np.asarray(prices, dtype=float)
    f_arr = np.asarray(forwards, dtype=float)
    k_arr = np.asarray(strikes, dtype=float)
    t_arr = np.asarray(tenors, dtype=float)
    out = np.full(p_arr.shape, np.nan, dtype=float)
    for idx in range(p_arr.size):
        try:
            out.flat[idx] = implied_volatility(
                float(p_arr.flat[idx]),
                float(f_arr.flat[idx]),
                float(k_arr.flat[idx]),
                float(r),
                float(t_arr.flat[idx]),
                flag,
            )
        except Exception:
            out.flat[idx] = np.nan
    return out


def _apply_greek_array(
    fn,
    flag: str,
    forwards: Any,
    strikes: Any,
    tenors: Any,
    r: float,
    sigmas: Any,
) -> np.ndarray:
    f_arr = np.asarray(forwards, dtype=float)
    k_arr = np.asarray(strikes, dtype=float)
    t_arr = np.asarray(tenors, dtype=float)
    s_arr = np.asarray(sigmas, dtype=float)
    out = np.zeros(f_arr.shape, dtype=float)
    for idx in range(f_arr.size):
        out.flat[idx] = fn(
            flag,
            float(f_arr.flat[idx]),
            float(k_arr.flat[idx]),
            float(t_arr.flat[idx]),
            float(r),
            float(s_arr.flat[idx]),
        )
    return out


def delta_array(flag: str, F: Any, K: Any, t: Any, r: float, sigma: Any) -> np.ndarray:
    return _apply_greek_array(delta, flag, F, K, t, r, sigma)


def gamma_array(flag: str, F: Any, K: Any, t: Any, r: float, sigma: Any) -> np.ndarray:
    return _apply_greek_array(gamma, flag, F, K, t, r, sigma)


def theta_array(flag: str, F: Any, K: Any, t: Any, r: float, sigma: Any) -> np.ndarray:
    return _apply_greek_array(theta, flag, F, K, t, r, sigma)


def vega_array(flag: str, F: Any, K: Any, t: Any, r: float, sigma: Any) -> np.ndarray:
    return _apply_greek_array(vega, flag, F, K, t, r, sigma)


def rho_array(flag: str, F: Any, K: Any, t: Any, r: float, sigma: Any) -> np.ndarray:
    return _apply_greek_array(rho, flag, F, K, t, r, sigma)


def calculate_option_greeks(
    flag: str,
    F: float,
    K: float,
    t: float,
    r: float,
    sigma: float,
) -> dict[str, float]:
    """Convenience bundle returning Black-76 price and all trader-unit Greeks."""
    return {
        "price": round(price(flag, F, K, t, r, sigma), 4),
        "iv": round(sigma * 100.0, 2),
        "delta": round(delta(flag, F, K, t, r, sigma), 4),
        "gamma": round(gamma(flag, F, K, t, r, sigma), 6),
        "theta": round(theta(flag, F, K, t, r, sigma), 4),
        "vega": round(vega(flag, F, K, t, r, sigma), 4),
        "rho": round(rho(flag, F, K, t, r, sigma), 4),
    }
