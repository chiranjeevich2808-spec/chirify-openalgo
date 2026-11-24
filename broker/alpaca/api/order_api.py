"""Alpaca Order Execution Adapter (`US_EQUITY`, `US_OPTIONS`, `CRYPTO`).

Translates OpenAlgo order payloads into Alpaca Trading API v2 orders while
enforcing:
- Strict Paper vs Live host/credential separation.
- Thread-safe 200 req/min :class:`TokenBucketLimiter`.
- Exponential backoff with jitter on HTTP 429.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from broker.alpaca.api.auth_api import (
    AlpacaEnvironmentMismatchError,
    build_alpaca_headers,
    resolve_alpaca_environment,
)
from broker.alpaca.api.rate_limiter import (
    DEFAULT_ALPACA_LIMITER,
    AlpacaRateLimitError,
    TokenBucketLimiter,
    exponential_backoff_with_jitter,
)
from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)

SUPPORTED_EXCHANGES: frozenset[str] = frozenset({"US_EQUITY", "US_OPTIONS", "CRYPTO"})
MAX_429_RETRIES = 3


class _RespShim:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.status = status_code


def normalize_alpaca_symbol(symbol: str, exchange: str) -> str:
    """Normalize an OpenAlgo symbol into Alpaca's symbol format."""
    sym = (symbol or "").strip().upper()
    exch = (exchange or "US_EQUITY").strip().upper()
    if exch == "CRYPTO":
        # OpenAlgo BTCUSDT / BTC-USD / BTC/USD -> Alpaca BTC/USD or BTC/USDT
        if "/" in sym:
            return sym
        if "-" in sym:
            return sym.replace("-", "/")
        for quote in ("USDT", "USDC", "USD"):
            if sym.endswith(quote) and len(sym) > len(quote):
                return f"{sym[: -len(quote)]}/{quote}"
    return sym


def transform_order_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """Map an OpenAlgo order dictionary to an Alpaca ``POST /v2/orders`` payload."""
    exchange = str(data.get("exchange") or "US_EQUITY").strip().upper()
    if exchange not in SUPPORTED_EXCHANGES:
        raise ValueError(
            f"Unsupported Alpaca exchange {exchange!r}; expected one of {sorted(SUPPORTED_EXCHANGES)}."
        )

    symbol = normalize_alpaca_symbol(str(data.get("symbol") or ""), exchange)
    if not symbol:
        raise ValueError("Order symbol is required.")

    action = str(data.get("action") or "").strip().upper()
    if action not in {"BUY", "SELL"}:
        raise ValueError(f"Order action must be BUY or SELL, got {action!r}.")

    pricetype = str(data.get("pricetype") or data.get("price_type") or "MARKET").strip().upper()
    type_map = {
        "MARKET": "market",
        "LIMIT": "limit",
        "SL": "stop_limit",
        "SL-M": "stop",
        "SLM": "stop",
    }
    alpaca_type = type_map.get(pricetype)
    if alpaca_type is None:
        raise ValueError(f"Unsupported price type {pricetype!r} for Alpaca.")

    qty_str = str(data.get("quantity") or "").strip()
    if not qty_str or float(qty_str) <= 0:
        raise ValueError(f"Order quantity must be positive, got {qty_str!r}.")

    # Crypto requires GTC or IOC on Alpaca; US equities/options default to DAY
    default_tif = "gtc" if exchange == "CRYPTO" else "day"
    tif = str(data.get("time_in_force") or default_tif).strip().lower()

    payload: dict[str, Any] = {
        "symbol": symbol,
        "qty": qty_str,
        "side": action.lower(),
        "type": alpaca_type,
        "time_in_force": tif,
    }

    if alpaca_type in {"limit", "stop_limit"}:
        price = str(data.get("price") or "").strip()
        if not price or float(price) <= 0:
            raise ValueError(f"{pricetype} order requires a positive limit price.")
        payload["limit_price"] = price

    if alpaca_type in {"stop", "stop_limit"}:
        trig = str(data.get("trigger_price") or "").strip()
        if not trig or float(trig) <= 0:
            raise ValueError(f"{pricetype} order requires a positive trigger_price.")
        payload["stop_price"] = trig

    if data.get("extended_hours") is True and exchange == "US_EQUITY" and alpaca_type == "limit":
        payload["extended_hours"] = True

    return payload


def alpaca_request(
    method: str,
    path: str,
    auth_token: str,
    *,
    api_secret: str | None = None,
    paper: bool | None = None,
    base_url: str | None = None,
    json_body: Mapping[str, Any] | None = None,
    params: Mapping[str, Any] | None = None,
    client: httpx.Client | None = None,
    limiter: TokenBucketLimiter | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> tuple[int, Any]:
    """Execute a rate-limited, Paper/Live-isolated Alpaca Trading API call with 429 backoff."""
    secret = (api_secret if api_secret is not None else os.getenv("BROKER_API_SECRET", "")).strip()
    endpoint = resolve_alpaca_environment(auth_token, paper=paper, base_url=base_url)
    headers = build_alpaca_headers(endpoint.api_key, secret)
    url = f"{endpoint.trading_base_url}{path}"

    active_limiter = limiter or DEFAULT_ALPACA_LIMITER
    active_http = client or get_httpx_client()
    sleep_fn = sleeper or time.sleep

    for attempt in range(MAX_429_RETRIES + 1):
        active_limiter.acquire(max_wait=5.0)
        resp = active_http.request(
            method.upper(),
            url,
            headers=headers,
            json=dict(json_body) if json_body is not None else None,
            params=dict(params) if params is not None else None,
            timeout=20.0,
        )
        if resp.status_code == 429 and attempt < MAX_429_RETRIES:
            delay = exponential_backoff_with_jitter(attempt, headers=resp.headers)
            logger.warning(
                f"[Alpaca] HTTP 429 on {method} {path} (attempt {attempt + 1}); "
                f"backing off {delay:.2f}s"
            )
            sleep_fn(delay)
            continue

        if resp.status_code == 204 or not resp.text.strip():
            return resp.status_code, {}
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"message": resp.text}

    return 429, {"message": "Alpaca rate limit retries exhausted"}


def place_order_api(
    data: Mapping[str, Any],
    auth: str,
    *,
    api_secret: str | None = None,
    paper: bool | None = None,
    base_url: str | None = None,
    client: httpx.Client | None = None,
    limiter: TokenBucketLimiter | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> tuple[_RespShim, dict[str, Any], str | None]:
    """Place an order on Alpaca Markets using OpenAlgo's standard tuple contract."""
    try:
        payload = transform_order_data(data)
        status_code, body = alpaca_request(
            "POST",
            "/v2/orders",
            auth,
            api_secret=api_secret,
            paper=paper,
            base_url=base_url,
            json_body=payload,
            client=client,
            limiter=limiter,
            sleeper=sleeper,
        )
        if status_code in (200, 201) and isinstance(body, Mapping) and body.get("id"):
            order_id = str(body["id"])
            return _RespShim(200), {"status": "success", "orderid": order_id}, order_id

        err_msg = (
            body.get("message")
            if isinstance(body, Mapping)
            else str(body)
        ) or f"Alpaca HTTP {status_code}"
        return _RespShim(status_code), {"status": "error", "message": str(err_msg)}, None
    except (AlpacaEnvironmentMismatchError, AlpacaRateLimitError, ValueError) as exc:
        code = 429 if isinstance(exc, AlpacaRateLimitError) else 400
        return _RespShim(code), {"status": "error", "message": str(exc)}, None


def modify_order(
    data: Mapping[str, Any],
    auth: str,
    **kwargs: Any,
) -> tuple[dict[str, Any], int]:
    """Modify an open Alpaca order via ``PATCH /v2/orders/{order_id}``."""
    order_id = str(data.get("orderid") or "").strip()
    if not order_id:
        return {"status": "error", "message": "orderid is required"}, 400

    patch_body: dict[str, Any] = {}
    if data.get("quantity"):
        patch_body["qty"] = str(data["quantity"])
    if data.get("price") and float(str(data["price"])) > 0:
        patch_body["limit_price"] = str(data["price"])
    if data.get("trigger_price") and float(str(data["trigger_price"])) > 0:
        patch_body["stop_price"] = str(data["trigger_price"])

    status_code, body = alpaca_request(
        "PATCH", f"/v2/orders/{order_id}", auth, json_body=patch_body, **kwargs
    )
    if status_code in (200, 201):
        replaced_id = str(body.get("id", order_id)) if isinstance(body, Mapping) else order_id
        return {"status": "success", "orderid": replaced_id}, 200
    msg = body.get("message", "Modify order failed") if isinstance(body, Mapping) else str(body)
    return {"status": "error", "message": str(msg)}, status_code


def cancel_order(orderid: str, auth: str, **kwargs: Any) -> tuple[dict[str, Any], int]:
    """Cancel an open Alpaca order via ``DELETE /v2/orders/{order_id}``."""
    status_code, body = alpaca_request("DELETE", f"/v2/orders/{orderid}", auth, **kwargs)
    if status_code in (200, 204):
        return {"status": "success", "orderid": str(orderid)}, 200
    msg = body.get("message", "Cancel failed") if isinstance(body, Mapping) else str(body)
    return {"status": "error", "message": str(msg)}, status_code


def cancel_all_orders_api(
    data: Mapping[str, Any], auth: str, **kwargs: Any
) -> tuple[list[str], list[str]]:
    """Cancel all open Alpaca orders via ``DELETE /v2/orders``."""
    status_code, body = alpaca_request("DELETE", "/v2/orders", auth, **kwargs)
    if status_code in (200, 207) and isinstance(body, list):
        cancelled = [str(item.get("id")) for item in body if item.get("status") in (200, 204, None)]
        failed = [str(item.get("id")) for item in body if item.get("status") not in (200, 204, None)]
        return cancelled, failed
    return (["all"], []) if status_code == 204 else ([], ["all"])


def close_all_positions(
    current_api_key: str, auth: str, **kwargs: Any
) -> tuple[dict[str, Any], int]:
    """Liquidate all open positions via ``DELETE /v2/positions``."""
    status_code, _ = alpaca_request(
        "DELETE", "/v2/positions", auth, params={"cancel_orders": "true"}, **kwargs
    )
    if status_code in (200, 204, 207):
        return {"status": "success", "message": "All Open Positions SquaredOff"}, 200
    return {"status": "error", "message": f"Close positions failed ({status_code})"}, status_code


def get_order_book(auth: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Fetch open + closed orders for today."""
    status_code, body = alpaca_request(
        "GET", "/v2/orders", auth, params={"status": "all", "limit": 200}, **kwargs
    )
    return body if status_code == 200 and isinstance(body, list) else []


def get_trade_book(auth: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Fetch filled orders from Alpaca."""
    orders = get_order_book(auth, **kwargs)
    return [o for o in orders if isinstance(o, dict) and o.get("status") == "filled"]


def get_positions(auth: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Fetch open positions via ``GET /v2/positions``."""
    status_code, body = alpaca_request("GET", "/v2/positions", auth, **kwargs)
    return body if status_code == 200 and isinstance(body, list) else []


def get_holdings(auth: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Return long equity/crypto positions as holdings."""
    return [p for p in get_positions(auth, **kwargs) if str(p.get("side", "")).lower() == "long"]


def place_smartorder_api(
    data: Mapping[str, Any], auth: str, **kwargs: Any
) -> tuple[_RespShim | None, dict[str, Any], str | None]:
    """Adjust current position toward target ``position_size``."""
    target = float(data.get("position_size") or 0)
    sym = normalize_alpaca_symbol(
        str(data.get("symbol") or ""), str(data.get("exchange") or "US_EQUITY")
    )
    current = 0.0
    for pos in get_positions(auth, **kwargs):
        if str(pos.get("symbol", "")).upper() == sym.replace("/", ""):
            qty = float(pos.get("qty") or 0)
            current = -abs(qty) if str(pos.get("side", "")).lower() == "short" else abs(qty)
            break

    delta = target - current
    if abs(delta) < 1e-9:
        return None, {"status": "success", "message": "Position matches target"}, None

    order_payload = dict(data)
    order_payload["action"] = "BUY" if delta > 0 else "SELL"
    order_payload["quantity"] = str(abs(delta))
    return place_order_api(order_payload, auth, **kwargs)
