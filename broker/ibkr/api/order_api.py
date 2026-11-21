"""IBKR Multi-Asset Order Adapter (`US_EQUITY`, `US_OPTIONS`, `EU_EQUITY`, `FUTURES`, `FOREX`)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from broker.ibkr.api.oauth_web_api import IBKROAuthWebClient
from utils.logging import get_logger

logger = get_logger(__name__)

SUPPORTED_EXCHANGES: frozenset[str] = frozenset(
    {"US_EQUITY", "US_OPTIONS", "EU_EQUITY", "FUTURES", "FOREX"}
)

EXCHANGE_ROUTING_MAP: Mapping[str, tuple[str, str]] = {
    "US_EQUITY": ("SMART", "STK"),
    "US_OPTIONS": ("SMART", "OPT"),
    "EU_EQUITY": ("SMART", "STK"),
    "FUTURES": ("CME", "FUT"),
    "FOREX": ("IDEALPRO", "CASH"),
}


class _RespShim:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.status = status_code


def transform_ibkr_order(data: Mapping[str, Any], account_id: str) -> dict[str, Any]:
    """Map an OpenAlgo order dictionary to an IBKR Web API order ticket."""
    exchange = str(data.get("exchange") or "US_EQUITY").strip().upper()
    if exchange not in SUPPORTED_EXCHANGES:
        raise ValueError(f"Unsupported IBKR exchange {exchange!r}.")

    listing_exchange, sec_type = EXCHANGE_ROUTING_MAP[exchange]
    symbol = str(data.get("symbol") or "").strip().upper()
    if not symbol:
        raise ValueError("Order symbol is required.")

    side = str(data.get("action") or "").strip().upper()
    if side not in {"BUY", "SELL"}:
        raise ValueError(f"Action must be BUY or SELL, got {side!r}.")

    pricetype = str(data.get("pricetype") or data.get("price_type") or "MARKET").strip().upper()
    order_type_map = {"MARKET": "MKT", "LIMIT": "LMT", "SL": "STP LMT", "SL-M": "STP", "SLM": "STP"}
    ib_order_type = order_type_map.get(pricetype)
    if ib_order_type is None:
        raise ValueError(f"Unsupported IBKR price type {pricetype!r}.")

    qty = float(data.get("quantity") or 0)
    if qty <= 0:
        raise ValueError("Quantity must be strictly positive.")

    ticket: dict[str, Any] = {
        "acctId": account_id,
        "ticker": symbol,
        "secType": sec_type,
        "listingExchange": listing_exchange,
        "orderType": ib_order_type,
        "side": side,
        "quantity": qty,
        "tif": str(data.get("time_in_force") or "DAY").upper(),
        "outsideRTH": bool(data.get("extended_hours", False)),
    }
    if data.get("conid") is not None:
        ticket["conid"] = int(data["conid"])
    if ib_order_type in {"LMT", "STP LMT"}:
        ticket["price"] = float(data.get("price") or 0)
        if ticket["price"] <= 0:
            raise ValueError(f"{pricetype} order requires a positive limit price.")
    if ib_order_type in {"STP", "STP LMT"}:
        ticket["auxPrice"] = float(data.get("trigger_price") or 0)
        if ticket["auxPrice"] <= 0:
            raise ValueError(f"{pricetype} order requires a positive trigger_price.")
    return {"orders": [ticket]}


def place_order_api(
    data: Mapping[str, Any],
    auth: str,
    *,
    account_id: str | None = None,
    web_client: IBKROAuthWebClient | None = None,
) -> tuple[_RespShim, dict[str, Any], str | None]:
    """Place an order via IBKR Web API ``POST /iserver/account/{accountId}/orders``."""
    acct = (account_id or os.getenv("IBKR_ACCOUNT_ID") or "DU000000").strip()
    try:
        payload = transform_ibkr_order(data, acct)
        client = web_client or IBKROAuthWebClient(auth, owner_id=f"order_{acct}")
        status_code, resp = client.request(
            "POST", f"/iserver/account/{acct}/orders", json_body=payload
        )
        if status_code in (200, 201) and isinstance(resp, list) and resp:
            first = resp[0]
            # Handle automated order warning reply confirmation if required
            if "id" in first and "order_id" not in first and first.get("message"):
                reply_id = first["id"]
                status_code, resp = client.request(
                    "POST", f"/iserver/reply/{reply_id}", json_body={"confirmed": True}
                )
                first = resp[0] if isinstance(resp, list) and resp else {}
            order_id = str(first.get("order_id") or "")
            if order_id:
                return _RespShim(200), {"status": "success", "orderid": order_id}, order_id

        return _RespShim(400), {"status": "error", "message": str(resp)}, None
    except Exception as exc:
        logger.error(f"[IBKR] Order placement failed: {exc}")
        return _RespShim(400), {"status": "error", "message": str(exc)}, None


def modify_order(
    data: Mapping[str, Any],
    auth: str,
    *,
    account_id: str | None = None,
    web_client: IBKROAuthWebClient | None = None,
) -> tuple[dict[str, Any], int]:
    """Modify an open IBKR order."""
    acct = (account_id or os.getenv("IBKR_ACCOUNT_ID") or "DU000000").strip()
    order_id = str(data.get("orderid") or "").strip()
    if not order_id:
        return {"status": "error", "message": "orderid is required"}, 400
    payload = transform_ibkr_order(data, acct)["orders"][0]
    client = web_client or IBKROAuthWebClient(auth, owner_id=f"order_{acct}")
    status_code, resp = client.request(
        "POST", f"/iserver/account/{acct}/order/{order_id}", json_body=payload
    )
    if status_code == 200:
        return {"status": "success", "orderid": order_id}, 200
    return {"status": "error", "message": str(resp)}, status_code


def cancel_order(
    orderid: str,
    auth: str,
    *,
    account_id: str | None = None,
    web_client: IBKROAuthWebClient | None = None,
) -> tuple[dict[str, Any], int]:
    """Cancel an open IBKR order via ``DELETE /iserver/account/{accountId}/order/{orderId}``."""
    acct = (account_id or os.getenv("IBKR_ACCOUNT_ID") or "DU000000").strip()
    client = web_client or IBKROAuthWebClient(auth, owner_id=f"order_{acct}")
    status_code, resp = client.request("DELETE", f"/iserver/account/{acct}/order/{orderid}")
    if status_code == 200:
        return {"status": "success", "orderid": str(orderid)}, 200
    return {"status": "error", "message": str(resp)}, status_code


def get_order_book(
    auth: str, *, web_client: IBKROAuthWebClient | None = None
) -> list[dict[str, Any]]:
    """Fetch IBKR live/today order book."""
    client = web_client or IBKROAuthWebClient(auth, owner_id="orderbook")
    status_code, resp = client.request("GET", "/iserver/account/orders")
    if status_code == 200 and isinstance(resp, Mapping):
        orders = resp.get("orders", [])
        return orders if isinstance(orders, list) else []
    return []


def cancel_all_orders_api(
    data: Mapping[str, Any], auth: str, **kwargs: Any
) -> tuple[list[str], list[str]]:
    """Cancel all working IBKR orders."""
    cancelled: list[str] = []
    failed: list[str] = []
    for order in get_order_book(auth, web_client=kwargs.get("web_client")):
        oid = str(order.get("orderId") or "")
        status = str(order.get("status") or "").lower()
        if oid and status in {"submitted", "presubmitted", "pending"}:
            _, code = cancel_order(oid, auth, **kwargs)
            (cancelled if code == 200 else failed).append(oid)
    return cancelled, failed


def get_positions(
    auth: str,
    *,
    account_id: str | None = None,
    web_client: IBKROAuthWebClient | None = None,
) -> list[dict[str, Any]]:
    """Fetch open portfolio positions."""
    acct = (account_id or os.getenv("IBKR_ACCOUNT_ID") or "DU000000").strip()
    client = web_client or IBKROAuthWebClient(auth, owner_id=f"pos_{acct}")
    status_code, resp = client.request("GET", f"/portfolio/{acct}/positions/0")
    return resp if status_code == 200 and isinstance(resp, list) else []


def get_holdings(auth: str, **kwargs: Any) -> list[dict[str, Any]]:
    return [p for p in get_positions(auth, **kwargs) if float(p.get("position") or 0) > 0]


def close_all_positions(
    current_api_key: str, auth: str, **kwargs: Any
) -> tuple[dict[str, Any], int]:
    """Square off open IBKR positions with market orders."""
    for pos in get_positions(auth, **kwargs):
        qty = float(pos.get("position") or 0)
        if qty == 0:
            continue
        place_order_api(
            {
                "symbol": str(pos.get("contractDesc") or pos.get("ticker") or ""),
                "exchange": "US_EQUITY",
                "action": "SELL" if qty > 0 else "BUY",
                "pricetype": "MARKET",
                "quantity": abs(qty),
                "conid": pos.get("conid"),
            },
            auth,
            **kwargs,
        )
    return {"status": "success", "message": "All Open Positions SquaredOff"}, 200
