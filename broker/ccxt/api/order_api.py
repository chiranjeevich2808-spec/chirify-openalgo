"""CCXT Unified Order Adapter (`CRYPTO`, `CRYPTO_SWAP`, `CRYPTO_OPTIONS`)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from broker.ccxt.api.precision_and_nonce import (
    CCXTPrecisionError,
    PreciseFormatter,
    normalize_contract_quantity,
)
from utils.logging import get_logger

logger = get_logger(__name__)

SUPPORTED_EXCHANGES: frozenset[str] = frozenset({"CRYPTO", "CRYPTO_SWAP", "CRYPTO_OPTIONS"})


class _RespShim:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.status = status_code


def prepare_ccxt_order_args(
    data: Mapping[str, Any],
    *,
    market: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize an OpenAlgo order payload into exact CCXT ``create_order`` parameters."""
    exchange_tag = str(data.get("exchange") or "CRYPTO").strip().upper()
    if exchange_tag not in SUPPORTED_EXCHANGES:
        raise ValueError(f"Unsupported CCXT exchange {exchange_tag!r}.")

    symbol = str(data.get("symbol") or "").strip().upper()
    side = str(data.get("action") or "").strip().lower()
    if side not in {"buy", "sell"}:
        raise ValueError(f"Order action must be BUY or SELL, got {side!r}.")

    pricetype = str(data.get("pricetype") or data.get("price_type") or "MARKET").strip().upper()
    order_type = "market" if pricetype == "MARKET" else "limit"

    ref_price = data.get("price") or data.get("ltp")
    normalized_qty = normalize_contract_quantity(
        symbol,
        data.get("quantity", 0),
        market,
        reference_price=ref_price,
    )

    formatted_price: str | None = None
    if order_type == "limit":
        if data.get("price") is None:
            raise CCXTPrecisionError("LIMIT order requires a positive price.")
        formatted_price = PreciseFormatter.price_to_precision(symbol, data["price"], market)

    params: dict[str, Any] = {}
    if pricetype in {"SL", "SL-M", "SLM"} and data.get("trigger_price") is not None:
        params["stopPrice"] = PreciseFormatter.price_to_precision(
            symbol, data["trigger_price"], market
        )
    if data.get("reduce_only") is True:
        params["reduceOnly"] = True

    return {
        "symbol": normalized_qty.symbol,
        "type": order_type,
        "side": side,
        "amount": float(normalized_qty.formatted_amount),
        "formatted_amount": normalized_qty.formatted_amount,
        "price": float(formatted_price) if formatted_price is not None else None,
        "formatted_price": formatted_price,
        "params": params,
    }


def place_order_api(
    data: Mapping[str, Any],
    auth: str,
    *,
    exchange_instance: Any | None = None,
    market: Mapping[str, Any] | None = None,
) -> tuple[_RespShim, dict[str, Any], str | None]:
    """Place a spot, swap, or option order through a CCXT exchange instance."""
    try:
        resolved_market = market
        if resolved_market is None and exchange_instance is not None and getattr(exchange_instance, "markets", None):
            resolved_market = exchange_instance.markets.get(str(data.get("symbol") or "").upper())

        args = prepare_ccxt_order_args(data, market=resolved_market)
        if exchange_instance is None:
            return _RespShim(400), {"status": "error", "message": "CCXT exchange instance not initialized"}, None

        res = exchange_instance.create_order(
            args["symbol"],
            args["type"],
            args["side"],
            args["amount"],
            args["price"],
            args["params"],
        )
        order_id = str(res.get("id") or "")
        return _RespShim(200), {"status": "success", "orderid": order_id}, order_id
    except Exception as exc:
        logger.error(f"[CCXT] Order placement failed: {exc}")
        return _RespShim(400), {"status": "error", "message": str(exc)}, None


def cancel_order(
    orderid: str,
    auth: str,
    *,
    symbol: str | None = None,
    exchange_instance: Any | None = None,
) -> tuple[dict[str, Any], int]:
    """Cancel an open CCXT order."""
    if exchange_instance is None:
        return {"status": "error", "message": "CCXT exchange instance not initialized"}, 400
    try:
        exchange_instance.cancel_order(orderid, symbol)
        return {"status": "success", "orderid": str(orderid)}, 200
    except Exception as exc:
        return {"status": "error", "message": str(exc)}, 400


def modify_order(
    data: Mapping[str, Any],
    auth: str,
    *,
    exchange_instance: Any | None = None,
    market: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], int]:
    """Edit an open CCXT order via ``edit_order``."""
    if exchange_instance is None:
        return {"status": "error", "message": "CCXT exchange instance not initialized"}, 400
    try:
        args = prepare_ccxt_order_args(data, market=market)
        res = exchange_instance.edit_order(
            str(data.get("orderid")),
            args["symbol"],
            args["type"],
            args["side"],
            args["amount"],
            args["price"],
            args["params"],
        )
        return {"status": "success", "orderid": str(res.get("id", data.get("orderid")))}, 200
    except Exception as exc:
        return {"status": "error", "message": str(exc)}, 400


def cancel_all_orders_api(
    data: Mapping[str, Any], auth: str, *, exchange_instance: Any | None = None
) -> tuple[list[str], list[str]]:
    if exchange_instance is None:
        return [], ["uninitialized"]
    symbol = data.get("symbol")
    if hasattr(exchange_instance, "cancel_all_orders"):
        exchange_instance.cancel_all_orders(symbol)
        return ["all"], []
    return [], []


def get_order_book(auth: str, *, symbol: str | None = None, exchange_instance: Any | None = None) -> list[dict[str, Any]]:
    if exchange_instance is None or not hasattr(exchange_instance, "fetch_open_orders"):
        return []
    return list(exchange_instance.fetch_open_orders(symbol))


def get_positions(auth: str, *, exchange_instance: Any | None = None) -> list[dict[str, Any]]:
    if exchange_instance is None or not hasattr(exchange_instance, "fetch_positions"):
        return []
    return list(exchange_instance.fetch_positions())


def get_holdings(auth: str, **kwargs: Any) -> list[dict[str, Any]]:
    return get_positions(auth, **kwargs)


def close_all_positions(
    current_api_key: str, auth: str, *, exchange_instance: Any | None = None
) -> tuple[dict[str, Any], int]:
    for pos in get_positions(auth, exchange_instance=exchange_instance):
        contracts = float(pos.get("contracts") or 0)
        if contracts <= 0:
            continue
        side = "SELL" if str(pos.get("side") or "").lower() == "long" else "BUY"
        if exchange_instance is not None:
            exchange_instance.create_order(
                pos["symbol"], "market", side.lower(), contracts, None, {"reduceOnly": True}
            )
    return {"status": "success", "message": "All Open Positions SquaredOff"}, 200
