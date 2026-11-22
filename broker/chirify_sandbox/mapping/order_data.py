"""OpenAlgo-standard order, trade, position, and holdings data mappers for Chirify Sandbox."""

from __future__ import annotations

from typing import Any


def map_order_data(order_data: Any) -> list[dict[str, Any]]:
    if isinstance(order_data, dict):
        data = order_data.get("data", {})
        if isinstance(data, dict):
            return list(data.get("orders", []))
        if isinstance(data, list):
            return list(data)
    if isinstance(order_data, list):
        return list(order_data)
    return []


def calculate_order_statistics(order_data: list[dict[str, Any]] | None) -> dict[str, int]:
    rows = order_data or []
    buy = sell = complete = open_c = rejected = 0
    for row in rows:
        act = str(row.get("action") or row.get("transaction_type") or "").upper()
        if act == "BUY":
            buy += 1
        elif act == "SELL":
            sell += 1
        st = str(row.get("order_status") or row.get("status") or "").lower()
        if st == "complete":
            complete += 1
        elif st in ("open", "trigger pending"):
            open_c += 1
        elif st == "rejected":
            rejected += 1
    return {
        "total_buy_orders": buy,
        "total_sell_orders": sell,
        "total_completed_orders": complete,
        "total_open_orders": open_c,
        "total_rejected_orders": rejected,
    }


def transform_order_data(orders: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return list(orders or [])


def map_trade_data(trade_data: Any) -> list[dict[str, Any]]:
    if isinstance(trade_data, dict):
        data = trade_data.get("data", [])
        return list(data) if isinstance(data, list) else []
    if isinstance(trade_data, list):
        return list(trade_data)
    return []


def transform_tradebook_data(trades: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return list(trades or [])


def map_position_data(position_data: Any) -> list[dict[str, Any]]:
    if isinstance(position_data, dict):
        data = position_data.get("data", [])
        return list(data) if isinstance(data, list) else []
    if isinstance(position_data, list):
        return list(position_data)
    return []


def transform_positions_data(positions: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return list(positions or [])


def map_portfolio_data(portfolio_data: Any) -> list[dict[str, Any]]:
    if isinstance(portfolio_data, dict):
        data = portfolio_data.get("data", {})
        if isinstance(data, dict):
            return list(data.get("holdings", []))
        if isinstance(data, list):
            return list(data)
    if isinstance(portfolio_data, list):
        return list(portfolio_data)
    return []


def calculate_portfolio_statistics(holdings_data: list[dict[str, Any]] | None) -> dict[str, float]:
    rows = holdings_data or []
    total_holding_value = sum(float(r.get("quantity", 0) or 0) * float(r.get("ltp", r.get("average_price", 0)) or 0) for r in rows)
    total_inv_value = sum(float(r.get("quantity", 0) or 0) * float(r.get("average_price", 0) or 0) for r in rows)
    total_pnl = sum(float(r.get("pnl", 0) or 0) for r in rows)
    pnl_pct = (total_pnl / total_inv_value * 100.0) if total_inv_value > 0 else 0.0
    return {
        "totalholdingvalue": round(total_holding_value, 2),
        "totalinvvalue": round(total_inv_value, 2),
        "totalprofitandloss": round(total_pnl, 2),
        "totalpnlpercentage": round(pnl_pct, 2),
    }


def transform_holdings_data(holdings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return list(holdings or [])
