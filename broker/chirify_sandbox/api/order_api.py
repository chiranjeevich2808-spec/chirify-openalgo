"""Order & book fallback module for Chirify Analyzer Sandbox broker plugin.

In Analyzer Mode (`get_analyze_mode() == True`), RESTX services route directly
to ``services/sandbox_service.py``. This module provides matching delegators so
internal calls (which import ``broker.<broker>.api.order_api`` without checking
``original_data``) also resolve cleanly against the Sandbox database.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from database import auth_db, sandbox_db
from sandbox.holdings_manager import HoldingsManager
from sandbox.order_manager import OrderManager
from sandbox.position_manager import PositionManager


def _resolve_user_id() -> str:
    row = sandbox_db.SandboxFunds.query.first()
    if row is not None and row.user_id:
        return str(row.user_id)
    key_row = auth_db.ApiKeys.query.first()
    if key_row is not None and key_row.user_id:
        return str(key_row.user_id)
    return "trader"


def get_order_book(auth: str = "") -> dict[str, Any]:
    om = OrderManager(_resolve_user_id())
    _, resp, _ = om.get_orderbook()
    return resp


def get_trade_book(auth: str = "") -> dict[str, Any]:
    om = OrderManager(_resolve_user_id())
    _, resp, _ = om.get_tradebook()
    return resp


def get_positions(auth: str = "") -> dict[str, Any]:
    pm = PositionManager(_resolve_user_id())
    _, resp, _ = pm.get_open_positions(update_mtm=True)
    return resp


def get_holdings(auth: str = "") -> dict[str, Any]:
    hm = HoldingsManager(_resolve_user_id())
    _, resp, _ = hm.get_holdings(update_mtm=True)
    return resp


def place_order_api(data: dict[str, Any], auth: str = "") -> tuple[SimpleNamespace, dict[str, Any], str | None]:
    om = OrderManager(_resolve_user_id())
    _, resp, code = om.place_order(data)
    return SimpleNamespace(status=code, status_code=code), resp, resp.get("orderid")


def place_smartorder_api(data: dict[str, Any], auth: str = "") -> tuple[SimpleNamespace, dict[str, Any], str | None]:
    return place_order_api(data, auth)


def modify_order(data: dict[str, Any], auth: str = "") -> tuple[dict[str, Any], int]:
    om = OrderManager(_resolve_user_id())
    _, resp, code = om.modify_order(data)
    return resp, code


def cancel_order(orderid: str, auth: str = "") -> tuple[dict[str, Any], int]:
    om = OrderManager(_resolve_user_id())
    _, resp, code = om.cancel_order(orderid)
    return resp, code


def cancel_all_orders_api(data: dict[str, Any], auth: str = "") -> tuple[list[str], list[str]]:
    om = OrderManager(_resolve_user_id())
    _, resp, _ = om.cancel_all_orders(strategy=data.get("strategy") if isinstance(data, dict) else None)
    return list(resp.get("canceled_orders", [])), list(resp.get("failed_cancellations", []))


def close_all_positions(current_api_key: str = "", auth: str = "") -> tuple[dict[str, Any], int]:
    pm = PositionManager(_resolve_user_id())
    _, resp, code = pm.close_position()
    return resp, code
