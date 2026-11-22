"""Margin calculator for Chirify Analyzer Sandbox broker plugin."""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from broker.chirify_sandbox.api.data import get_sandbox_market_feed
from database import auth_db, sandbox_db
from sandbox.fund_manager import FundManager


def _resolve_user_id() -> str:
    row = sandbox_db.SandboxFunds.query.first()
    if row is not None and row.user_id:
        return str(row.user_id)
    key_row = auth_db.ApiKeys.query.first()
    if key_row is not None and key_row.user_id:
        return str(key_row.user_id)
    return "trader"


def calculate_margin_api(
    positions: list[dict[str, Any]],
    auth_token: str = "",
) -> tuple[SimpleNamespace, dict[str, Any]]:
    """Compute realistic Sandbox span/exposure/total margin for a list of positions."""
    feed = get_sandbox_market_feed()
    fm = FundManager(_resolve_user_id())

    total_margin = Decimal("0.00")
    span_margin = Decimal("0.00")
    exposure_margin = Decimal("0.00")

    for pos in positions or []:
        symbol = str(pos.get("symbol") or "").strip().upper()
        exchange = str(pos.get("exchange") or "NSE").strip().upper()
        product = str(pos.get("product") or "MIS").strip().upper()
        action = str(pos.get("action") or "BUY").strip().upper()
        quantity = abs(int(pos.get("quantity") or 0))
        if not symbol or quantity <= 0:
            continue

        raw_price = float(pos.get("price") or 0.0)
        if raw_price <= 0.0:
            quote = feed.get_quote(symbol, exchange)
            raw_price = float(quote.get("ltp") or 0.0)

        price_dec = Decimal(str(round(raw_price, 4)))
        req_margin = fm.calculate_margin_required(
            symbol=symbol,
            exchange=exchange,
            product=product,
            quantity=quantity,
            price=price_dec,
            action=action,
        )
        req_dec = Decimal(str(req_margin))
        total_margin += req_dec
        if exchange in {"NFO", "BFO", "MCX", "CDS", "BCD", "NCDEX", "CRYPTO_SWAP"}:
            span_part = (req_dec * Decimal("0.72")).quantize(Decimal("0.01"))
            span_margin += span_part
            exposure_margin += req_dec - span_part
        else:
            exposure_margin += req_dec

    response = SimpleNamespace(status_code=200, status=200)
    payload = {
        "status": "success",
        "data": {
            "total_margin_required": round(float(total_margin), 2),
            "span_margin": round(float(span_margin), 2),
            "exposure_margin": round(float(exposure_margin), 2),
        },
    }
    return response, payload
