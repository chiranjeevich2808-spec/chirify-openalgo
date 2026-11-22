"""Funds helper for Chirify Analyzer Sandbox broker plugin."""

from __future__ import annotations

from typing import Any

from database import auth_db, sandbox_db
from sandbox.fund_manager import FundManager


def _resolve_sandbox_user_id() -> str:
    row = sandbox_db.SandboxFunds.query.first()
    if row is not None and row.user_id:
        return str(row.user_id)
    key_row = auth_db.ApiKeys.query.first()
    if key_row is not None and key_row.user_id:
        return str(key_row.user_id)
    return "trader"


def get_margin_data(auth_token: str = "") -> dict[str, Any]:
    """Return OpenAlgo-normalized funds dictionary backed by ``FundManager``."""
    user_id = _resolve_sandbox_user_id()
    fm = FundManager(user_id)
    fm.initialize_funds()
    funds = fm.get_funds() or {}
    return {
        "availablecash": f"{float(funds.get('availablecash', 0.0)):.2f}",
        "collateral": f"{float(funds.get('collateral', 0.0)):.2f}",
        "m2mrealized": f"{float(funds.get('m2mrealized', 0.0)):.2f}",
        "m2munrealized": f"{float(funds.get('m2munrealized', 0.0)):.2f}",
        "utiliseddebits": f"{float(funds.get('utiliseddebits', 0.0)):.2f}",
    }
