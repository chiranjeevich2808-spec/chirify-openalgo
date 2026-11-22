"""M1 Integration Tests: Sandbox Bootstrap, Historify DuckDB 1.5.5, Options Greeks/GEX, Strategy RMS, and MCP Internal Bridge."""

from __future__ import annotations

import math
from pathlib import Path

from flask import Flask
import pytest

from blueprints.internal_ops import internal_ops_bp
from utils import broker_keys
from utils.black_scholes import delta, gamma, implied_volatility, price, theta, vega


INTERNAL_TOKEN = "test-m1-internal-ops-token-2026"


@pytest.fixture()
def isolated_m1_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    hist_path = tmp_path / "historify_m1.duckdb"
    worm_path = tmp_path / "worm_m1.jsonl"
    sym_db_url = f"sqlite:///{tmp_path / 'openalgo_m1.db'}"
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_INTERNAL_OPS_TOKEN", INTERNAL_TOKEN)
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "tenant-m1-test")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_USERNAME", "m1_admin")
    monkeypatch.setenv("HISTORIFY_DATABASE_PATH", str(hist_path))
    monkeypatch.setenv("CHIRIFY_WORM_LOG_PATH", str(worm_path))

    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    from database import historify_db, symbol as symbol_db
    from services.chirify_sandbox_bootstrap import (
        seed_historify_market_data,
        seed_sandbox_symtokens,
    )

    orig_engine = symbol_db.engine
    orig_session = symbol_db.db_session
    test_engine = create_engine(sym_db_url)
    symbol_db.Base.metadata.create_all(bind=test_engine)
    test_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=test_engine))
    monkeypatch.setattr(symbol_db, "engine", test_engine)
    monkeypatch.setattr(symbol_db, "db_session", test_session)

    historify_db.close_duckdb_anchor()
    historify_db.init_database()
    seed_summary = seed_historify_market_data(seed_mode="synthetic")
    assert seed_summary["daily_seeded"] >= 45
    spots = {}
    for k, px in (seed_summary.get("latest_spots") or {}).items():
        if ":" in k:
            ex, sym = k.split(":", 1)
            spots[(sym, ex)] = float(px)
    seed_sandbox_symtokens(spots)

    app = Flask(__name__)
    app.config["TESTING"] = True
    app.register_blueprint(internal_ops_bp)
    yield app, tmp_path
    test_session.remove()
    test_engine.dispose()
    monkeypatch.setattr(symbol_db, "engine", orig_engine)
    monkeypatch.setattr(symbol_db, "db_session", orig_session)
    historify_db.close_duckdb_anchor(str(hist_path))


def _hdrs() -> dict[str, str]:
    return {"X-Chirify-Internal-Token": INTERNAL_TOKEN}


def test_black_scholes_put_call_parity_greeks_and_iv_inversion():
    fwd, strike, r, t, sigma = 25850.0, 25800.0, 0.065, 14.0 / 365.0, 0.145
    call_px = price("CE", fwd, strike, t, r, sigma)
    put_px = price("PE", fwd, strike, t, r, sigma)
    # Black-76 put-call parity: C - P = exp(-r * T) * (F - K)
    lhs = call_px - put_px
    rhs = math.exp(-r * t) * (fwd - strike)
    assert abs(lhs - rhs) < 1e-4

    assert 0.45 < delta("CE", fwd, strike, t, r, sigma) < 0.65
    assert -0.55 < delta("PE", fwd, strike, t, r, sigma) < -0.35
    assert gamma("CE", fwd, strike, t, r, sigma) > 0.0
    assert vega("CE", fwd, strike, t, r, sigma) > 0.0
    assert theta("CE", fwd, strike, t, r, sigma) < 0.0

    recovered_iv = implied_volatility(call_px, fwd, strike, r, t, "CE")
    assert abs(recovered_iv - sigma) < 1e-4


def test_broker_keys_supports_chirify_sandbox_without_daily_rollover_expiry():
    resolved = broker_keys.resolve("chirify_sandbox")
    assert resolved is not None
    assert resolved.broker == "chirify_sandbox"
    assert broker_keys.pin_keys_for("chirify_sandbox") is True
    assert broker_keys._never_expires("chirify_sandbox") is True
    # Live SEBI brokers must still expire at daily rollover by default
    assert broker_keys._never_expires("zerodha") is False


def test_internal_ops_auth_rejects_public_ip_and_bad_token(isolated_m1_app):
    app, _ = isolated_m1_app
    client = app.test_client()

    # Missing token -> 401/403
    r_missing = client.get(
        "/internal/v1/historify/catalog",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert r_missing.status_code in (401, 403)

    # Public REMOTE_ADDR with spoofed X-Forwarded-For -> 403 (INV-14)
    r_spoof = client.get(
        "/internal/v1/historify/catalog",
        headers={**_hdrs(), "X-Forwarded-For": "127.0.0.1"},
        environ_base={"REMOTE_ADDR": "8.8.8.8"},
    )
    assert r_spoof.status_code == 403


def test_historify_catalog_candles_ingest_and_parquet_export(isolated_m1_app):
    app, tmp_path = isolated_m1_app
    client = app.test_client()
    env = {"REMOTE_ADDR": "127.0.0.1"}

    cat = client.get("/internal/v1/historify/catalog", headers=_hdrs(), environ_base=env)
    assert cat.status_code == 200
    cat_json = cat.get_json()
    assert cat_json["status"] == "success"
    assert cat_json["total_rows"] > 10_000
    assert len(cat_json["items"]) >= 45

    cnd = client.get(
        "/internal/v1/historify/candles?symbol=RELIANCE&exchange=NSE&interval=D&limit=20",
        headers=_hdrs(),
        environ_base=env,
    )
    assert cnd.status_code == 200
    candles = cnd.get_json()["candles"]
    assert len(candles) == 20
    assert candles[-1]["close"] > 0

    ing = client.post(
        "/internal/v1/historify/ingest",
        json={
            "symbol": "TESTALPHA",
            "exchange": "NSE",
            "interval": "D",
            "candles": [
                {
                    "timestamp": 1735689600,
                    "open": 100.0,
                    "high": 105.0,
                    "low": 99.0,
                    "close": 103.5,
                    "volume": 250000.0,
                    "oi": 0.0,
                }
            ],
        },
        headers=_hdrs(),
        environ_base=env,
    )
    assert ing.status_code == 200
    assert ing.get_json()["upserted"] == 1

    out_pq = tmp_path / "snapshot.parquet"
    exp = client.post(
        "/internal/v1/historify/export-parquet",
        json={"output_path": str(out_pq), "exchange": "NSE", "interval": "D"},
        headers=_hdrs(),
        environ_base=env,
    )
    assert exp.status_code == 200
    assert out_pq.exists() and out_pq.stat().st_size > 1024


def test_options_analytics_chain_gex_and_iv_smile(isolated_m1_app):
    app, _ = isolated_m1_app
    client = app.test_client()
    resp = client.get(
        "/internal/v1/options/analytics?underlying=NIFTY&exchange=NFO",
        headers=_hdrs(),
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "success"
    assert body["spot_price"] > 0
    assert body["pcr"] > 0
    assert body["max_pain"] > 0
    assert len(body["chain"]) >= 10
    assert len(body["gex_profile"]) == len(body["chain"])
    assert len(body["iv_smile"]) == len(body["chain"])
    first = body["chain"][0]
    assert "ce_delta" in first and "pe_delta" in first and "ce_gamma" in first


def test_mcp_surface_gate1_and_gate2_confirmation_enforcement(isolated_m1_app):
    app, _ = isolated_m1_app
    client = app.test_client()
    env = {"REMOTE_ADDR": "127.0.0.1"}

    r_cop = client.get("/internal/v1/mcp/tools?surface=copilot", headers=_hdrs(), environ_base=env)
    r_chart = client.get("/internal/v1/mcp/tools?surface=trading_chart", headers=_hdrs(), environ_base=env)
    assert r_cop.status_code == 200 and r_chart.status_code == 200
    cop = r_cop.get_json()
    chart = r_chart.get_json()
    assert cop["total_tools"] >= 50
    assert chart["filtered_mutating_tools"] >= 7
    assert all(not t["mutating"] for t in chart["tools"])

    # Gate 1: mutating tool on trading_chart MUST be blocked (403)
    g1 = client.post(
        "/internal/v1/mcp/invoke",
        json={
            "tool_name": "place_order",
            "arguments": {"symbol": "RELIANCE", "exchange": "NSE", "action": "BUY", "quantity": 1},
            "surface": "trading_chart",
            "actor": "test-user",
        },
        headers=_hdrs(),
        environ_base=env,
    )
    assert g1.status_code == 403

    # Gate 2: mutating tool on copilot without confirmation_token pauses (202) and never executes
    g2_draft = client.post(
        "/internal/v1/mcp/invoke",
        json={
            "tool_name": "place_order",
            "arguments": {"symbol": "RELIANCE", "exchange": "NSE", "action": "BUY", "quantity": 1},
            "surface": "copilot",
            "confirmation_token": None,
            "actor": "test-user",
        },
        headers=_hdrs(),
        environ_base=env,
    )
    assert g2_draft.status_code == 202
    assert g2_draft.get_json().get("executed") is False

    # Gate 2: forged confirmation_token MUST be rejected (403)
    g2_forged = client.post(
        "/internal/v1/mcp/invoke",
        json={
            "tool_name": "place_order",
            "arguments": {"symbol": "RELIANCE", "exchange": "NSE", "action": "BUY", "quantity": 1},
            "surface": "copilot",
            "confirmation_token": "forged_id.forged_hmac",
            "actor": "test-user",
        },
        headers=_hdrs(),
        environ_base=env,
    )
    assert g2_forged.status_code == 403
