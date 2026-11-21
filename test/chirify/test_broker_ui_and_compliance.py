"""PRR Tests: Broker Discovery & Setup UI (`alpaca`, `ibkr`, `ccxt`), AGPL-3.0 / EU AI Act
Status Telemetry (`/api/v1/chirify/status`), and DORA Emergency Kill-Switch.
"""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from dotenv import dotenv_values
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from marshmallow import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import NullPool

from blueprints.auth import auth_bp
from blueprints.brlogin import brlogin_bp
from blueprints.broker_config import broker_config_bp
from blueprints.broker_credentials import broker_credentials_bp
from blueprints.chirify_sso import chirify_sso_bp
from blueprints.chirify_status import (
    DEFAULT_CHIRIFY_SOURCE_REPO_URL,
    EU_AI_ACT_ART50_DISCLOSURE,
    UPSTREAM_OPENALGO_URL,
    chirify_probes_bp,
    chirify_status_bp,
)
from blueprints.internal_ops import internal_ops_bp
from blueprints.settings import settings_bp
from database import analyzer_db, auth_db, broker_keys_db, settings_db, user_db
from services import analyzer_service
from services.chirify_agent_guard import PromptBlindOrderGuard
from services.chirify_bootstrap_service import install_managed_pod_setup_guard
from services.chirify_live_gate import (
    EntitlementClaims,
    LiveGateBlockedError,
    evaluate_live_gate,
    sign_entitlement_token,
)
from subscribers import worm_audit_subscriber
from subscribers.worm_audit_subscriber import (
    GENESIS_PREV_HASH,
    WormAuditWriter,
    verify_worm_chain,
)
from utils import broker_keys, broker_login, broker_setup_guide, broker_switch, constants
from utils.plugin_loader import load_broker_auth_functions, load_broker_capabilities
from utils.session import end_session_if_signed_out

ROOT = Path(__file__).resolve().parents[2]


def _load_file_module(mod_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_schemas_mod = _load_file_module("oa_restx_schemas", ROOT / "restx_api" / "schemas.py")
_data_schemas_mod = _load_file_module(
    "oa_restx_data_schemas", ROOT / "restx_api" / "data_schemas.py"
)
OrderSchema = _schemas_mod.OrderSchema
SmartOrderSchema = _schemas_mod.SmartOrderSchema
DepthSchema = _data_schemas_mod.DepthSchema
ExpirySchema = _data_schemas_mod.ExpirySchema
HistorySchema = _data_schemas_mod.HistorySchema
QuotesSchema = _data_schemas_mod.QuotesSchema

ENTITLEMENT_SECRET = "chirify-entitlement-hmac-secret-2026-broker-ui-suite"
INTERNAL_OPS_TOKEN = "chirify-internal-ops-bearer-2026-killswitch"

UPSTREAM_39_BROKERS = [
    "fivepaisa",
    "fivepaisaxts",
    "aliceblue",
    "angel",
    "arrow",
    "compositedge",
    "dhan",
    "dhan_sandbox",
    "definedge",
    "deltaexchange",
    "firstock",
    "flattrade",
    "fyers",
    "groww",
    "hdfcsecurities",
    "hdfcsky",
    "ibulls",
    "iifl",
    "iiflcapital",
    "indmoney",
    "jainamxts",
    "kotak",
    "motilal",
    "mstock",
    "nubra",
    "nuvama",
    "paytm",
    "pocketful",
    "rmoney",
    "rupeezy",
    "sahi",
    "samco",
    "shoonya",
    "tradejini",
    "tradesmart",
    "upstox",
    "wisdom",
    "zebu",
    "zerodha",
]


@pytest.fixture(autouse=True)
def _isolated_environment_and_stores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate SQLite DBs, WORM log, .env resolver, and Chirify env vars per test."""
    db_file = tmp_path / "openalgo_test.db"
    worm_file = tmp_path / "worm_audit.jsonl"
    env_file = tmp_path / ".env"
    egress_file = tmp_path / "egress_verified.json"
    db_url = f"sqlite:///{db_file}"

    for var in broker_keys.ENV_VARS.values():
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("CHIRIFY_WORM_LOG_PATH", str(worm_file))
    monkeypatch.setenv("CHIRIFY_EGRESS_STATE_PATH", str(egress_file))
    monkeypatch.setenv("HOST_SERVER", "http://127.0.0.1:5000")

    for var in (
        "CHIRIFY_MANAGED_POD",
        "CHIRIFY_TENANT_ID",
        "CHIRIFY_SOURCE_REPO_URL",
        "CHIRIFY_INTERNAL_OPS_TOKEN",
        "CHIRIFY_ENTITLEMENT_SECRET",
        "CHIRIFY_ENTITLEMENT_TOKEN",
        "CHIRIFY_ENFORCE_LIVE_GATE",
        "CHIRIFY_EMERGENCY_KILL_SWITCH",
        "CHIRIFY_REQUIRE_STATIC_EGRESS",
        "EXPECTED_EGRESS_IPV4",
        "EXPECTED_SECONDARY_IPV4",
        "CHIRIFY_OPENROUTER_REGION",
        "OPENROUTER_REGION",
        "CHIRIFY_DATA_RESIDENCY",
        "CHIRIFY_WORM_AUDIT_ENABLED",
        "ZMQ_HOST",
        "CHIRIFY_IB_GATEWAY_READY",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setattr(broker_keys, "env_file_path", lambda: env_file)
    monkeypatch.setattr(
        broker_keys, "_STARTUP_VALUES", dict.fromkeys(broker_keys.ENV_VARS.values())
    )
    monkeypatch.setattr(broker_switch, "_blockers", lambda username: (0, 0, 0, 0))
    monkeypatch.setattr(analyzer_service, "_reconcile_sandbox", lambda *a, **kw: None)
    monkeypatch.setattr(analyzer_service.log_executor, "submit", lambda *a, **kw: None)

    restorers = []
    engines = []
    sessions = []

    for mod in (user_db, auth_db, broker_keys_db, settings_db, analyzer_db):
        orig_session = mod.db_session
        tmp_engine = create_engine(
            db_url,
            poolclass=NullPool,
            connect_args={"check_same_thread": False},
        )
        tmp_session = scoped_session(
            sessionmaker(autocommit=False, autoflush=False, bind=tmp_engine)
        )
        monkeypatch.setattr(mod, "engine", tmp_engine)
        monkeypatch.setattr(mod, "db_session", tmp_session)
        mod.Base.query = tmp_session.query_property()
        mod.Base.metadata.create_all(tmp_engine)
        engines.append(tmp_engine)
        sessions.append(tmp_session)
        restorers.append((mod, orig_session))

    fresh_worm = WormAuditWriter(worm_file, fsync=False)
    monkeypatch.setattr(worm_audit_subscriber, "_default_writer", fresh_worm)

    auth_db._session_revocation_cache.invalidate()
    auth_db.auth_cache.clear()
    user_db.username_cache.clear()
    settings_db.clear_settings_cache()
    broker_keys.forget_logged_in_broker()
    broker_login.clear_pending_logins()
    broker_keys.broker_type.cache_clear()
    broker_keys.broker_exchanges.cache_clear()

    yield {
        "db_file": db_file,
        "worm_file": worm_file,
        "env_file": env_file,
        "egress_file": egress_file,
    }

    for sess in sessions:
        sess.remove()
    for eng in engines:
        eng.dispose()
    for mod, orig_session in restorers:
        mod.Base.query = orig_session.query_property()

    auth_db._session_revocation_cache.invalidate()
    auth_db.auth_cache.clear()
    user_db.username_cache.clear()
    settings_db.clear_settings_cache()
    broker_keys.forget_logged_in_broker()
    broker_login.clear_pending_logins()


def _build_app(*, csrf_enabled: bool = True) -> Flask:
    app = Flask(__name__, root_path=str(ROOT))
    app.secret_key = "test-secret-key-" + ("a" * 48)
    app.config["WTF_CSRF_ENABLED"] = csrf_enabled

    install_managed_pod_setup_guard(app)
    csrf = CSRFProtect(app)
    app.csrf = csrf

    app.register_blueprint(auth_bp)
    app.register_blueprint(brlogin_bp)
    app.register_blueprint(broker_credentials_bp)
    app.register_blueprint(broker_config_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(internal_ops_bp)
    app.register_blueprint(chirify_sso_bp)
    app.register_blueprint(chirify_status_bp)
    app.register_blueprint(chirify_probes_bp)

    csrf.exempt(internal_ops_bp)
    csrf.exempt(chirify_sso_bp)
    csrf.exempt(chirify_status_bp)
    csrf.exempt(chirify_probes_bp)
    with app.app_context():
        csrf.exempt(app.view_functions["brlogin.broker_callback"])
        app.broker_auth_functions = load_broker_auth_functions()
        load_broker_capabilities()

    @app.before_request
    def _drop_ended_sessions():
        end_session_if_signed_out()

    app.add_url_rule("/dashboard", "dashboard_bp.dashboard", lambda: "dashboard")
    return app


def _signed_in_client(app: Flask, username: str = "trader", **extra):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = username
        sess["auth_at"] = datetime.now(UTC).isoformat()
        sess.update(extra)
    return client


def _qualified_claims(**overrides) -> EntitlementClaims:
    now = int(time.time())
    payload = {
        "tenant_id": "ten_comp_01",
        "user_id": "usr_comp_01",
        "cohort": "india_pro_pod",
        "broker_name": "zerodha",
        "broker_type": "IN_stock",
        "hosted_cloud": True,
        "sandbox_qualified": True,
        "simulated_trades": 10,
        "unhandled_rms_breaches": 0,
        "max_daily_loss": 5000.0,
        "max_order_notional": 250000.0,
        "static_ip_verified": True,
        "exchange_algo_id": "NSE-ALGO-2026-4411",
        "personal_family_under_10ops_attested": False,
        "issued_at": now,
        "expires_at": now + 3600,
    }
    payload.update(overrides)
    return EntitlementClaims.from_mapping(payload)


# =============================================================================
# 1. Native Broker Discovery, Exchange Schemas & Setup UI (`alpaca`, `ibkr`, `ccxt`)
# =============================================================================


def test_sample_env_and_constants_expose_global_brokers_and_exchanges_without_regression():
    sample = dotenv_values(ROOT / ".sample.env")
    valid_brokers = [b.strip() for b in sample["VALID_BROKERS"].split(",") if b.strip()]

    # All 39 upstream brokers remain intact in exact order, with alpaca, ibkr, ccxt appended
    assert valid_brokers[:39] == UPSTREAM_39_BROKERS
    assert valid_brokers[39:] == ["alpaca", "ibkr", "ccxt"]
    assert len(valid_brokers) == 42

    expected_new_exchanges = {
        "US_EQUITY",
        "US_OPTIONS",
        "EU_EQUITY",
        "FUTURES",
        "FOREX",
        "CRYPTO_SWAP",
        "CRYPTO_OPTIONS",
    }
    assert expected_new_exchanges <= set(constants.VALID_EXCHANGES)
    assert {"NSE", "BSE", "NFO", "BFO", "MCX", "CDS", "CRYPTO"} <= set(constants.VALID_EXCHANGES)
    assert expected_new_exchanges <= set(constants.EXCHANGE_BADGE_COLORS)

    # OrderSchema & SmartOrderSchema accept all new global exchanges
    for exch in expected_new_exchanges:
        loaded = OrderSchema().load(
            {
                "apikey": "test-api-key",
                "strategy": "global_alpha",
                "exchange": exch,
                "symbol": "AAPL" if exch == "US_EQUITY" else "BTCUSDT",
                "action": "BUY",
                "quantity": 1,
            }
        )
        assert loaded["exchange"] == exch
        assert SmartOrderSchema().load(
            {
                "apikey": "test-api-key",
                "strategy": "global_alpha",
                "exchange": exch,
                "symbol": "AAPL",
                "action": "BUY",
                "quantity": 1,
                "position_size": 1,
            }
        )["exchange"] == exch

    # Fractional crypto quantities remain permitted on CRYPTO_SWAP / CRYPTO_OPTIONS,
    # while non-crypto venues (NSE, US_EQUITY) continue enforcing integer quantities
    frac_swap = OrderSchema().load(
        {
            "apikey": "test-api-key",
            "strategy": "perp_arb",
            "exchange": "CRYPTO_SWAP",
            "symbol": "BTCUSDT",
            "action": "BUY",
            "quantity": 0.25,
        }
    )
    assert frac_swap["quantity"] == 0.25

    with pytest.raises(ValidationError):
        OrderSchema().load(
            {
                "apikey": "test-api-key",
                "strategy": "india_eq",
                "exchange": "NSE",
                "symbol": "RELIANCE",
                "action": "BUY",
                "quantity": 1.5,
            }
        )

    # Data schemas accept the new exchanges
    for exch in expected_new_exchanges:
        assert QuotesSchema().load(
            {"apikey": "k", "symbol": "SPY", "exchange": exch}
        )["exchange"] == exch
        assert DepthSchema().load(
            {"apikey": "k", "symbol": "SPY", "exchange": exch}
        )["exchange"] == exch
        assert HistorySchema().load(
            {
                "apikey": "k",
                "symbol": "SPY",
                "exchange": exch,
                "interval": "1h",
                "start_date": "2026-01-01",
                "end_date": "2026-01-02",
            }
        )["exchange"] == exch

    for deriv_exch in ("US_OPTIONS", "FUTURES", "CRYPTO_SWAP", "CRYPTO_OPTIONS"):
        assert ExpirySchema().load(
            {
                "apikey": "k",
                "symbol": "BTC",
                "exchange": deriv_exch,
                "instrumenttype": "options",
            }
        )["exchange"] == deriv_exch


def test_broker_list_api_and_setup_ui_expose_alpaca_ibkr_ccxt_and_preserve_all_39_brokers(
    monkeypatch: pytest.MonkeyPatch,
):
    sample = dotenv_values(ROOT / ".sample.env")
    monkeypatch.setenv("VALID_BROKERS", sample["VALID_BROKERS"])

    enabled = broker_keys.enabled_brokers()
    assert len(enabled) == 42
    assert set(UPSTREAM_39_BROKERS) <= set(enabled)
    assert {"alpaca", "ibkr", "ccxt"} <= set(enabled)

    # Verify broker_keys helpers & setup guides directly
    assert broker_keys.broker_type("alpaca") == "US_multi"
    assert broker_keys.broker_type("ibkr") == "GLOBAL_multi"
    assert broker_keys.broker_type("ccxt") == "crypto"

    alpaca_guide = broker_setup_guide.guide("alpaca")
    assert alpaca_guide["name"] == "Alpaca Markets — US Equities, Options & Crypto"
    assert alpaca_guide["sign_in"] == "saved_keys"
    assert "200 req/min" in alpaca_guide["banner"]
    assert "PK*" in alpaca_guide["banner"] and "AK*" in alpaca_guide["banner"]

    ibkr_guide = broker_setup_guide.guide("ibkr")
    assert ibkr_guide["name"] == "Interactive Brokers — Global Multi-Asset"
    assert ibkr_guide["sign_in"] == "saved_keys"
    assert "127.0.0.1:4002" in ibkr_guide["banner"]
    assert "OAuth 2.0" in ibkr_guide["banner"]

    ccxt_guide = broker_setup_guide.guide("ccxt")
    assert ccxt_guide["name"] == "CCXT Unified Crypto — 103+ Spot, Perp & Options Venues"
    assert ccxt_guide["sign_in"] == "saved_keys"
    assert "103+" in ccxt_guide["banner"]
    assert [f["key"] for f in ccxt_guide["fields"]] == [
        "api_key",
        "api_secret",
        "api_key_market",
        "api_secret_market",
    ]

    # Exercise GET /api/broker/list and PUT /api/broker/credentials/<broker>
    app = _build_app(csrf_enabled=False)
    client = _signed_in_client(app)

    list_resp = client.get("/api/broker/list", headers={"Accept": "application/json"})
    assert list_resp.status_code == 200
    payload = list_resp.get_json()
    assert payload["status"] == "success"
    brokers_by_id = {b["id"]: b for b in payload["data"]["brokers"]}
    assert len(brokers_by_id) == 42
    assert set(UPSTREAM_39_BROKERS) <= set(brokers_by_id)

    assert brokers_by_id["alpaca"]["exchanges"] == ["US_EQUITY", "US_OPTIONS", "CRYPTO"]
    assert brokers_by_id["ibkr"]["exchanges"] == [
        "US_EQUITY",
        "US_OPTIONS",
        "EU_EQUITY",
        "FUTURES",
        "FOREX",
    ]
    assert brokers_by_id["ccxt"]["exchanges"] == ["CRYPTO", "CRYPTO_SWAP", "CRYPTO_OPTIONS"]
    for new_b in ("alpaca", "ibkr", "ccxt"):
        assert brokers_by_id[new_b]["sign_in"] == "saved_keys"
        assert brokers_by_id[new_b]["redirect_url"] is None

    # Save keys for alpaca, ibkr, and ccxt via PUT /api/broker/credentials/<broker>
    r_save_alpaca = client.put(
        "/api/broker/credentials/alpaca",
        json={"api_key": "PKTESTKEY123456", "api_secret": "alpaca-super-secret-value"},
    )
    assert r_save_alpaca.status_code == 200

    r_save_ibkr = client.put(
        "/api/broker/credentials/ibkr",
        json={
            "api_key": "IBKROAUTHTOKEN999",
            "api_secret": "ibkr-oauth-secret",
            "api_key_market": "127.0.0.1:4002",
        },
    )
    assert r_save_ibkr.status_code == 200

    r_save_ccxt = client.put(
        "/api/broker/credentials/ccxt",
        json={
            "api_key": "CCXTKEYABCDEF123",
            "api_secret": "ccxt-secret-xyz",
            "api_key_market": "okx:testnet",
            "api_secret_market": "okx-passphrase-secret",
        },
    )
    assert r_save_ccxt.status_code == 200

    # Verify GET /api/broker/list masks all saved values and leaks zero plaintext secrets
    after_resp = client.get("/api/broker/list", headers={"Accept": "application/json"})
    raw_text = after_resp.get_data(as_text=True)
    for secret_str in (
        "PKTESTKEY123456",
        "alpaca-super-secret-value",
        "IBKROAUTHTOKEN999",
        "ibkr-oauth-secret",
        "CCXTKEYABCDEF123",
        "ccxt-secret-xyz",
        "okx-passphrase-secret",
    ):
        assert secret_str not in raw_text

    after_brokers = {b["id"]: b for b in after_resp.get_json()["data"]["brokers"]}
    for new_b in ("alpaca", "ibkr", "ccxt"):
        assert after_brokers[new_b]["configured"] is True
        assert after_brokers[new_b]["source"] == "saved"

    ccxt_saved_fields = {f["key"]: f["saved"] for f in after_brokers["ccxt"]["fields"]}
    assert ccxt_saved_fields == {
        "api_key": "CCXTKE********",
        "api_secret": "********",
        "api_key_market": "okx:te********",
        "api_secret_market": "********",
    }

    # Verify POST /auth/broker/login starts a saved_keys callback flow for all three
    for new_b in ("alpaca", "ibkr", "ccxt"):
        start_resp = client.post("/auth/broker/login", json={"broker": new_b})
        assert start_resp.status_code == 200
        assert start_resp.get_json()["url"] == f"/{new_b}/callback"


# =============================================================================
# 2. AGPL-3.0 Section 13 Attribution, EU AI Act Art. 50 & Pod Telemetry
# =============================================================================


def test_chirify_status_public_before_login_and_detailed_when_authenticated(
    _isolated_environment_and_stores: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    worm_file = _isolated_environment_and_stores["worm_file"]
    egress_file = _isolated_environment_and_stores["egress_file"]

    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_eu_quant_07")
    monkeypatch.setenv("CHIRIFY_OPENROUTER_REGION", "EU")
    monkeypatch.setenv("CHIRIFY_REQUIRE_STATIC_EGRESS", "true")
    monkeypatch.setenv("EXPECTED_EGRESS_IPV4", "185.199.108.42")
    monkeypatch.setenv("CHIRIFY_INTERNAL_OPS_TOKEN", INTERNAL_OPS_TOKEN)
    settings_db.set_analyze_mode(True)

    egress_file.write_text(
        json.dumps({"observed_ip": "185.199.108.42", "verified_at_epoch": time.time()}),
        encoding="utf-8",
    )

    rec = worm_audit_subscriber.emit_worm_audit_event(
        "chirify_pod_bootstrapped", {"tenant_id": "ten_eu_quant_07"}
    )

    app = _build_app(csrf_enabled=True)
    anon_client = app.test_client()

    # 1. Publicly readable BEFORE login (AGPL-3.0 Section 13 + EU AI Act Art. 50)
    pub_resp = anon_client.get("/api/v1/chirify/status")
    assert pub_resp.status_code == 200
    assert pub_resp.headers.get("Cache-Control") == "no-store"
    pub = pub_resp.get_json()

    assert pub["license"] == "AGPL-3.0"
    assert pub["source_code_url"] == DEFAULT_CHIRIFY_SOURCE_REPO_URL
    assert pub["upstream_url"] == UPSTREAM_OPENALGO_URL
    assert pub["managed_pod"] is True
    assert pub["ai_disclosure"] == EU_AI_ACT_ART50_DISCLOSURE
    assert pub["analyze_mode"] is True
    assert pub["kill_switch_engaged"] is False
    assert pub["static_egress_verified"] is True
    assert pub["openrouter_region"] == "EU"
    assert pub["worm_audit"] == {
        "enabled": True,
        "records_count": 1,
        "head_hash": rec.record_hash,
        "valid": True,
    }
    assert pub["live_gate"]["enforced"] is True
    assert pub["live_gate"]["allowed"] is False
    assert pub["authenticated"] is False
    assert "telemetry" not in pub

    # Custom CHIRIFY_SOURCE_REPO_URL override is honored
    custom_repo = "https://github.com/acme-fork/chirify-openalgo-custom"
    monkeypatch.setenv("CHIRIFY_SOURCE_REPO_URL", custom_repo)
    assert anon_client.get("/api/v1/chirify/status").get_json()["source_code_url"] == custom_repo

    # 2. Signed-in OpenAlgo session receives detailed pod telemetry
    signed_client = _signed_in_client(app, username="eu_trader", broker="ibkr", logged_in=True)
    auth_resp = signed_client.get("/api/v1/chirify/status")
    assert auth_resp.status_code == 200
    auth_body = auth_resp.get_json()
    assert auth_body["authenticated"] is True
    assert auth_body["telemetry"] == {
        "tenant_id": "ten_eu_quant_07",
        "active_broker": "ibkr",
        "egress": {
            "require_static_egress": True,
            "state_file_present": True,
            "verified": True,
        },
    }
    assert INTERNAL_OPS_TOKEN not in auth_resp.get_data(as_text=True)

    # 3. Internal Control Plane bearer token over cluster IP also unlocks telemetry
    ops_resp = anon_client.get(
        "/api/v1/chirify/status",
        headers={"Authorization": f"Bearer {INTERNAL_OPS_TOKEN}"},
        environ_base={"REMOTE_ADDR": "10.244.1.9"},
    )
    assert ops_resp.status_code == 200
    assert ops_resp.get_json()["authenticated"] is True
    assert ops_resp.get_json()["telemetry"]["tenant_id"] == "ten_eu_quant_07"

    # Verify app.py wires chirify_status_bp and exempts CSRF
    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "chirify_status_bp" in app_source
    assert "csrf.exempt(chirify_status_bp)" in app_source


# =============================================================================
# 3. DORA Article 30 / SEBI Emergency Unconditional Kill-Switch
# =============================================================================


def test_emergency_kill_switch_forces_sandbox_blocks_live_and_agent_orders_and_restores_cleanly(
    _isolated_environment_and_stores: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    worm_file = _isolated_environment_and_stores["worm_file"]

    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_comp_01")
    monkeypatch.setenv("CHIRIFY_ENFORCE_LIVE_GATE", "true")
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_SECRET", ENTITLEMENT_SECRET)
    monkeypatch.setenv("CHIRIFY_INTERNAL_OPS_TOKEN", INTERNAL_OPS_TOKEN)

    qualified_claims = _qualified_claims()
    qualified_token = sign_entitlement_token(qualified_claims, ENTITLEMENT_SECRET)
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_TOKEN", qualified_token)

    # Start in validly unlocked Live Mode (analyze_mode=False) with passing Gate 3 guard
    assert analyzer_service.apply_analyze_mode(False, broker="zerodha") is False
    assert settings_db.get_analyze_mode() is False

    guard = PromptBlindOrderGuard()
    pre_order = guard.validate_order(
        symbol="RELIANCE",
        exchange="NSE",
        action="BUY",
        quantity=5,
        product="CNC",
        ltp=Decimal("2500"),
    )
    assert pre_order.allowed is True

    app = _build_app(csrf_enabled=True)
    client = app.test_client()
    ops_headers = {"Authorization": f"Bearer {INTERNAL_OPS_TOKEN}"}
    cluster_env = {"REMOTE_ADDR": "10.244.3.20"}

    # Auth guard checks on POST /internal/v1/compliance/kill-switch
    assert (
        client.post(
            "/internal/v1/compliance/kill-switch",
            json={"engaged": True, "reason": "public_probe"},
            headers=ops_headers,
            environ_base={"REMOTE_ADDR": "8.8.8.8"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/internal/v1/compliance/kill-switch",
            json={"engaged": True, "reason": "missing_token"},
            environ_base=cluster_env,
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/internal/v1/compliance/kill-switch",
            json={"engaged": True, "reason": "bad_token"},
            headers={"Authorization": "Bearer wrong-token"},
            environ_base=cluster_env,
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/internal/v1/compliance/kill-switch",
            json={"reason": "missing_engaged_field"},
            headers=ops_headers,
            environ_base=cluster_env,
        ).status_code
        == 400
    )

    # Engage DORA / SEBI Emergency Kill-Switch
    engage_resp = client.post(
        "/internal/v1/compliance/kill-switch",
        json={"engaged": True, "reason": "dora_art30_ runaway_algo_halt"},
        headers=ops_headers,
        environ_base=cluster_env,
    )
    assert engage_resp.status_code == 200
    engage_body = engage_resp.get_json()
    assert engage_body["status"] == "ok"
    assert engage_body["engaged"] is True
    assert engage_body["kill_switch_engaged"] is True
    assert engage_body["analyze_mode"] is True
    assert os.environ["CHIRIFY_EMERGENCY_KILL_SWITCH"] == "true"

    # 1. OpenAlgo was immediately flipped back to Analyzer Sandbox Mode
    assert settings_db.get_analyze_mode() is True

    # 2. evaluate_live_gate, apply_analyze_mode(False), and toggle_analyzer_mode_with_auth are blocked (403)
    gate_while_engaged = evaluate_live_gate(qualified_claims)
    assert gate_while_engaged.allowed is False
    assert gate_while_engaged.code == "emergency_kill_switch_engaged"

    with pytest.raises(LiveGateBlockedError) as exc_info:
        analyzer_service.apply_analyze_mode(False, broker="zerodha")
    assert exc_info.value.status_code == 403
    assert exc_info.value.verdict.code == "emergency_kill_switch_engaged"
    assert settings_db.get_analyze_mode() is True

    ok_toggle, resp_toggle, status_toggle = analyzer_service.toggle_analyzer_mode_with_auth(
        {"mode": False}, "broker-tok", "zerodha", {"mode": False}
    )
    assert ok_toggle is False
    assert status_toggle == 403
    assert resp_toggle["code"] == "emergency_kill_switch_engaged"

    # 3. PromptBlindOrderGuard immediately blocks all agent orders while engaged
    blocked_order = guard.validate_order(
        symbol="TCS",
        exchange="NSE",
        action="BUY",
        quantity=1,
        product="CNC",
        ltp=Decimal("3500"),
    )
    assert blocked_order.allowed is False
    assert blocked_order.code == "kill_switch_engaged"

    # 4. Public /api/v1/chirify/status reflects engaged kill switch, Sandbox mode, and WORM head hash
    status_engaged = client.get("/api/v1/chirify/status").get_json()
    assert status_engaged["kill_switch_engaged"] is True
    assert status_engaged["analyze_mode"] is True
    assert status_engaged["live_gate"]["allowed"] is False
    assert status_engaged["live_gate"]["code"] == "emergency_kill_switch_engaged"
    assert status_engaged["worm_audit"]["records_count"] == 1
    assert status_engaged["worm_audit"]["head_hash"] != GENESIS_PREV_HASH
    assert status_engaged["worm_audit"]["head_hash"] == engage_body["worm_audit"]["record_hash"]

    # 5. Disengage Emergency Kill-Switch (`engaged=False`) -> restores normal gate evaluation
    clear_resp = client.post(
        "/internal/v1/compliance/kill-switch",
        json={"engaged": False, "reason": "dora_incident_cleared_by_compliance"},
        headers=ops_headers,
        environ_base=cluster_env,
    )
    assert clear_resp.status_code == 200
    clear_body = clear_resp.get_json()
    assert clear_body["engaged"] is False
    assert clear_body["kill_switch_engaged"] is False
    assert clear_body["analyze_mode"] is True  # Remains safely in Sandbox until explicitly switched
    assert os.environ["CHIRIFY_EMERGENCY_KILL_SWITCH"] == "false"

    # Normal gate evaluation & PromptBlindOrderGuard restored cleanly!
    restored_gate = evaluate_live_gate(qualified_claims)
    assert restored_gate.allowed is True
    assert restored_gate.code == "ok"

    restored_order = guard.validate_order(
        symbol="INFY",
        exchange="NSE",
        action="BUY",
        quantity=2,
        product="CNC",
        ltp=Decimal("1600"),
    )
    assert restored_order.allowed is True

    assert analyzer_service.apply_analyze_mode(False, broker="zerodha") is False
    assert settings_db.get_analyze_mode() is False

    # 6. Verify SHA-256 WORM chain integrity across both toggle events
    chain = verify_worm_chain(worm_file)
    assert chain.valid is True
    assert chain.records_checked == 2
    assert chain.head_hash == clear_body["worm_audit"]["record_hash"]

    lines = [json.loads(line) for line in worm_file.read_text(encoding="utf-8").splitlines() if line]
    assert [r["event_type"] for r in lines] == [
        "chirify_emergency_kill_switch_toggled",
        "chirify_emergency_kill_switch_toggled",
    ]
    assert lines[0]["payload"]["engaged"] is True
    assert lines[0]["payload"]["reason"] == "dora_art30_ runaway_algo_halt"
    assert lines[0]["payload"]["timestamp_utc"].endswith("Z")
    assert lines[1]["payload"]["engaged"] is False
    assert lines[1]["payload"]["reason"] == "dora_incident_cleared_by_compliance"


def test_ccxt_auth_reads_ui_saved_exchange_id_testnet_and_passphrase_fields(
    monkeypatch: pytest.MonkeyPatch,
):
    from broker.ccxt.api.auth_api import authenticate_broker as ccxt_authenticate
    from broker.ccxt.api.precision_and_nonce import ApiKeyNonceLockRegistry

    class _DummyVenue:
        def __init__(self):
            self.sandbox_enabled = False
            self.balance_checked = False
            self.urls = {"test": "https://testnet.okx.example"}

        def set_sandbox_mode(self, enabled: bool):
            self.sandbox_enabled = enabled

        def fetch_balance(self):
            self.balance_checked = True
            return {"USDT": {"free": 1000}}

    monkeypatch.setenv("BROKER_API_KEY", "OKXKEY999")
    monkeypatch.setenv("BROKER_API_SECRET", "OKXSECRET999")
    monkeypatch.setenv("BROKER_API_KEY_MARKET", "okx:testnet")
    monkeypatch.setenv("BROKER_API_SECRET_MARKET", "okx-pass-123")

    venue = _DummyVenue()
    registry = ApiKeyNonceLockRegistry()
    token, err = ccxt_authenticate(exchange_instance=venue, nonce_registry=registry)
    assert err is None
    assert token == "okx:OKXKEY999"
    assert venue.sandbox_enabled is True
    assert venue.balance_checked is True


def test_settings_analyze_mode_http_route_returns_403_when_kill_switch_engaged(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CHIRIFY_EMERGENCY_KILL_SWITCH", "true")
    monkeypatch.setenv("DISABLE_SESSION_EXPIRY", "true")
    monkeypatch.setenv("VALID_BROKERS", "zerodha")
    settings_db.set_analyze_mode(True)
    broker_keys_db.save_broker_keys(
        "zerodha", {"api_key": "zkey123", "api_secret": "zsec123"}, None
    )

    auth_db.db_session.add(
        auth_db.Auth(
            name="trader",
            auth=auth_db.encrypt_token("tok-123"),
            broker="zerodha",
            is_revoked=False,
        )
    )
    auth_db.db_session.commit()

    app = _build_app(csrf_enabled=False)
    client = _signed_in_client(
        app,
        username="trader",
        broker="zerodha",
        logged_in=True,
        login_time=datetime.now(UTC).isoformat(),
    )

    r_live = client.post("/settings/analyze-mode/0")
    assert r_live.status_code == 403
    assert r_live.get_json()["code"] == "emergency_kill_switch_engaged"
    assert settings_db.get_analyze_mode() is True


# =============================================================================
# 4. Unauthenticated Kubernetes Probes (`/healthz`, `/readyz`) & Prometheus `/metrics`
# =============================================================================


def test_k8s_healthz_readyz_and_prometheus_metrics_probes(
    _isolated_environment_and_stores: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    egress_file = _isolated_environment_and_stores["egress_file"]
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("ZMQ_HOST", "127.0.0.1")
    settings_db.set_analyze_mode(True)

    app = _build_app(csrf_enabled=True)
    db_event = threading.Event()
    app.db_ready = db_event
    anon = app.test_client()

    # 1. GET /healthz always returns 200 OK unauthenticated even before DB init completes
    hz = anon.get("/healthz")
    assert hz.status_code == 200
    assert hz.headers.get("Cache-Control") == "no-store"
    assert hz.get_json() == {
        "status": "ok",
        "service": "chirify-openalgo",
        "tz": "UTC",
    }

    # 2. GET /readyz returns 503 while app.db_ready is unset
    rz_booting = anon.get("/readyz")
    assert rz_booting.status_code == 503
    rz_boot_body = rz_booting.get_json()
    assert rz_boot_body["status"] == "not_ready"
    assert rz_boot_body["db_ready"] is False
    assert "db_not_ready" in rz_boot_body["reasons"]

    # Once DB finishes initializing, GET /readyz returns 200 OK with mode & kill-switch state
    db_event.set()
    rz_ok = anon.get("/readyz")
    assert rz_ok.status_code == 200
    assert rz_ok.headers.get("Cache-Control") == "no-store"
    rz_ok_body = rz_ok.get_json()
    assert rz_ok_body["status"] == "ready"
    assert rz_ok_body["db_ready"] is True
    assert rz_ok_body["zmq_host"] == "127.0.0.1"
    assert rz_ok_body["analyze_mode"] is True
    assert rz_ok_body["kill_switch_engaged"] is False

    # Non-loopback ZMQ_HOST causes /readyz to fail closed with 503
    monkeypatch.setenv("ZMQ_HOST", "0.0.0.0")
    rz_bad_zmq = anon.get("/readyz")
    assert rz_bad_zmq.status_code == 503
    assert "invalid_zmq_host:0.0.0.0" in rz_bad_zmq.get_json()["reasons"]
    monkeypatch.setenv("ZMQ_HOST", "127.0.0.1")

    # Static egress mismatch causes /readyz -> 503 and egress mismatch gauge -> 1
    monkeypatch.setenv("CHIRIFY_REQUIRE_STATIC_EGRESS", "true")
    monkeypatch.setenv("EXPECTED_EGRESS_IPV4", "52.66.10.11")
    egress_file.write_text(
        json.dumps({"observed_ip": "198.51.100.99", "verified_at_epoch": time.time()}),
        encoding="utf-8",
    )
    rz_bad_egress = anon.get("/readyz")
    assert rz_bad_egress.status_code == 503
    assert "static_egress_unverified" in rz_bad_egress.get_json()["reasons"]

    m_drift = anon.get("/metrics")
    assert m_drift.status_code == 200
    assert "chirify_tenant_static_egress_ip_mismatch_total 1" in m_drift.get_data(as_text=True)

    # Restore valid static egress IP, emit 2 WORM events, engage kill-switch, simulate IB stall
    egress_file.write_text(
        json.dumps({"observed_ip": "52.66.10.11", "verified_at_epoch": time.time()}),
        encoding="utf-8",
    )
    assert anon.get("/readyz").status_code == 200

    worm_audit_subscriber.emit_worm_audit_event("order_placed", {"symbol": "RELIANCE"})
    worm_audit_subscriber.emit_worm_audit_event("order_filled", {"symbol": "RELIANCE"})
    monkeypatch.setenv("CHIRIFY_EMERGENCY_KILL_SWITCH", "true")
    monkeypatch.setenv("CHIRIFY_IB_GATEWAY_READY", "false")

    # 3. GET /metrics exports Prometheus 0.0.4 exposition matching prometheus-slo-rules.yaml
    m_resp = anon.get("/metrics")
    assert m_resp.status_code == 200
    assert m_resp.headers["Content-Type"].startswith(
        "text/plain; version=0.0.4; charset=utf-8"
    )
    assert m_resp.headers.get("Cache-Control") == "no-store"
    metrics_text = m_resp.get_data(as_text=True)
    assert "chirify_pod_analyze_mode 1" in metrics_text
    assert "chirify_pod_kill_switch_engaged 1" in metrics_text
    assert "chirify_eventbus_worm_events_published_total 2" in metrics_text
    assert "chirify_tenant_static_egress_ip_mismatch_total 0" in metrics_text
    assert "chirify_ib_gateway_api_readiness_probe_success 0" in metrics_text

    # 4. Verify app.py wires chirify_probes_bp, CSRF exemption & pre-login bypasses
    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "chirify_probes_bp" in app_source
    assert "csrf.exempt(chirify_probes_bp)" in app_source
    assert '"/healthz"' in app_source
    assert '"/readyz"' in app_source
    assert '"/metrics"' in app_source


