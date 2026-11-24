"""PRR Tests: Headless Pod Bootstrap, Single-Use 60s SSO Ticket & Dynamic Entitlement Sync."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from flask import Flask, jsonify, session
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import NullPool

from blueprints import chirify_sso
from blueprints.auth import auth_bp
from blueprints.chirify_sso import (
    SSOTicketReplayError,
    chirify_sso_bp,
    mint_sso_ticket,
    reset_consumed_jtis,
    verify_and_consume_sso_ticket,
)
from blueprints.core import core_bp
from blueprints.internal_ops import internal_ops_bp
from blueprints.react_app import react_bp
from database import analyzer_db, auth_db, settings_db, user_db
from services import analyzer_service
from services.chirify_bootstrap_service import (
    ManagedPodBootstrapError,
    bootstrap_managed_tenant,
    install_managed_pod_setup_guard,
    is_managed_pod,
)
from services.chirify_live_gate import (
    EntitlementClaims,
    LiveGateBlockedError,
    sign_entitlement_token,
)
from subscribers import worm_audit_subscriber
from subscribers.worm_audit_subscriber import WormAuditWriter, verify_worm_chain
from utils.url_redaction import redact_url_credentials

ROOT = Path(__file__).resolve().parents[2]
SSO_SECRET = "chirify-sso-hmac-secret-2026-production-grade-key"
ENTITLEMENT_SECRET = "chirify-entitlement-hmac-secret-2026-production-key"
INTERNAL_OPS_TOKEN = "chirify-internal-ops-bearer-2026"


@pytest.fixture(autouse=True)
def _isolated_pod_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Bind user_db, auth_db, settings_db, analyzer_db, and WORM writer to isolated tmp_path files."""
    db_file = tmp_path / "pod_isolated.db"
    worm_file = tmp_path / "worm_audit.jsonl"
    db_url = f"sqlite:///{db_file}"

    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("CHIRIFY_WORM_LOG_PATH", str(worm_file))
    monkeypatch.delenv("CHIRIFY_MANAGED_POD", raising=False)
    monkeypatch.delenv("CHIRIFY_TENANT_ID", raising=False)
    monkeypatch.delenv("CHIRIFY_TENANT_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("CHIRIFY_TENANT_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("CHIRIFY_TENANT_BOOTSTRAP_PASSWORD", raising=False)
    monkeypatch.delenv("CHIRIFY_SSO_SECRET", raising=False)
    monkeypatch.delenv("CHIRIFY_ENTITLEMENT_SECRET", raising=False)
    monkeypatch.delenv("CHIRIFY_ENTITLEMENT_TOKEN", raising=False)
    monkeypatch.delenv("CHIRIFY_ENFORCE_LIVE_GATE", raising=False)

    restorers = []
    engines = []
    sessions = []

    for mod in (user_db, auth_db, settings_db, analyzer_db):
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
        engines.append(tmp_engine)
        sessions.append(tmp_session)
        restorers.append((mod, orig_session))

    fresh_worm_writer = WormAuditWriter(worm_file, fsync=False)
    monkeypatch.setattr(worm_audit_subscriber, "_default_writer", fresh_worm_writer)

    user_db.username_cache.clear()
    settings_db.clear_settings_cache()
    auth_db.invalidate_user_cache("test-reset")
    reset_consumed_jtis()

    yield {"db_file": db_file, "worm_file": worm_file}

    for sess in sessions:
        sess.remove()
    for eng in engines:
        eng.dispose()
    for mod, orig_session in restorers:
        mod.Base.query = orig_session.query_property()

    user_db.username_cache.clear()
    settings_db.clear_settings_cache()
    reset_consumed_jtis()


def _build_test_app() -> Flask:
    """Construct a CSRF-protected Flask test app matching app.py's Chirify middleware & blueprints."""
    app = Flask(__name__)
    app.secret_key = "test-app-secret-key-" + ("x" * 40)
    app.config["WTF_CSRF_ENABLED"] = True

    install_managed_pod_setup_guard(app)
    csrf = CSRFProtect(app)
    app.csrf = csrf

    app.register_blueprint(react_bp)
    app.register_blueprint(core_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chirify_sso_bp)
    app.register_blueprint(internal_ops_bp)

    csrf.exempt(chirify_sso_bp)
    csrf.exempt(internal_ops_bp)

    @app.route("/_test/whoami", methods=["GET"])
    def _whoami():
        return jsonify(
            {
                "user": session.get("user"),
                "auth_at": session.get("auth_at"),
                "pending_totp_user": session.get("pending_totp_user"),
                "logged_in": bool(session.get("logged_in")),
                "broker": session.get("broker"),
            }
        )

    return app


def _qualified_claims(tenant_id: str = "ten_live_01", **overrides) -> dict:
    now = int(time.time())
    payload = {
        "tenant_id": tenant_id,
        "user_id": "usr_live_01",
        "cohort": "india_pro_pod",
        "broker_name": "zerodha",
        "broker_type": "IN_stock",
        "hosted_cloud": True,
        "sandbox_qualified": True,
        "simulated_trades": 8,
        "unhandled_rms_breaches": 0,
        "max_daily_loss": 5000.0,
        "max_order_notional": 150000.0,
        "static_ip_verified": True,
        "exchange_algo_id": "NSE-ALGO-2026-7777",
        "personal_family_under_10ops_attested": False,
        "issued_at": now,
        "expires_at": now + 3600,
        "jti": "ent-jti-2026-0001",
    }
    payload.update(overrides)
    return payload


def test_headless_bootstrap_creates_admin_locks_sandbox_idempotent_and_blocks_setup(
    _isolated_pod_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    worm_file = _isolated_pod_state["worm_file"]
    app = _build_test_app()
    client = app.test_client()

    # 1. Standalone OSS mode (CHIRIFY_MANAGED_POD unset/false) is untouched
    assert is_managed_pod() is False
    standalone_res = bootstrap_managed_tenant()
    assert standalone_res == {"bootstrapped": False, "reason": "standalone_mode"}

    user_db.init_db()
    r_check_standalone = client.get("/auth/check-setup")
    assert r_check_standalone.status_code == 200
    assert r_check_standalone.get_json()["needs_setup"] is True

    # GET /setup is NOT 403 in standalone mode
    r_setup_standalone = client.get("/setup")
    assert r_setup_standalone.status_code != 403

    # 2. Managed pod requires CHIRIFY_TENANT_ID and CHIRIFY_TENANT_ADMIN_EMAIL
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    assert is_managed_pod() is True
    with pytest.raises(ManagedPodBootstrapError, match="CHIRIFY_TENANT_ID"):
        bootstrap_managed_tenant()

    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_alpha_01")
    with pytest.raises(ManagedPodBootstrapError, match="CHIRIFY_TENANT_ADMIN_EMAIL"):
        bootstrap_managed_tenant()

    # 3. First boot creates admin owner, locks Analyzer (Sandbox) Mode ON, and emits WORM record
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_EMAIL", "Founder.Quant@Chirify.io")
    boot1 = bootstrap_managed_tenant()
    assert boot1["bootstrapped"] is True
    assert boot1["already_existed"] is False
    assert boot1["tenant_id"] == "ten_alpha_01"
    assert boot1["username"] == "founder_quant"
    assert boot1["email"] == "founder.quant@chirify.io"
    assert boot1["analyze_mode"] is True
    assert "password" not in boot1

    admin_user = user_db.find_user_by_username()
    assert admin_user is not None
    assert admin_user.username == "founder_quant"
    assert admin_user.email == "founder.quant@chirify.io"
    assert admin_user.is_admin is True
    assert settings_db.get_analyze_mode() is True
    assert auth_db.get_api_key("founder_quant") is True

    chain = verify_worm_chain(worm_file)
    assert chain.valid is True
    assert chain.records_checked == 1
    worm_entry = json.loads(worm_file.read_text(encoding="utf-8").strip())
    assert worm_entry["event_type"] == "chirify_pod_bootstrapped"
    assert worm_entry["payload"]["tenant_id"] == "ten_alpha_01"

    # 4. Second boot is idempotent and does NOT overwrite legitimately unlocked Live Mode
    boot2 = bootstrap_managed_tenant()
    assert boot2["bootstrapped"] is True
    assert boot2["already_existed"] is True
    assert user_db.User.query.count() == 1

    settings_db.set_analyze_mode(False)
    boot3 = bootstrap_managed_tenant()
    assert boot3["already_existed"] is True
    assert settings_db.get_analyze_mode() is False  # Preserved!

    # 5. /setup is strictly blocked with 403 on both GET and POST (even without CSRF token)
    for method in ("get", "post"):
        resp = getattr(client, method)("/setup", data={"username": "attacker"})
        assert resp.status_code == 403
        body = resp.get_json()
        assert body["status"] == "error"
        assert body["code"] == "managed_pod_setup_disabled"

    r_trailing = client.get("/setup/")
    assert r_trailing.status_code == 403
    assert r_trailing.get_json()["code"] == "managed_pod_setup_disabled"

    r_check_managed = client.get("/auth/check-setup")
    assert r_check_managed.status_code == 200
    assert r_check_managed.get_json()["needs_setup"] is False


def test_cli_bootstrap_entrypoint_and_start_sh_app_wiring(tmp_path: Path):
    start_sh = (ROOT / "start.sh").read_text(encoding="utf-8")
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")

    invariants_pos = start_sh.index("utils.startup_invariants")
    bootstrap_pos = start_sh.index("services.chirify_bootstrap_service")
    ws_proxy_pos = start_sh.index("websocket_proxy.server")
    assert invariants_pos < bootstrap_pos < ws_proxy_pos

    assert "install_managed_pod_setup_guard(app)" in app_py
    assert "app.register_blueprint(chirify_sso_bp)" in app_py
    assert "csrf.exempt(chirify_sso_bp)" in app_py
    assert '"/auth/chirify/"' in app_py

    cli_db = tmp_path / "cli_boot.db"
    cli_worm = tmp_path / "cli_worm.jsonl"
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "DATABASE_URL": f"sqlite:///{cli_db}",
        "API_KEY_PEPPER": "a" * 64,
        "FERNET_SALT": "b" * 32,
        "CHIRIFY_MANAGED_POD": "1",
        "CHIRIFY_TENANT_ID": "ten_cli_99",
        "CHIRIFY_TENANT_ADMIN_EMAIL": "cli-owner@chirify.io",
        "CHIRIFY_WORM_LOG_PATH": str(cli_worm),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "services.chirify_bootstrap_service"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ten_cli_99" in proc.stdout
    assert verify_worm_chain(cli_worm).valid is True


def test_valid_60s_chirify_sso_ticket_establishes_session_and_routes_to_broker_or_dashboard(
    _isolated_pod_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    worm_file = _isolated_pod_state["worm_file"]
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_sso_01")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_EMAIL", "trader@chirify.io")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_USERNAME", "pro_trader")
    monkeypatch.setenv("CHIRIFY_SSO_SECRET", SSO_SECRET)

    bootstrap_managed_tenant()
    app = _build_test_app()
    client = app.test_client()

    # 1. Exact Control Plane 60s ticket via GET /auth/chirify/sso?ticket=<jwt>
    ticket_get = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_sso_01",
        email="trader@chirify.io",
        ttl_seconds=60,
    )
    # Ensure URL redaction strips ?ticket=<jwt> from any request logs
    assert ticket_get not in redact_url_credentials(f"/auth/chirify/sso?ticket={ticket_get}")

    r_get = client.get(f"/auth/chirify/sso?ticket={ticket_get}")
    assert r_get.status_code == 302
    assert r_get.headers["Location"].endswith("/broker")
    assert "no-store" in r_get.headers.get("Cache-Control", "")
    assert r_get.headers.get("Referrer-Policy") == "no-referrer"

    who = client.get("/_test/whoami").get_json()
    assert who["user"] == "pro_trader"
    assert who["auth_at"] is not None

    # 2. POST /auth/chirify/sso JSON (CSRF-exempt) and format=json
    client_post = app.test_client()
    ticket_post = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_sso_01",
        email="trader@chirify.io",
        ttl_seconds=60,
        typ=None,
        purpose="pod_sso",  # Also verify purpose=="pod_sso" variant
    )
    r_post = client_post.post("/auth/chirify/sso", json={"ticket": ticket_post})
    assert r_post.status_code == 200
    assert r_post.get_json() == {
        "status": "success",
        "redirect": "/broker",
        "user": "pro_trader",
    }
    who_post = client_post.get("/_test/whoami").get_json()
    assert who_post["user"] == "pro_trader"
    assert who_post["auth_at"] is not None

    # 3. Active broker session resume routes straight to /dashboard
    def _fake_resume(username: str):
        session["logged_in"] = True
        session["broker"] = "zerodha"
        return jsonify({"status": "success", "redirect": "/dashboard", "broker": "zerodha"}), 200

    monkeypatch.setattr("blueprints.chirify_sso._try_resume_broker_session", _fake_resume)
    client_resumed = app.test_client()
    ticket_resume = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_sso_01",
        email="trader@chirify.io",
        ttl_seconds=60,
    )
    r_resumed = client_resumed.get(f"/auth/chirify/sso?ticket={ticket_resume}&format=json")
    assert r_resumed.status_code == 200
    assert r_resumed.get_json()["redirect"] == "/dashboard"
    assert r_resumed.get_json()["broker"] == "zerodha"

    # 4. User with 2FA TOTP enabled for login parks pending_totp_user without setting session["user"]
    u = user_db.find_user_by_exact_username("pro_trader")
    u.totp_enabled = True
    u.totp_required_for_login = True
    user_db.db_session.commit()

    client_totp = app.test_client()
    ticket_totp = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_sso_01",
        email="trader@chirify.io",
        ttl_seconds=60,
    )
    r_totp = client_totp.get(f"/auth/chirify/sso?ticket={ticket_totp}")
    assert r_totp.status_code == 302
    assert r_totp.headers["Location"].endswith("/login?totp=1")
    who_totp = client_totp.get("/_test/whoami").get_json()
    assert who_totp["user"] is None
    assert who_totp["pending_totp_user"] == "pro_trader"

    # Verify WORM log recorded SSO events without leaking raw JWT strings
    raw_worm = worm_file.read_text(encoding="utf-8")
    assert ticket_get not in raw_worm
    assert ticket_post not in raw_worm
    assert verify_worm_chain(worm_file).valid is True


def test_sso_jti_replay_attack_rejected_with_401(
    _isolated_pod_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_replay_01")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_EMAIL", "replay@chirify.io")
    monkeypatch.setenv("CHIRIFY_SSO_SECRET", SSO_SECRET)

    bootstrap_managed_tenant()
    app = _build_test_app()

    replay_ticket = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_replay_01",
        email="replay@chirify.io",
        jti="deadbeef" * 4,
        ttl_seconds=60,
    )

    # First redemption succeeds
    c1 = app.test_client()
    r1 = c1.get(f"/auth/chirify/sso?ticket={replay_ticket}")
    assert r1.status_code == 302
    assert r1.headers["Location"].endswith("/broker")

    # Second redemption with the same JTI is rejected with HTTP 401!
    c2 = app.test_client()
    r2 = c2.get(f"/auth/chirify/sso?ticket={replay_ticket}")
    assert r2.status_code == 401
    assert r2.get_json()["code"] == "sso_ticket_replayed"
    assert c2.get("/_test/whoami").get_json()["user"] is None

    # Direct verifier call also raises SSOTicketReplayError
    with pytest.raises(SSOTicketReplayError):
        verify_and_consume_sso_ticket(
            replay_ticket,
            secret=SSO_SECRET,
            expected_tenant_id="ten_replay_01",
        )


def test_sso_rejects_entitlement_token_wrong_aud_expired_and_over_120s_ttl_with_401(
    _isolated_pod_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    # Share secret between entitlement & SSO fallback to prove anti-confusion is enforced by claims!
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_guard_01")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_EMAIL", "guard@chirify.io")
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_SECRET", ENTITLEMENT_SECRET)

    bootstrap_managed_tenant()
    app = _build_test_app()
    client = app.test_client()

    # 1. Ordinary Chirify Entitlement token presented to SSO endpoint -> 401
    ent_token = sign_entitlement_token(
        EntitlementClaims.from_mapping(_qualified_claims(tenant_id="ten_guard_01")),
        ENTITLEMENT_SECRET,
    )
    r_ent = client.get(f"/auth/chirify/sso?ticket={ent_token}")
    assert r_ent.status_code == 401
    assert r_ent.get_json()["code"] == "sso_wrong_token_type"

    # 2. JWT with header typ="JWT" and matching iss/aud/sub/jti, but missing typ="CHIRIFY-SSO" & purpose="pod_sso" -> 401
    now = int(time.time())
    hdr_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode("ascii")
    pay_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "chirify-control-plane",
                    "aud": "ten_guard_01",
                    "tenant_id": "ten_guard_01",
                    "sub": "guard@chirify.io",
                    "iat": now,
                    "exp": now + 60,
                    "jti": "plain-jwt-no-sso-purpose",
                }
            ).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    sig_b64 = (
        base64.urlsafe_b64encode(
            hmac.new(
                ENTITLEMENT_SECRET.encode("utf-8"),
                f"{hdr_b64}.{pay_b64}".encode("ascii"),
                hashlib.sha256,
            ).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    r_plain_jwt = client.get(f"/auth/chirify/sso?ticket={hdr_b64}.{pay_b64}.{sig_b64}")
    assert r_plain_jwt.status_code == 401
    assert r_plain_jwt.get_json()["code"] == "sso_wrong_token_type"

    # 3. Wrong audience / tenant_id -> 401
    wrong_aud_ticket = mint_sso_ticket(
        secret=ENTITLEMENT_SECRET,
        tenant_id="ten_other_victim",
        email="guard@chirify.io",
        ttl_seconds=60,
    )
    r_aud = client.get(f"/auth/chirify/sso?ticket={wrong_aud_ticket}")
    assert r_aud.status_code == 401
    assert r_aud.get_json()["code"] in {"sso_wrong_aud", "sso_wrong_tenant"}

    # 4. Expired ticket -> 401
    expired_ticket = mint_sso_ticket(
        secret=ENTITLEMENT_SECRET,
        tenant_id="ten_guard_01",
        email="guard@chirify.io",
        now_epoch=now - 180,
        ttl_seconds=60,
    )
    r_exp = client.get(f"/auth/chirify/sso?ticket={expired_ticket}")
    assert r_exp.status_code == 401
    assert r_exp.get_json()["code"] == "sso_ticket_expired"

    # 5. Ticket exceeding 120s hard TTL ceiling (e.g. 121s and 600s) -> 401
    long_ttl_ticket = mint_sso_ticket(
        secret=ENTITLEMENT_SECRET,
        tenant_id="ten_guard_01",
        email="guard@chirify.io",
        now_epoch=now,
        ttl_seconds=121,
    )
    r_ttl = client.get(f"/auth/chirify/sso?ticket={long_ttl_ticket}")
    assert r_ttl.status_code == 401
    assert r_ttl.get_json()["code"] == "sso_ttl_exceeded"

    # 6. Wrong signing secret -> 401
    forged_ticket = mint_sso_ticket(
        secret="attacker-forged-secret",
        tenant_id="ten_guard_01",
        email="guard@chirify.io",
        ttl_seconds=60,
    )
    r_forged = client.get(f"/auth/chirify/sso?ticket={forged_ticket}")
    assert r_forged.status_code == 401
    assert r_forged.get_json()["code"] == "sso_bad_signature"


def test_full_managed_pod_lifecycle_sandbox_boot_to_dynamic_entitlement_sync_to_live_mode(
    _isolated_pod_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    worm_file = _isolated_pod_state["worm_file"]

    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_live_01")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_EMAIL", "alpha@chirify.io")
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_SECRET", ENTITLEMENT_SECRET)
    monkeypatch.setenv("CHIRIFY_INTERNAL_OPS_TOKEN", INTERNAL_OPS_TOKEN)

    monkeypatch.setattr(analyzer_service, "_reconcile_sandbox", lambda *a, **kw: None)
    monkeypatch.setattr(analyzer_service.log_executor, "submit", lambda *a, **kw: None)

    # Step 1: Headless pod boots in Sandbox Mode (analyze_mode=True) with Live Gate enforced
    boot = bootstrap_managed_tenant()
    assert boot["bootstrapped"] is True
    assert settings_db.get_analyze_mode() is True

    # Step 2: Before qualification sync, switching to Live Mode is blocked with HTTP 403!
    with pytest.raises(LiveGateBlockedError) as blocked_exc:
        analyzer_service.apply_analyze_mode(False, broker="zerodha")
    assert blocked_exc.value.status_code == 403
    assert settings_db.get_analyze_mode() is True

    ok_pre, resp_pre, status_pre = analyzer_service.toggle_analyzer_mode_with_auth(
        {"mode": False}, "broker-tok", "zerodha", {"mode": False}
    )
    assert ok_pre is False
    assert status_pre == 403
    assert settings_db.get_analyze_mode() is True

    app = _build_test_app()
    client = app.test_client()
    ops_headers = {"Authorization": f"Bearer {INTERNAL_OPS_TOKEN}"}
    cluster_env = {"REMOTE_ADDR": "10.244.2.15"}

    # Step 3: Public IP or wrong tenant_id or forged token on /internal/v1/entitlements/sync rejected
    qualified_jwt = sign_entitlement_token(_qualified_claims("ten_live_01"), ENTITLEMENT_SECRET)

    r_pub = client.post(
        "/internal/v1/entitlements/sync",
        json={"entitlement_token": qualified_jwt, "enforce_live_gate": True},
        headers=ops_headers,
        environ_base={"REMOTE_ADDR": "198.51.100.42"},
    )
    assert r_pub.status_code == 403

    wrong_tenant_jwt = sign_entitlement_token(
        _qualified_claims("ten_wrong_99"), ENTITLEMENT_SECRET
    )
    r_wrong_tenant = client.post(
        "/internal/v1/entitlements/sync",
        json={"entitlement_token": wrong_tenant_jwt, "enforce_live_gate": True},
        headers=ops_headers,
        environ_base=cluster_env,
    )
    assert r_wrong_tenant.status_code == 403
    assert r_wrong_tenant.get_json()["code"] == "tenant_mismatch"

    r_forged = client.post(
        "/internal/v1/entitlements/sync",
        json={"entitlement_token": qualified_jwt + "tamper", "enforce_live_gate": True},
        headers=ops_headers,
        environ_base=cluster_env,
    )
    assert r_forged.status_code == 403
    assert r_forged.get_json()["code"] == "entitlement_invalid"

    # SSO ticket rejected on entitlements/sync (bidirectional anti-confusion)
    sso_ticket = mint_sso_ticket(
        secret=ENTITLEMENT_SECRET,
        tenant_id="ten_live_01",
        email="alpha@chirify.io",
        ttl_seconds=60,
    )
    r_sso_confused = client.post(
        "/internal/v1/entitlements/sync",
        json={"entitlement_token": sso_ticket},
        headers=ops_headers,
        environ_base=cluster_env,
    )
    assert r_sso_confused.status_code == 400
    assert r_sso_confused.get_json()["code"] == "wrong_token_type"

    # Step 4: Control Plane pushes qualified HS256 entitlement token at Step 8 ("Unlock Live Execution")
    r_sync = client.post(
        "/internal/v1/entitlements/sync",
        json={"entitlement_token": qualified_jwt, "enforce_live_gate": True},
        headers=ops_headers,
        environ_base=cluster_env,
    )
    assert r_sync.status_code == 200
    sync_body = r_sync.get_json()
    assert sync_body["status"] == "ok"
    assert sync_body["tenant_id"] == "ten_live_01"
    assert sync_body["live_gate"]["allowed"] is True
    assert sync_body["live_gate"]["code"] == "ok"

    # Step 5: apply_analyze_mode(False) now succeeds dynamically without pod restart!
    persisted_mode = analyzer_service.apply_analyze_mode(False, broker="zerodha")
    assert persisted_mode is False
    assert settings_db.get_analyze_mode() is False

    # Verify WORM audit chain integrity and ensure raw token was redacted
    worm_raw = worm_file.read_text(encoding="utf-8")
    assert qualified_jwt not in worm_raw
    worm_records = [json.loads(line) for line in worm_raw.splitlines() if line.strip()]
    event_types = [r["event_type"] for r in worm_records]
    assert "chirify_pod_bootstrapped" in event_types
    assert "chirify_entitlement_synced" in event_types
    synced_rec = next(r for r in worm_records if r["event_type"] == "chirify_entitlement_synced")
    assert synced_rec["payload"]["jti"] == "ent-jti-2026-0001"
    assert synced_rec["payload"]["tenant_id"] == "ten_live_01"
    assert synced_rec["payload"]["allowed"] is True
    assert synced_rec["payload"]["cohort"] == "india_pro_pod"

    verification = verify_worm_chain(worm_file)
    assert verification.valid is True
    assert verification.records_checked == len(worm_records)


def test_sso_consumed_jtis_bounded_cap_evicts_oldest_expiring_and_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
):
    """PRR Memory-DoS regression: _CONSUMED_JTIS never exceeds MAX_CONSUMED_JTIS."""
    assert chirify_sso.MAX_CONSUMED_JTIS == 10_000
    monkeypatch.setattr(chirify_sso, "MAX_CONSUMED_JTIS", 5)

    warnings_logged: list[str] = []
    monkeypatch.setattr(
        chirify_sso.logger,
        "warning",
        lambda msg, *args, **kwargs: warnings_logged.append(str(msg)),
    )

    base_now = 1_800_000_000
    minted_tickets: list[tuple[str, str]] = []
    for idx in range(8):
        jti = f"bounded-jti-{idx:02d}"
        ticket = mint_sso_ticket(
            secret=SSO_SECRET,
            tenant_id="ten_cap_01",
            email="cap@chirify.io",
            jti=jti,
            now_epoch=base_now,
            ttl_seconds=30 + idx * 5,
        )
        minted_tickets.append((jti, ticket))

        claims = verify_and_consume_sso_ticket(
            ticket,
            secret=SSO_SECRET,
            expected_tenant_id="ten_cap_01",
            now_epoch=base_now + 1,
        )
        assert claims.jti == jti
        assert len(chirify_sso._CONSUMED_JTIS) <= 5

    # Cache stays strictly bounded at cap=5, retaining the 5 freshest active JTIs
    assert len(chirify_sso._CONSUMED_JTIS) == 5
    assert set(chirify_sso._CONSUMED_JTIS.keys()) == {
        f"bounded-jti-{idx:02d}" for idx in range(3, 8)
    }
    # High-priority warnings emitted on the 3 evictions (insertions 6, 7, 8)
    assert len(warnings_logged) == 3
    assert all("evicted" in w.lower() for w in warnings_logged)

    # Replay protection remains intact for the freshest active window (even at exact cap)
    for idx in (3, 7):
        with pytest.raises(SSOTicketReplayError):
            verify_and_consume_sso_ticket(
                minted_tickets[idx][1],
                secret=SSO_SECRET,
                expected_tenant_id="ten_cap_01",
                now_epoch=base_now + 1,
            )


def test_sso_endpoint_attaches_nosniff_no_store_and_no_referrer_headers(
    _isolated_pod_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
):
    """PRR security header regression for /auth/chirify/sso across 403, 401, 302, and 200."""
    app = _build_test_app()
    client = app.test_client()

    # 1. Standalone mode (403)
    r_disabled = client.get("/auth/chirify/sso?ticket=anything")
    assert r_disabled.status_code == 403
    assert r_disabled.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-store" in r_disabled.headers.get("Cache-Control", "")
    assert r_disabled.headers.get("Referrer-Policy") == "no-referrer"

    # Enable managed pod + bootstrap owner
    monkeypatch.setenv("CHIRIFY_MANAGED_POD", "true")
    monkeypatch.setenv("CHIRIFY_TENANT_ID", "ten_hdr_01")
    monkeypatch.setenv("CHIRIFY_TENANT_ADMIN_EMAIL", "headers@chirify.io")
    monkeypatch.setenv("CHIRIFY_SSO_SECRET", SSO_SECRET)
    bootstrap_managed_tenant()

    # 2. Invalid ticket (401)
    r_invalid = client.get("/auth/chirify/sso?ticket=not.a.validjwt")
    assert r_invalid.status_code == 401
    assert r_invalid.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-store" in r_invalid.headers.get("Cache-Control", "")
    assert r_invalid.headers.get("Referrer-Policy") == "no-referrer"

    # 3. Valid GET redirect (302)
    ticket_get = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_hdr_01",
        email="headers@chirify.io",
        ttl_seconds=60,
    )
    r_ok_get = client.get(f"/auth/chirify/sso?ticket={ticket_get}")
    assert r_ok_get.status_code == 302
    assert r_ok_get.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-store" in r_ok_get.headers.get("Cache-Control", "")
    assert r_ok_get.headers.get("Referrer-Policy") == "no-referrer"

    # 4. Valid POST JSON (200)
    ticket_post = mint_sso_ticket(
        secret=SSO_SECRET,
        tenant_id="ten_hdr_01",
        email="headers@chirify.io",
        ttl_seconds=60,
    )
    r_ok_post = app.test_client().post("/auth/chirify/sso", json={"ticket": ticket_post})
    assert r_ok_post.status_code == 200
    assert r_ok_post.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-store" in r_ok_post.headers.get("Cache-Control", "")
    assert r_ok_post.headers.get("Referrer-Policy") == "no-referrer"
