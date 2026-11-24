"""PRR Tests: Cohort-A Sandbox-Gated Live Mode & SEBI Compliance (`chirify_live_gate`)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from services import analyzer_service
from services.chirify_live_gate import (
    EntitlementClaims,
    EntitlementVerificationError,
    LiveGateBlockedError,
    check_live_mode_transition,
    evaluate_live_gate,
    sign_entitlement_token,
    verify_entitlement_token,
)

SECRET = "chirify-control-plane-hmac-secret-2026-test"


def _qualified_india_pro_claims(**overrides) -> EntitlementClaims:
    base = {
        "tenant_id": "ten_01",
        "user_id": "usr_01",
        "cohort": "india_pro_pod",
        "broker_name": "zerodha",
        "broker_type": "IN_stock",
        "hosted_cloud": True,
        "sandbox_qualified": True,
        "simulated_trades": 7,
        "unhandled_rms_breaches": 0,
        "max_daily_loss": 5000.0,
        "max_order_notional": 100000.0,
        "static_ip_verified": True,
        "exchange_algo_id": "NSE-ALGO-2026-9981",
        "personal_family_under_10ops_attested": False,
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 3600,
    }
    base.update(overrides)
    return EntitlementClaims.from_mapping(base)


def test_standalone_oss_mode_passes_through_without_entitlement_token():
    verdict = check_live_mode_transition(
        current_mode=True,
        target_mode=False,
        env={"CHIRIFY_ENFORCE_LIVE_GATE": "false"},
    )
    assert verdict.allowed is True
    assert verdict.code == "gate_disabled"

    verdict_unset = check_live_mode_transition(current_mode=True, target_mode=False, env={})
    assert verdict_unset.allowed is True


def test_hmac_entitlement_token_roundtrip_and_tamper_rejection():
    claims = _qualified_india_pro_claims()
    token = sign_entitlement_token(claims, SECRET)
    decoded = verify_entitlement_token(token, SECRET)
    assert decoded.exchange_algo_id == "NSE-ALGO-2026-9981"
    assert decoded.simulated_trades == 7

    # Wrong HMAC secret rejected
    with pytest.raises(EntitlementVerificationError, match="signature"):
        verify_entitlement_token(token, "wrong-secret")

    # Tampered payload rejected
    header_b64, _payload_b64, sig_b64 = token.split(".")
    forged_payload = base64.urlsafe_b64encode(
        json.dumps({**claims.to_dict(), "simulated_trades": 999}).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    with pytest.raises(EntitlementVerificationError):
        verify_entitlement_token(f"{header_b64}.{forged_payload}.{sig_b64}", SECRET)

    # Expired token rejected
    expired = sign_entitlement_token(_qualified_india_pro_claims(expires_at=1000), SECRET)
    with pytest.raises(EntitlementVerificationError, match="expired"):
        verify_entitlement_token(expired, SECRET, now_epoch=2000.0)

    # 2-part hex HMAC token also supported
    p_b64 = base64.urlsafe_b64encode(json.dumps(claims.to_dict()).encode("utf-8")).rstrip(b"=").decode("ascii")
    hex_sig = hmac.new(SECRET.encode("utf-8"), p_b64.encode("ascii"), hashlib.sha256).hexdigest()
    assert verify_entitlement_token(f"{p_b64}.{hex_sig}", SECRET).tenant_id == "ten_01"


def test_cohort_a_sandbox_and_risk_guard_gates():
    assert evaluate_live_gate(_qualified_india_pro_claims()).allowed is True

    v_unqual = evaluate_live_gate(_qualified_india_pro_claims(sandbox_qualified=False))
    assert not v_unqual.allowed and v_unqual.code == "sandbox_unqualified"

    v_trades = evaluate_live_gate(_qualified_india_pro_claims(simulated_trades=4))
    assert not v_trades.allowed and v_trades.code == "insufficient_simulated_trades"

    v_rms = evaluate_live_gate(_qualified_india_pro_claims(unhandled_rms_breaches=1))
    assert not v_rms.allowed and v_rms.code == "unhandled_rms_breaches"

    v_loss = evaluate_live_gate(_qualified_india_pro_claims(max_daily_loss=0.0))
    assert not v_loss.allowed and v_loss.code == "risk_kill_switch_unconfigured"

    v_notional = evaluate_live_gate(_qualified_india_pro_claims(max_order_notional=0.0))
    assert not v_notional.allowed and v_notional.code == "risk_notional_unconfigured"


def test_sebi_compliance_rules_for_indian_vs_global_brokers():
    # Indian Pro Pod missing static IP verification -> blocked
    v_ip = evaluate_live_gate(_qualified_india_pro_claims(static_ip_verified=False))
    assert not v_ip.allowed and v_ip.code == "sebi_static_ip_unverified"

    # Indian hosted cloud pod missing SEBI exchange_algo_id -> blocked
    v_algo = evaluate_live_gate(_qualified_india_pro_claims(exchange_algo_id="   "))
    assert not v_algo.allowed and v_algo.code == "sebi_exchange_algo_id_required"

    # Indian BYO-VPS cohort: hosted_cloud=False, requires <10 OPS personal/family attestation
    byo_blocked = evaluate_live_gate(
        _qualified_india_pro_claims(
            cohort="india_byo_vps",
            hosted_cloud=False,
            static_ip_verified=False,
            exchange_algo_id="",
            personal_family_under_10ops_attested=False,
        )
    )
    assert not byo_blocked.allowed and byo_blocked.code == "sebi_byo_vps_attestation_required"

    byo_ok = evaluate_live_gate(
        _qualified_india_pro_claims(
            cohort="india_byo_vps",
            hosted_cloud=False,
            static_ip_verified=False,
            exchange_algo_id="",
            personal_family_under_10ops_attested=True,
        )
    )
    assert byo_ok.allowed is True

    # Global US/Crypto brokers do not require Indian SEBI exchange_algo_id
    us_ok = evaluate_live_gate(
        _qualified_india_pro_claims(
            cohort="global_cloud",
            broker_name="alpaca",
            broker_type="US_multi",
            hosted_cloud=True,
            static_ip_verified=False,
            exchange_algo_id="",
        )
    )
    assert us_ok.allowed is True


def test_analyzer_service_wiring_blocks_unqualified_live_switch_and_allows_qualified(monkeypatch):
    state = {"analyze_mode": True}
    monkeypatch.setattr(analyzer_service, "get_analyze_mode", lambda: state["analyze_mode"])
    monkeypatch.setattr(
        analyzer_service,
        "set_analyze_mode",
        lambda mode: state.__setitem__("analyze_mode", bool(mode)),
    )
    monkeypatch.setattr(analyzer_service, "_reconcile_sandbox", lambda *a, **kw: None)
    monkeypatch.setattr(analyzer_service.log_executor, "submit", lambda *a, **kw: None)

    class _DummyQuery:
        def count(self) -> int:
            return 5

    monkeypatch.setattr(analyzer_service.db_session, "query", lambda *a: _DummyQuery())

    # Enforce Live Gate with an unqualified token (only 2 simulated trades)
    bad_token = sign_entitlement_token(_qualified_india_pro_claims(simulated_trades=2), SECRET)
    monkeypatch.setenv("CHIRIFY_ENFORCE_LIVE_GATE", "true")
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_SECRET", SECRET)
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_TOKEN", bad_token)

    with pytest.raises(LiveGateBlockedError):
        analyzer_service.apply_analyze_mode(False, broker="zerodha")
    assert state["analyze_mode"] is True  # Remained safely in Sandbox!

    ok, resp, status = analyzer_service.toggle_analyzer_mode_with_auth(
        {"mode": False}, "broker-token", "zerodha", {"mode": False}
    )
    assert ok is False
    assert status == 403
    assert resp["code"] == "insufficient_simulated_trades"
    assert state["analyze_mode"] is True

    # Switching to Sandbox (mode=True) is always allowed even with bad token
    ok_sb, resp_sb, status_sb = analyzer_service.toggle_analyzer_mode_with_auth(
        {"mode": True}, "broker-token", "zerodha", {"mode": True}
    )
    assert ok_sb is True and status_sb == 200

    # Qualified token allows switching to Live (mode=False)
    good_token = sign_entitlement_token(_qualified_india_pro_claims(), SECRET)
    monkeypatch.setenv("CHIRIFY_ENTITLEMENT_TOKEN", good_token)
    ok_live, resp_live, status_live = analyzer_service.toggle_analyzer_mode_with_auth(
        {"mode": False}, "broker-token", "zerodha", {"mode": False}
    )
    assert ok_live is True
    assert status_live == 200
    assert resp_live["data"]["mode"] == "live"
    assert state["analyze_mode"] is False
