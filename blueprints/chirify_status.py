"""Chirify Pod Telemetry, EU AI Act Art. 50 Disclosure & AGPL-3.0 Attribution (`/api/v1/chirify/*`).

Exposes ``GET /api/v1/chirify/status``:
- **Publicly readable before login** so any network user can discover the exact
  corresponding source repository under **GNU AGPL-3.0 Section 13**, the
  **EU AI Act Article 50** white-box copilot transparency notice, non-secret
  operational safety posture (``analyze_mode``, ``kill_switch_engaged``,
  ``live_gate``, ``static_egress_verified``, ``openrouter_region``), and the
  tamper-evident SHA-256 WORM audit head hash.
- **Authenticated pod telemetry** when signed into OpenAlgo or called over a
  cluster-private IP with ``CHIRIFY_INTERNAL_OPS_TOKEN``, attaching tenant and
  broker metadata without ever exposing credentials or raw tokens.
"""

from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, request, session

from blueprints.internal_ops import is_allowed_internal_ip
from services import chirify_live_gate
from services.chirify_bootstrap_service import (
    _clean_env_val,
    is_managed_pod,
    is_worm_audit_enabled,
)
from services.chirify_openrouter import detect_key_workspace
from subscribers.worm_audit_subscriber import (
    DEFAULT_WORM_LOG_PATH,
    GENESIS_PREV_HASH,
    verify_worm_chain,
)
from utils.logging import get_logger
from utils.startup_invariants import (
    ALLOWED_ZMQ_HOSTS,
    DEFAULT_EGRESS_STATE_PATH,
    is_truthy,
)

logger = get_logger(__name__)

chirify_status_bp = Blueprint("chirify_status_bp", __name__, url_prefix="/api/v1/chirify")
chirify_probes_bp = Blueprint("chirify_probes_bp", __name__)

DEFAULT_CHIRIFY_SOURCE_REPO_URL = "https://github.com/chiranjeevich2808-spec/chirify-openalgo"
UPSTREAM_OPENALGO_URL = "https://github.com/marketcalls/openalgo"
EU_AI_ACT_ART50_DISCLOSURE = (
    "AI outputs are white-box analytical/copilot aids, not personalized investment advice"
)


def _extract_internal_token() -> str:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return (request.headers.get("X-Chirify-Internal-Token") or "").strip()


def _is_internal_caller_authenticated() -> bool:
    if not is_allowed_internal_ip(request.remote_addr):
        return False
    expected = _clean_env_val(os.getenv("CHIRIFY_INTERNAL_OPS_TOKEN"))
    provided = _extract_internal_token()
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _is_session_caller_authenticated() -> bool:
    user = session.get("user")
    if not user:
        return False
    try:
        from utils.session import sign_in_revoked

        if sign_in_revoked():
            return False
    except Exception:
        pass
    return True


def _read_analyze_mode_safe(*, default_sandbox: bool) -> bool:
    """Read persisted ``analyze_mode`` without failing if DB tables are uninitialized."""
    try:
        from database.settings_db import get_analyze_mode

        return bool(get_analyze_mode())
    except Exception:
        return default_sandbox


def _resolve_static_egress_state() -> tuple[bool, bool, bool]:
    """Return ``(verified, require_static_egress, state_file_present)``."""
    require_static = is_truthy(os.getenv("CHIRIFY_REQUIRE_STATIC_EGRESS"))
    state_path = Path(
        _clean_env_val(os.getenv("CHIRIFY_EGRESS_STATE_PATH")) or str(DEFAULT_EGRESS_STATE_PATH)
    )
    if not state_path.is_file():
        return False, require_static, False

    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, require_static, True

    if not isinstance(payload, dict):
        return False, require_static, True

    if payload.get("verified") is False:
        return False, require_static, True

    observed_ip = str(payload.get("observed_ip") or "").strip()
    allowed_ips = {
        ip.strip()
        for ip in (
            os.getenv("EXPECTED_EGRESS_IPV4", ""),
            os.getenv("EXPECTED_SECONDARY_IPV4", ""),
        )
        if ip and ip.strip()
    }
    verified = bool(observed_ip) and (not allowed_ips or observed_ip in allowed_ips)
    return verified, require_static, True


def _resolve_openrouter_region() -> str:
    """Resolve active OpenRouter data-residency region (``EU``, ``US``, or ``GLOBAL``)."""
    for env_key in (
        "CHIRIFY_OPENROUTER_REGION",
        "OPENROUTER_REGION",
        "CHIRIFY_DATA_RESIDENCY",
    ):
        raw = _clean_env_val(os.getenv(env_key)).upper()
        if raw in {"EU", "US"}:
            return raw
        if raw in {"GLOBAL", "IN"}:
            return "GLOBAL"

    for key_var in ("CHIRIFY_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"):
        raw_key = _clean_env_val(os.getenv(key_var))
        if raw_key:
            try:
                detected = detect_key_workspace(raw_key)
                if detected in {"EU", "US"}:
                    return detected
            except ValueError:
                pass
    return "GLOBAL"


def _resolve_worm_audit_summary() -> dict[str, Any]:
    """Summarize WORM JSONL audit status, record count, and SHA-256 head hash."""
    explicit_path = _clean_env_val(os.getenv("CHIRIFY_WORM_LOG_PATH"))
    if explicit_path:
        candidates = [Path(explicit_path)]
    else:
        fallback_dir = Path(_clean_env_val(os.getenv("LOG_DIR")) or "log")
        candidates = [Path(DEFAULT_WORM_LOG_PATH), fallback_dir / "worm_audit.jsonl"]

    chosen_path = next((p for p in candidates if p.is_file()), candidates[0])
    enabled = bool(is_worm_audit_enabled() or chosen_path.is_file())

    if not chosen_path.is_file():
        return {
            "enabled": enabled,
            "records_count": 0,
            "head_hash": GENESIS_PREV_HASH,
            "valid": True,
        }

    verification = verify_worm_chain(chosen_path)
    return {
        "enabled": enabled,
        "records_count": verification.records_checked,
        "head_hash": verification.head_hash,
        "valid": verification.valid,
    }


@chirify_status_bp.route("/status", methods=["GET"])
def get_chirify_status():
    """Return AGPL-3.0 Section 13 attribution, EU AI Act Art. 50 notice, and pod telemetry."""
    managed = is_managed_pod()
    source_code_url = (
        _clean_env_val(os.getenv("CHIRIFY_SOURCE_REPO_URL")) or DEFAULT_CHIRIFY_SOURCE_REPO_URL
    )
    analyze_mode = _read_analyze_mode_safe(default_sandbox=managed)
    kill_switch_engaged = chirify_live_gate.is_emergency_kill_switch_engaged()

    authenticated = _is_session_caller_authenticated() or _is_internal_caller_authenticated()
    active_broker = session.get("broker") if _is_session_caller_authenticated() else None

    gate_verdict = chirify_live_gate.check_live_mode_transition(
        current_mode=analyze_mode,
        target_mode=False,
        broker=active_broker,
    )
    live_gate_summary: dict[str, Any] = {
        "enforced": chirify_live_gate.is_live_gate_enforced(),
        "allowed": gate_verdict.allowed,
        "code": gate_verdict.code,
        "message": gate_verdict.message,
        "reasons": list(gate_verdict.reasons),
    }

    static_egress_verified, require_static_egress, egress_file_present = (
        _resolve_static_egress_state()
    )
    openrouter_region = _resolve_openrouter_region()
    worm_summary = _resolve_worm_audit_summary()

    payload: dict[str, Any] = {
        "status": "ok",
        "license": "AGPL-3.0",
        "source_code_url": source_code_url,
        "upstream_url": UPSTREAM_OPENALGO_URL,
        "managed_pod": managed,
        "ai_disclosure": EU_AI_ACT_ART50_DISCLOSURE,
        "analyze_mode": analyze_mode,
        "kill_switch_engaged": kill_switch_engaged,
        "live_gate": live_gate_summary,
        "static_egress_verified": static_egress_verified,
        "openrouter_region": openrouter_region,
        "worm_audit": worm_summary,
        "authenticated": authenticated,
    }

    if authenticated:
        payload["telemetry"] = {
            "tenant_id": _clean_env_val(os.getenv("CHIRIFY_TENANT_ID")) or None,
            "active_broker": active_broker,
            "egress": {
                "require_static_egress": require_static_egress,
                "state_file_present": egress_file_present,
                "verified": static_egress_verified,
            },
        }

    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response, 200


def _resolve_ib_gateway_readiness_gauge() -> int:
    """Resolve IB Gateway API readiness gauge (`1` = healthy/not stalling, `0` = degraded)."""
    app_flag = getattr(current_app, "ib_gateway_ready", None)
    if isinstance(app_flag, bool):
        return 1 if app_flag else 0

    raw_env = _clean_env_val(os.getenv("CHIRIFY_IB_GATEWAY_READY"))
    if raw_env:
        return 1 if is_truthy(raw_env) else 0

    return 1


@chirify_probes_bp.route("/healthz", methods=["GET"])
def pod_healthz():
    """Unauthenticated Kubernetes liveness probe (`GET /healthz`)."""
    response = jsonify(
        {
            "status": "ok",
            "service": "chirify-openalgo",
            "tz": "UTC",
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@chirify_probes_bp.route("/readyz", methods=["GET"])
def pod_readyz():
    """Unauthenticated Kubernetes readiness probe (`GET /readyz`).

    Verifies database initialization readiness (`current_app.db_ready`),
    loopback ZeroMQ binding (`ZMQ_HOST in {'127.0.0.1', 'localhost'}`), and
    static egress IP verification when `CHIRIFY_REQUIRE_STATIC_EGRESS` is enabled.
    """
    reasons: list[str] = []

    db_ready_event = getattr(current_app, "db_ready", None)
    db_ready = True if db_ready_event is None else bool(db_ready_event.is_set())
    if not db_ready:
        reasons.append("db_not_ready")

    zmq_host = _clean_env_val(os.getenv("ZMQ_HOST")) or "127.0.0.1"
    if zmq_host not in ALLOWED_ZMQ_HOSTS:
        reasons.append(f"invalid_zmq_host:{zmq_host}")

    static_egress_verified, require_static_egress, _egress_file_present = (
        _resolve_static_egress_state()
    )
    if require_static_egress and not static_egress_verified:
        reasons.append("static_egress_unverified")

    managed = is_managed_pod()
    analyze_mode = _read_analyze_mode_safe(default_sandbox=managed)
    kill_switch_engaged = chirify_live_gate.is_emergency_kill_switch_engaged()

    ready = len(reasons) == 0
    payload: dict[str, Any] = {
        "status": "ready" if ready else "not_ready",
        "service": "chirify-openalgo",
        "tz": "UTC",
        "db_ready": db_ready,
        "zmq_host": zmq_host,
        "analyze_mode": analyze_mode,
        "kill_switch_engaged": kill_switch_engaged,
        "static_egress_verified": static_egress_verified,
    }
    if reasons:
        payload["reasons"] = reasons

    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response, (200 if ready else 503)


@chirify_probes_bp.route("/metrics", methods=["GET"])
def pod_prometheus_metrics():
    """Unauthenticated Prometheus OpenMetrics 0.0.4 scrape endpoint (`GET /metrics`)."""
    managed = is_managed_pod()
    analyze_mode_val = 1 if _read_analyze_mode_safe(default_sandbox=managed) else 0
    kill_switch_val = 1 if chirify_live_gate.is_emergency_kill_switch_engaged() else 0

    worm_summary = _resolve_worm_audit_summary()
    worm_events_published = int(worm_summary.get("records_count", 0))

    static_egress_verified, require_static_egress, egress_file_present = (
        _resolve_static_egress_state()
    )
    egress_mismatch = (
        1 if ((require_static_egress or egress_file_present) and not static_egress_verified) else 0
    )
    ib_gateway_ready = _resolve_ib_gateway_readiness_gauge()

    lines = [
        "# HELP chirify_pod_analyze_mode Whether OpenAlgo pod is operating in Analyzer/Sandbox mode (1=sandbox, 0=live).",
        "# TYPE chirify_pod_analyze_mode gauge",
        f"chirify_pod_analyze_mode {analyze_mode_val}",
        "# HELP chirify_pod_kill_switch_engaged Whether the EU DORA Art. 30 / SEBI emergency kill-switch is engaged (1=engaged, 0=clear).",
        "# TYPE chirify_pod_kill_switch_engaged gauge",
        f"chirify_pod_kill_switch_engaged {kill_switch_val}",
        "# HELP chirify_eventbus_worm_events_published_total Total hash-chained UTC WORM regulatory audit records written by this pod.",
        "# TYPE chirify_eventbus_worm_events_published_total counter",
        f"chirify_eventbus_worm_events_published_total {worm_events_published}",
        "# HELP chirify_tenant_static_egress_ip_mismatch_total Non-zero when observed SNAT egress IPv4 diverges from allowed static VIPs.",
        "# TYPE chirify_tenant_static_egress_ip_mismatch_total counter",
        f"chirify_tenant_static_egress_ip_mismatch_total {egress_mismatch}",
        "# HELP chirify_ib_gateway_api_readiness_probe_success Interactive Brokers Gateway active reqCurrentTime() API readiness (1=ok, 0=stalled).",
        "# TYPE chirify_ib_gateway_api_readiness_probe_success gauge",
        f"chirify_ib_gateway_api_readiness_probe_success {ib_gateway_ready}",
        "",
    ]
    response = Response(
        "\n".join(lines),
        status=200,
        content_type="text/plain; version=0.0.4; charset=utf-8",
    )
    response.headers["Cache-Control"] = "no-store"
    return response

