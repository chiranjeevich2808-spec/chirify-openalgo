"""Internal Cluster Operations Blueprint (`/internal/v1/*`).

Provides authenticated, private-network-only operational endpoints for the
Chirify Control Plane and Cilium static-egress failover controller:

- ``GET  /internal/v1/health/egress``
- ``POST /internal/v1/failover-reconcile``
- ``GET  /internal/v1/pod/runtime-credentials``
- ``GET  /internal/v1/historify/catalog``
- ``GET  /internal/v1/historify/candles``
- ``POST /internal/v1/historify/ingest``
- ``POST /internal/v1/historify/export-parquet``
- ``GET  /internal/v1/strategies``
- ``POST /internal/v1/strategies``
- ``POST /internal/v1/strategies/<id>/<action>`` (``start``|``stop``|``close_all``)
- ``GET  /internal/v1/strategies/<id>/{runs,orders,events}``
- ``GET  /internal/v1/options/analytics``
- ``GET  /internal/v1/mcp/tools``
- ``POST /internal/v1/mcp/invoke``
- ``POST /internal/v1/entitlements/sync``
- ``POST /internal/v1/compliance/kill-switch``

Security controls:
1. Restricted strictly to loopback, RFC1918 private, link-local, ULA, or
   cluster CGNAT (``100.64.0.0/10``) peer IP addresses via raw
   ``request.remote_addr`` (never trusting spoofable ``X-Forwarded-For``).
2. Constant-time ``hmac.compare_digest`` bearer/header authentication against
   ``CHIRIFY_INTERNAL_OPS_TOKEN`` (fails closed when the token env var is unset).
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import tempfile
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
from flask import Blueprint, current_app, has_app_context, jsonify, request

from services import chirify_live_gate
from services.qlib_snapshot_service import export_historify_parquet
from services.strategy_module import ack_reconciliation
from subscribers.worm_audit_subscriber import (
    REDACTED_VALUE,
    WormAuditRecord,
    WormAuditWriter,
    emit_worm_audit_event,
)
from utils import real_threading
from utils.logging import get_logger
from utils.startup_invariants import DEFAULT_EGRESS_STATE_PATH, is_truthy

logger = get_logger(__name__)

internal_ops_bp = Blueprint("internal_ops_bp", __name__, url_prefix="/internal/v1")


@internal_ops_bp.after_request
def _apply_internal_ops_security_headers(response):
    """Attach non-cacheable nosniff headers to all internal cluster ops responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


_ALLOWED_IPV4_NETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)
_ALLOWED_IPV6_NETS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def is_allowed_internal_ip(remote_addr: str | None) -> bool:
    """Return True iff ``remote_addr`` is in loopback, RFC1918/ULA private, link-local, or pod CGNAT."""
    if not remote_addr:
        return False
    cleaned = remote_addr.strip()
    # Strip IPv6 zone suffix if present (e.g. fe80::1%eth0)
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _ALLOWED_IPV4_NETS)
    return any(addr in net for net in _ALLOWED_IPV6_NETS)


def _extract_provided_token() -> str:
    """Extract internal ops token from ``Authorization: Bearer`` or Chirify internal headers."""
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return (
        request.headers.get("X-Chirify-Internal-Token")
        or request.headers.get("X-Chirify-Ops-Token")
        or ""
    ).strip()


@internal_ops_bp.before_request
def _authenticate_internal_ops():
    """Enforce private/loopback IP allowlist and constant-time token verification."""
    if not is_allowed_internal_ip(request.remote_addr):
        logger.warning(
            f"[InternalOps] Rejected non-private peer IP {request.remote_addr!r} on {request.path}"
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "forbidden_ip",
                    "message": "Internal operations endpoints are restricted to cluster/private IPs.",
                }
            ),
            403,
        )

    expected_token = (os.getenv("CHIRIFY_INTERNAL_OPS_TOKEN") or "").strip()
    if not expected_token:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "internal_ops_disabled",
                    "message": "CHIRIFY_INTERNAL_OPS_TOKEN is not configured.",
                }
            ),
            503,
        )

    provided_token = _extract_provided_token()
    if not provided_token:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "missing_token",
                    "message": "Missing internal operations bearer token.",
                }
            ),
            401,
        )

    if not hmac.compare_digest(
        provided_token.encode("utf-8"),
        expected_token.encode("utf-8"),
    ):
        logger.warning(f"[InternalOps] Invalid token presented from {request.remote_addr!r}")
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_token",
                    "message": "Invalid internal operations token.",
                }
            ),
            403,
        )

    return None


_require_internal_ops_auth = _authenticate_internal_ops
_ENTITLEMENT_SYNC_LOCK = real_threading.Lock()


@internal_ops_bp.route("/health/egress", methods=["GET"])
def egress_health():
    """Report static egress IP verification state for Cilium egress health probes."""
    require_static = is_truthy(os.getenv("CHIRIFY_REQUIRE_STATIC_EGRESS"))
    state_path = Path(
        os.getenv("CHIRIFY_EGRESS_STATE_PATH") or str(DEFAULT_EGRESS_STATE_PATH)
    )
    allowed_ips = sorted(
        {
            ip.strip()
            for ip in (
                os.getenv("EXPECTED_EGRESS_IPV4", ""),
                os.getenv("EXPECTED_SECONDARY_IPV4", ""),
            )
            if ip and ip.strip()
        }
    )

    if not state_path.is_file():
        status_code = 503 if require_static else 200
        return (
            jsonify(
                {
                    "status": "unhealthy" if require_static else "unverified",
                    "require_static_egress": require_static,
                    "state_file_present": False,
                    "allowed_egress_ips": allowed_ips,
                }
            ),
            status_code,
        )

    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return (
            jsonify(
                {
                    "status": "unhealthy",
                    "require_static_egress": require_static,
                    "error": f"Unreadable egress state file: {exc}",
                }
            ),
            503,
        )

    observed_ip = str(payload.get("observed_ip") or "").strip() if isinstance(payload, dict) else ""
    matches = bool(observed_ip) and (not allowed_ips or observed_ip in allowed_ips)
    healthy = matches or not require_static

    return (
        jsonify(
            {
                "status": "ok" if healthy else "unhealthy",
                "require_static_egress": require_static,
                "observed_ip": observed_ip,
                "allowed_egress_ips": allowed_ips,
                "matched": matches,
            }
        ),
        200 if healthy else 503,
    )


@internal_ops_bp.route("/failover-reconcile", methods=["POST"])
def failover_reconcile():
    """Reconcile in-flight strategy acknowledgements after a Cilium egress gateway failover."""
    body: dict[str, Any] = request.get_json(silent=True) or {}
    explicit_run_ids = body.get("run_ids")

    if isinstance(explicit_run_ids, list) and explicit_run_ids:
        examined = repaired = already_bound = unresolved = unresolved_exposure = failed = 0
        for raw_run_id in explicit_run_ids:
            examined += 1
            try:
                summary = ack_reconciliation.reconcile(int(raw_run_id))
                repaired += summary.repaired
                already_bound += summary.already_bound
                unresolved += summary.unresolved
                unresolved_exposure += summary.unresolved_exposure
            except Exception:
                logger.exception("Failover reconciliation failed for run_id=%r", raw_run_id)
                failed += 1
        metrics = {
            "examined": examined,
            "repaired": repaired,
            "already_bound": already_bound,
            "unresolved": unresolved,
            "unresolved_exposure": unresolved_exposure,
            "polled": 0,
            "folded": 0,
            "failed": failed,
        }
    else:
        run_limit = int(body.get("run_limit", ack_reconciliation.OPEN_RUN_REPAIR_BATCH))
        poll_limit = int(
            body.get("status_poll_limit", ack_reconciliation.BROKER_STATUS_POLL_BATCH)
        )
        try:
            open_summary = ack_reconciliation.reconcile_open_runs(
                run_limit=run_limit,
                status_poll_limit=poll_limit,
            )
            metrics = {
                "examined": open_summary.examined,
                "repaired": open_summary.repaired,
                "already_bound": open_summary.already_bound,
                "unresolved": open_summary.unresolved,
                "polled": open_summary.polled,
                "folded": open_summary.folded,
                "failed": open_summary.failed,
            }
        except Exception as exc:
            logger.exception("Failover open-run reconciliation encountered error")
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "reconciliation_failed",
                        "message": str(exc),
                    }
                ),
                500,
            )

    worm_record = _emit_internal_worm_safe(
        "cilium_egress_failover_reconciled",
        {
            "old_egress_ip": body.get("old_egress_ip") or body.get("previous_egress_ip"),
            "new_egress_ip": body.get("new_egress_ip") or body.get("active_egress_ip"),
            "reason": (
                body.get("reason")
                or body.get("failover_reason")
                or "cilium_egress_gateway_failover"
            ),
            "metrics": metrics,
        },
    )

    return (
        jsonify(
            {
                "status": "success",
                "event": "cilium_egress_failover_reconciled",
                "metrics": metrics,
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "timestamp_utc": worm_record.timestamp_utc,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )


def _default_parquet_export_path() -> str:
    app_dir = Path("/app")
    if app_dir.is_dir() and os.access(app_dir, os.W_OK):
        return "/app/tmp/historify_snapshot.parquet"
    return os.path.join(tempfile.gettempdir(), "historify_snapshot.parquet")


@internal_ops_bp.route("/historify/export-parquet", methods=["POST"])
def export_parquet_endpoint():
    """Trigger a lock-free DuckDB-to-Parquet snapshot export for Qlib research workers."""
    body: dict[str, Any] = request.get_json(silent=True) or {}
    output_path = str(body.get("output_path") or _default_parquet_export_path()).strip()

    try:
        snapshot = export_historify_parquet(
            output_path,
            db_path=body.get("db_path"),
            symbols=body.get("symbols"),
            exchange=body.get("exchange"),
            interval=body.get("interval"),
            start_timestamp=body.get("start_timestamp"),
            end_timestamp=body.get("end_timestamp"),
            presigned_url=body.get("presigned_url"),
        )
    except Exception as exc:
        logger.exception("Internal Parquet snapshot export failed")
        return (
            jsonify({"status": "error", "code": "export_failed", "message": str(exc)}),
            400,
        )

    worm_record = _emit_internal_worm_safe(
        "historify_parquet_exported",
        {
            "parquet_path": snapshot.parquet_path,
            "sha256": snapshot.sha256,
            "row_count": snapshot.row_count,
            "symbol_count": snapshot.symbol_count,
            "uploaded": snapshot.uploaded,
        },
    )

    return (
        jsonify(
            {
                "status": "success",
                "snapshot": snapshot.as_dict(),
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )


def _decode_token_metadata(token: str) -> tuple[str | None, str | None, str | None]:
    """Extract ``(jti, payload_typ, purpose)`` from an already-verified compact token."""
    try:
        parts = token.strip().split(".")
        payload_b64 = parts[1] if len(parts) == 3 else parts[0]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if not isinstance(payload, dict):
            return None, None, None
        raw_jti = payload.get("jti")
        raw_typ = payload.get("typ")
        raw_purpose = payload.get("purpose")
        return (
            str(raw_jti).strip() if raw_jti is not None and str(raw_jti).strip() else None,
            str(raw_typ).strip() if raw_typ is not None else None,
            str(raw_purpose).strip() if raw_purpose is not None else None,
        )
    except Exception:
        return None, None, None


def _emit_internal_worm_safe(event_type: str, payload: dict[str, Any]) -> WormAuditRecord:
    """Append WORM audit event, falling back to local LOG_DIR if /app/log is read-only in dev/tests."""
    try:
        return emit_worm_audit_event(event_type, payload)
    except OSError:
        fallback_dir = Path((os.getenv("LOG_DIR") or "log").strip() or "log")
        return WormAuditWriter(fallback_dir / "worm_audit.jsonl").append(event_type, payload)


@internal_ops_bp.route("/entitlements/sync", methods=["POST"])
def sync_entitlements():
    """Verify and hot-apply a signed Chirify Entitlement JWT into the running tenant pod."""
    auth_error = _require_internal_ops_auth()
    if auth_error is not None:
        return auth_error

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_payload",
                    "message": "Request body must be a JSON object.",
                }
            ),
            400,
        )

    token = str(body.get("entitlement_token") or "").strip()
    if not token:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "missing_entitlement_token",
                    "message": "entitlement_token is required.",
                }
            ),
            400,
        )

    secret = (os.getenv("CHIRIFY_ENTITLEMENT_SECRET") or "").strip()
    try:
        claims = chirify_live_gate.verify_entitlement_token(token, secret)
    except chirify_live_gate.EntitlementWrongTokenTypeError as exc:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "wrong_token_type",
                    "message": str(exc),
                }
            ),
            400,
        )
    except chirify_live_gate.EntitlementVerificationError as exc:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "entitlement_invalid",
                    "message": str(exc),
                }
            ),
            403,
        )

    token_jti, payload_typ, payload_purpose = _decode_token_metadata(token)
    if payload_typ == "CHIRIFY-SSO" or payload_purpose == "pod_sso":
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "wrong_token_type",
                    "message": "SSO launch tickets cannot be synced as entitlement tokens.",
                }
            ),
            400,
        )

    expected_tenant_id = (os.getenv("CHIRIFY_TENANT_ID") or "").strip()
    if expected_tenant_id:
        if not claims.tenant_id or not hmac.compare_digest(
            claims.tenant_id.encode("utf-8"),
            expected_tenant_id.encode("utf-8"),
        ):
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "tenant_mismatch",
                        "message": (
                            f"Entitlement token tenant_id {claims.tenant_id!r} does not match "
                            f"pod tenant_id {expected_tenant_id!r}."
                        ),
                    }
                ),
                403,
            )

    enforce_requested = body.get("enforce_live_gate")
    should_enable_gate = enforce_requested is True or (
        isinstance(enforce_requested, str) and is_truthy(enforce_requested)
    )

    with _ENTITLEMENT_SYNC_LOCK:
        os.environ["CHIRIFY_ENTITLEMENT_TOKEN"] = token
        if should_enable_gate:
            os.environ["CHIRIFY_ENFORCE_LIVE_GATE"] = "true"

    verdict = chirify_live_gate.evaluate_live_gate(claims)
    worm_record = _emit_internal_worm_safe(
        "chirify_entitlement_synced",
        {
            "jti": token_jti,
            "tenant_id": claims.tenant_id,
            "allowed": verdict.allowed,
            "code": verdict.code,
            "cohort": claims.cohort,
            "exchange_algo_id": claims.exchange_algo_id,
            "static_ip_verified": claims.static_ip_verified,
            "enforce_live_gate": chirify_live_gate.is_live_gate_enforced(),
            "entitlement_token": REDACTED_VALUE,
        },
    )

    return (
        jsonify(
            {
                "status": "ok",
                "tenant_id": claims.tenant_id,
                "live_gate": verdict.as_dict(),
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )


_KILL_SWITCH_LOCK = real_threading.Lock()


@internal_ops_bp.route("/compliance/kill-switch", methods=["POST"])
def toggle_compliance_kill_switch():
    """DORA Article 30 / SEBI emergency unconditional kill-switch endpoint."""
    auth_error = _require_internal_ops_auth()
    if auth_error is not None:
        return auth_error

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or (
        "engaged" not in body and "kill_switch_engaged" not in body
    ):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_payload",
                    "message": "Request body must be a JSON object containing boolean 'engaged' or 'kill_switch_engaged'.",
                }
            ),
            400,
        )

    raw_engaged = (
        body["engaged"] if "engaged" in body else body.get("kill_switch_engaged")
    )
    if isinstance(raw_engaged, bool):
        engaged = raw_engaged
    elif isinstance(raw_engaged, str) and raw_engaged.strip().lower() in {"true", "false"}:
        engaged = raw_engaged.strip().lower() == "true"
    else:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_engaged_flag",
                    "message": "Field 'engaged' must be a boolean (true or false).",
                }
            ),
            400,
        )

    default_reason = "dora_emergency_halt" if engaged else "dora_emergency_cleared"
    reason = str(body.get("reason") or default_reason).strip() or default_reason

    from datetime import UTC, datetime

    from database import settings_db
    from services.analyzer_service import apply_analyze_mode

    toggled_at_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    stopped_runs: list[int] = []
    stop_errors: list[dict[str, Any]] = []
    with _KILL_SWITCH_LOCK:
        settings_db.Base.metadata.create_all(settings_db.engine)
        if engaged:
            os.environ["CHIRIFY_EMERGENCY_KILL_SWITCH"] = "true"
            current_analyze_mode = bool(apply_analyze_mode(True))
            # Actively stop any running strategies so active threads cannot keep placing orders
            try:
                from services.strategy_module import engine as strat_engine
                from services.strategy_module import store as strat_store

                pod_user = _resolve_pod_username()
                running_rows = strat_store.list_strategies(pod_user, status="running")
                for row in running_rows or []:
                    run_id = row.get("current_run_id") if isinstance(row, dict) else getattr(row, "current_run_id", None)
                    if run_id:
                        try:
                            strat_engine.stop_run(int(run_id), pod_user, reason="dora_kill_switch")
                            stopped_runs.append(int(run_id))
                        except Exception as stop_exc:
                            stop_errors.append({"run_id": int(run_id), "error": str(stop_exc)})
            except Exception as list_exc:
                logger.debug(f"[InternalOps] Kill-switch strategy stop sweep skipped: {list_exc}")
        else:
            os.environ["CHIRIFY_EMERGENCY_KILL_SWITCH"] = "false"
            current_analyze_mode = bool(settings_db.get_analyze_mode())

    worm_record = _emit_internal_worm_safe(
        "chirify_emergency_kill_switch_toggled",
        {
            "priority": "CRITICAL" if engaged else "HIGH",
            "engaged": engaged,
            "reason": reason,
            "analyze_mode": current_analyze_mode,
            "stopped_runs": stopped_runs,
            "stop_errors": stop_errors,
            "timestamp_utc": toggled_at_utc,
            "tenant_id": (os.getenv("CHIRIFY_TENANT_ID") or "").strip() or None,
        },
    )

    return (
        jsonify(
            {
                "status": "ok",
                "event": "chirify_emergency_kill_switch_toggled",
                "engaged": engaged,
                "kill_switch_engaged": engaged,
                "reason": reason,
                "analyze_mode": current_analyze_mode,
                "stopped_runs": stopped_runs,
                "stop_errors": stop_errors,
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "timestamp_utc": worm_record.timestamp_utc,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )


# =============================================================================
# Pod Runtime Credentials & Active Tenant Helpers
# =============================================================================

_HIST_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9._:&/-]{0,47}$")
_OPT_UNDERLYING_RE = re.compile(r"^[A-Z0-9&-]{1,20}$")
_OPT_EXCHANGE_RE = re.compile(r"^[A-Z0-9_]{2,20}$")
_ORDER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_EXPIRY_NORMALIZE_RE = re.compile(r"^(\d{2})-?([A-Za-z]{3})-?(\d{2}|\d{4})$")


def _resolve_pod_username() -> str | None:
    """Resolve the active tenant admin username from ``user_db`` or ``auth_db``."""
    from database import auth_db, user_db

    try:
        user = user_db.find_user_by_username()
        if user is not None and getattr(user, "username", None):
            return str(user.username)
    except Exception:
        pass
    try:
        key_row = auth_db.ApiKeys.query.first()
        if key_row is not None and getattr(key_row, "user_id", None):
            return str(key_row.user_id)
    except Exception:
        pass
    return None


def _resolve_pod_api_key(username: str | None = None, *, provision_if_missing: bool = False) -> str | None:
    """Decrypt and return the active pod API key (never log its value)."""
    from database import auth_db

    resolved_user = username or _resolve_pod_username()
    if resolved_user:
        try:
            key = auth_db.get_api_key_for_tradingview(resolved_user)
            if key and auth_db.verify_api_key(str(key)):
                return str(key)
        except Exception:
            pass
        if provision_if_missing:
            try:
                auth_db.init_db()
                new_key = (os.getenv("CHIRIFY_POD_API_KEY") or "").strip() or secrets.token_hex(32)
                auth_db.upsert_api_key(resolved_user, new_key)
                return str(auth_db.get_api_key_for_tradingview(resolved_user) or new_key)
            except Exception:
                pass
    try:
        fallback = auth_db.get_first_available_api_key()
        if fallback and auth_db.verify_api_key(str(fallback)):
            return str(fallback)
    except Exception:
        pass
    return None


def _resolve_active_broker(username: str | None) -> str:
    from database import auth_db

    try:
        row = None
        if username:
            row = auth_db.Auth.query.filter_by(name=username, is_revoked=False).first()
        if row is None:
            row = auth_db.Auth.query.filter_by(is_revoked=False).first()
        if row is not None and getattr(row, "broker", None):
            return str(row.broker).strip()
    except Exception:
        pass
    return (os.getenv("BROKER_NAME") or "chirify_sandbox").strip() or "chirify_sandbox"


@internal_ops_bp.route("/pod/runtime-credentials", methods=["GET"])
def pod_runtime_credentials():
    """Return active pod runtime credentials & metadata for Control Plane bridging."""
    from sqlalchemy import distinct, func

    from database import settings_db
    from database import symbol as symbol_db
    from services.chirify_bootstrap_service import is_managed_pod

    username = _resolve_pod_username()
    if not username:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "pod_not_bootstrapped",
                    "message": "No tenant admin user has been provisioned on this pod.",
                }
            ),
            503,
        )

    api_key = _resolve_pod_api_key(username, provision_if_missing=True)
    if not api_key:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "api_key_unavailable",
                    "message": "Active OpenAlgo API key is unavailable.",
                }
            ),
            503,
        )

    tenant_id = (os.getenv("CHIRIFY_TENANT_ID") or "").strip() or "default"
    try:
        analyze_mode = bool(settings_db.get_analyze_mode())
    except Exception:
        analyze_mode = bool(is_managed_pod())

    broker = _resolve_active_broker(username)
    http_port = int(os.getenv("FLASK_PORT") or os.getenv("PORT") or 5000)
    ws_port = int(os.getenv("WEBSOCKET_PORT") or 8765)

    seeded_symbols_count = 0
    exchanges: list[str] = []
    try:
        seeded_symbols_count = int(
            symbol_db.db_session.query(func.count(symbol_db.SymToken.id)).scalar() or 0
        )
        exchanges = sorted(
            str(r[0])
            for r in symbol_db.db_session.query(distinct(symbol_db.SymToken.exchange))
            .filter(symbol_db.SymToken.exchange.isnot(None))
            .all()
            if r[0]
        )
    except Exception:
        seeded_symbols_count = 0
        exchanges = []

    return (
        jsonify(
            {
                "status": "success",
                "tenant_id": tenant_id,
                "username": username,
                "api_key": api_key,
                "analyze_mode": analyze_mode,
                "broker": broker,
                "http_port": http_port,
                "ws_port": ws_port,
                "exchanges": exchanges,
                "seeded_symbols_count": seeded_symbols_count,
            }
        ),
        200,
    )


# =============================================================================
# Historify DuckDB Time-Series Bridge (`catalog`, `candles`, `ingest`)
# =============================================================================


@internal_ops_bp.route("/historify/catalog", methods=["GET"])
def historify_catalog():
    """Return available symbol/exchange/interval ranges from Historify DuckDB."""
    from database import historify_db

    historify_db.init_database()
    items: list[dict[str, Any]] = []
    with historify_db.get_connection() as conn:
        rows = conn.execute(
            """
            SELECT symbol, exchange, interval,
                   COALESCE(record_count, 0) AS row_count,
                   COALESCE(first_timestamp, 0) AS first_ts,
                   COALESCE(last_timestamp, 0) AS last_ts
            FROM data_catalog
            ORDER BY exchange, symbol, interval
            """
        ).fetchall()
        if not rows:
            rows = conn.execute(
                """
                SELECT symbol, exchange, interval,
                       COUNT(*) AS row_count,
                       COALESCE(MIN(timestamp), 0) AS first_ts,
                       COALESCE(MAX(timestamp), 0) AS last_ts
                FROM market_data
                GROUP BY symbol, exchange, interval
                ORDER BY exchange, symbol, interval
                """
            ).fetchall()

    for sym, ex, iv, cnt, first_ts, last_ts in rows:
        items.append(
            {
                "symbol": str(sym),
                "exchange": str(ex),
                "interval": str(iv),
                "row_count": int(cnt or 0),
                "first_ts": int(first_ts or 0),
                "last_ts": int(last_ts or 0),
            }
        )

    total_rows = sum(item["row_count"] for item in items)
    return (
        jsonify(
            {
                "status": "success",
                "total_rows": total_rows,
                "items": items,
            }
        ),
        200,
    )


def _parse_optional_epoch_param(name: str, raw: str | None) -> tuple[int | None, str | None]:
    if raw is None or not str(raw).strip():
        return None, None
    try:
        val = int(str(raw).strip())
    except ValueError:
        return None, f"Query parameter '{name}' must be an integer epoch."
    if val <= 0:
        return None, f"Query parameter '{name}' must be a positive integer."
    return val, None


@internal_ops_bp.route("/historify/candles", methods=["GET"])
def historify_candles():
    """Return ascending OHLCV candles from Historify DuckDB (supports aggregation)."""
    from database import historify_db
    from utils.constants import VALID_EXCHANGES

    symbol = str(request.args.get("symbol") or "").strip().upper()
    exchange = str(request.args.get("exchange") or "").strip().upper()
    interval = str(request.args.get("interval") or "D").strip()
    if interval in ("1d", "1D", "day", "DAY"):
        interval = "D"

    if not symbol or not _HIST_SYMBOL_RE.match(symbol):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_symbol",
                    "message": "Valid 'symbol' query parameter is required.",
                }
            ),
            400,
        )
    if not exchange or exchange not in VALID_EXCHANGES:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_exchange",
                    "message": f"Exchange {exchange!r} is not supported.",
                }
            ),
            400,
        )
    if interval not in historify_db.STORAGE_INTERVALS and historify_db.parse_interval(interval) is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_interval",
                    "message": f"Interval {interval!r} is not supported.",
                }
            ),
            400,
        )

    raw_limit = request.args.get("limit", "500")
    try:
        limit = int(str(raw_limit).strip())
    except ValueError:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_limit",
                    "message": "Parameter 'limit' must be a positive integer.",
                }
            ),
            400,
        )
    if limit <= 0:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_limit",
                    "message": "Parameter 'limit' must be >= 1.",
                }
            ),
            400,
        )
    limit = min(limit, 5000)

    start_ts, err = _parse_optional_epoch_param("start_timestamp", request.args.get("start_timestamp"))
    if err:
        return jsonify({"status": "error", "code": "invalid_timestamp", "message": err}), 400
    end_ts, err = _parse_optional_epoch_param("end_timestamp", request.args.get("end_timestamp"))
    if err:
        return jsonify({"status": "error", "code": "invalid_timestamp", "message": err}), 400

    historify_db.init_database()
    df = historify_db.get_ohlcv(
        symbol=symbol,
        exchange=exchange,
        interval=interval,
        start_timestamp=start_ts,
        end_timestamp=end_ts,
    )
    if (df is None or df.empty) and interval.upper() not in ("D", "1D", "W", "M"):
        daily_df = historify_db.get_ohlcv(
            symbol=symbol,
            exchange=exchange,
            interval="D",
            start_timestamp=start_ts,
            end_timestamp=end_ts,
        )
        if daily_df is not None and not daily_df.empty:
            from broker.chirify_sandbox.api.data import _synthesize_intraday_from_daily

            df = _synthesize_intraday_from_daily(daily_df, symbol, exchange, interval)
            if start_ts is not None and not df.empty:
                df = df[df["timestamp"] >= start_ts]
            if end_ts is not None and not df.empty:
                df = df[df["timestamp"] <= end_ts]

    candles: list[dict[str, Any]] = []
    if df is not None and not df.empty:
        ordered = df.sort_values("timestamp").tail(limit)
        for row in ordered.to_dict(orient="records"):
            raw_oi = row.get("oi")
            try:
                oi_val = float(raw_oi) if raw_oi is not None and math.isfinite(float(raw_oi)) else 0.0
            except (TypeError, ValueError):
                oi_val = 0.0
            candles.append(
                {
                    "timestamp": int(row["timestamp"]),
                    "open": float(row["open"]),
                    "high": float(row["high"]),
                    "low": float(row["low"]),
                    "close": float(row["close"]),
                    "volume": float(row["volume"]),
                    "oi": oi_val,
                }
            )

    return (
        jsonify(
            {
                "status": "success",
                "symbol": symbol,
                "exchange": exchange,
                "interval": interval,
                "candles": candles,
            }
        ),
        200,
    )


def _strict_finite_float(val: Any, field: str, idx: int) -> tuple[float | None, str | None]:
    if isinstance(val, bool) or val is None:
        return None, f"candles[{idx}].{field} must be a finite number."
    try:
        parsed = float(val)
    except (TypeError, ValueError):
        return None, f"candles[{idx}].{field} must be a finite number."
    if not math.isfinite(parsed):
        return None, f"candles[{idx}].{field} must be finite."
    return parsed, None


@internal_ops_bp.route("/historify/ingest", methods=["POST"])
def historify_ingest():
    """Validate and atomically upsert OHLCV candles into Historify DuckDB."""
    from database import historify_db
    from utils.constants import VALID_EXCHANGES

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_payload",
                    "message": "Request body must be a JSON object.",
                }
            ),
            400,
        )

    symbol = str(body.get("symbol") or "").strip().upper()
    exchange = str(body.get("exchange") or "").strip().upper()
    interval = str(body.get("interval") or "").strip()
    if interval in ("1d", "1D", "day", "DAY"):
        interval = "D"

    if not symbol or not _HIST_SYMBOL_RE.match(symbol):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_symbol",
                    "message": f"Invalid symbol {symbol!r}.",
                }
            ),
            400,
        )
    if not exchange or exchange not in VALID_EXCHANGES:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_exchange",
                    "message": f"Unsupported exchange {exchange!r}.",
                }
            ),
            400,
        )
    if not interval or (
        interval not in historify_db.STORAGE_INTERVALS
        and historify_db.parse_interval(interval) is None
    ):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_interval",
                    "message": f"Unsupported interval {interval!r}.",
                }
            ),
            400,
        )

    raw_candles = body.get("candles")
    if not isinstance(raw_candles, list) or not raw_candles:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_candles",
                    "message": "'candles' must be a non-empty list of OHLCV objects.",
                }
            ),
            400,
        )
    if len(raw_candles) > 50_000:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "batch_too_large",
                    "message": "Maximum 50,000 candles per ingest request.",
                }
            ),
            400,
        )

    cleaned_rows: list[dict[str, Any]] = []
    for idx, c in enumerate(raw_candles):
        if not isinstance(c, dict):
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_candle",
                        "message": f"candles[{idx}] must be an object.",
                    }
                ),
                400,
            )

        raw_ts = c.get("timestamp")
        if isinstance(raw_ts, bool) or raw_ts is None:
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_timestamp",
                        "message": f"candles[{idx}].timestamp must be a positive integer.",
                    }
                ),
                400,
            )
        try:
            ts_f = float(raw_ts)
            if not math.isfinite(ts_f) or ts_f <= 0 or ts_f != int(ts_f):
                raise ValueError("not positive integer")
            ts_i = int(ts_f)
            if ts_i > 100_000_000_000:
                ts_i = ts_i // 1000
        except (TypeError, ValueError):
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_timestamp",
                        "message": f"candles[{idx}].timestamp must be a positive integer.",
                    }
                ),
                400,
            )

        o_v, err = _strict_finite_float(c.get("open"), "open", idx)
        if err:
            return jsonify({"status": "error", "code": "invalid_ohlc", "message": err}), 400
        h_v, err = _strict_finite_float(c.get("high"), "high", idx)
        if err:
            return jsonify({"status": "error", "code": "invalid_ohlc", "message": err}), 400
        l_v, err = _strict_finite_float(c.get("low"), "low", idx)
        if err:
            return jsonify({"status": "error", "code": "invalid_ohlc", "message": err}), 400
        c_v, err = _strict_finite_float(c.get("close"), "close", idx)
        if err:
            return jsonify({"status": "error", "code": "invalid_ohlc", "message": err}), 400
        vol_v, err = _strict_finite_float(c.get("volume"), "volume", idx)
        if err:
            return jsonify({"status": "error", "code": "invalid_ohlc", "message": err}), 400
        oi_v, err = _strict_finite_float(c.get("oi", 0), "oi", idx)
        if err:
            return jsonify({"status": "error", "code": "invalid_ohlc", "message": err}), 400

        assert o_v is not None and h_v is not None and l_v is not None and c_v is not None
        assert vol_v is not None and oi_v is not None

        if o_v <= 0 or h_v <= 0 or l_v <= 0 or c_v <= 0:
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_ohlc",
                        "message": f"candles[{idx}] OHLC prices must be strictly positive.",
                    }
                ),
                400,
            )
        if h_v < l_v or h_v < o_v or h_v < c_v or l_v > o_v or l_v > c_v:
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_ohlc",
                        "message": f"candles[{idx}] violates OHLC ordering (low <= open,close <= high).",
                    }
                ),
                400,
            )
        if vol_v < 0 or oi_v < 0:
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_ohlc",
                        "message": f"candles[{idx}] volume and oi must be non-negative.",
                    }
                ),
                400,
            )

        cleaned_rows.append(
            {
                "timestamp": ts_i,
                "open": o_v,
                "high": h_v,
                "low": l_v,
                "close": c_v,
                "volume": int(round(vol_v)),
                "oi": int(round(oi_v)),
            }
        )

    df = pd.DataFrame(
        cleaned_rows,
        columns=["timestamp", "open", "high", "low", "close", "volume", "oi"],
    )
    df["timestamp"] = df["timestamp"].astype("int64")
    df["volume"] = df["volume"].astype("int64")
    df["oi"] = df["oi"].astype("int64")
    df = df.drop_duplicates(subset=["timestamp"], keep="last").sort_values("timestamp").reset_index(drop=True)

    historify_db.init_database()
    upserted = historify_db.upsert_market_data(df, symbol=symbol, exchange=exchange, interval=interval)

    return (
        jsonify(
            {
                "status": "success",
                "upserted": int(upserted),
            }
        ),
        200,
    )


# =============================================================================
# Durable Strategy RMS Internal Bridge (`/internal/v1/strategies*`)
# =============================================================================


def _init_strategy_store():
    from database import strategy_module_db as store

    store.init_db()
    return store


@internal_ops_bp.route("/strategies", methods=["GET"])
def internal_list_strategies():
    """List durable Strategy RMS strategies for the pod's tenant owner."""
    username = _resolve_pod_username()
    if not username:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "pod_not_bootstrapped",
                    "message": "No tenant user provisioned.",
                }
            ),
            503,
        )

    store = _init_strategy_store()
    status_filter = (request.args.get("status") or "").strip() or None
    if status_filter and status_filter not in store.STRATEGY_STATUSES:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_status",
                    "message": f"Unknown strategy status {status_filter!r}.",
                }
            ),
            400,
        )
    q = (request.args.get("q") or "").strip()[:100] or None
    rows = store.list_strategies(username, status=status_filter, q=q)
    return (
        jsonify(
            {
                "status": "success",
                "strategies": rows,
                "data": rows,
                "count": len(rows),
            }
        ),
        200,
    )


@internal_ops_bp.route("/strategies", methods=["POST"])
def internal_create_strategy():
    """Validate and persist a new durable Strategy RMS definition."""
    from blueprints.strategy_module import validate_strategy_config

    username = _resolve_pod_username()
    if not username:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "pod_not_bootstrapped",
                    "message": "No tenant user provisioned.",
                }
            ),
            503,
        )

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_payload",
                    "message": "Request body must be a JSON object.",
                }
            ),
            400,
        )

    config, err_msg = validate_strategy_config(body)
    if err_msg or config is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_strategy_config",
                    "message": err_msg or "Invalid strategy configuration.",
                }
            ),
            400,
        )

    store = _init_strategy_store()
    created, store_err = store.create_strategy(username, config)
    if store_err or created is None:
        code = 409 if store_err and "already" in store_err.lower() else 500
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "strategy_create_failed",
                    "message": store_err or "Failed to create strategy.",
                }
            ),
            code,
        )

    webhook_token = created.pop("webhook_token", None)
    masked = (
        f"{webhook_token[:9]}...{webhook_token[-4:]}"
        if isinstance(webhook_token, str) and len(webhook_token) > 13
        else None
    )

    try:
        store.record_event(
            created["id"],
            username,
            "strategy_created",
            f"Strategy '{created['name']}' created via internal ops bridge",
        )
    except Exception:
        pass

    worm_record = _emit_internal_worm_safe(
        "chirify_strategy_created",
        {
            "strategy_id": created["id"],
            "name": created["name"],
            "underlying": created["underlying"],
            "legs_count": len(created.get("legs", [])),
            "webhook_token": REDACTED_VALUE,
        },
    )

    return (
        jsonify(
            {
                "status": "success",
                "strategy": created,
                "data": created,
                "webhook_token_issued": bool(webhook_token),
                "webhook_token_masked": masked,
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        201,
    )


@internal_ops_bp.route("/strategies/<int:strategy_id>/<action>", methods=["POST"])
def internal_strategy_action(strategy_id: int, action: str):
    """Execute ``start``, ``stop``, or ``close_all`` on a durable Strategy RMS strategy."""
    clean_action = (action or "").strip().lower()
    if clean_action not in {"start", "stop", "close_all"}:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_action",
                    "message": f"Action must be 'start', 'stop', or 'close_all'; got {action!r}.",
                }
            ),
            400,
        )

    username = _resolve_pod_username()
    if not username:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "pod_not_bootstrapped",
                    "message": "No tenant user provisioned.",
                }
            ),
            503,
        )

    store = _init_strategy_store()
    row = store.get_strategy(strategy_id, username)
    if row is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "strategy_not_found",
                    "message": f"Strategy {strategy_id} not found.",
                }
            ),
            404,
        )

    # Lazy import avoids circular dependency with order dispatch
    from services.strategy_module import engine

    if clean_action == "start":
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_mode",
                        "message": "Request body must specify explicit mode ('sandbox' or 'live').",
                    }
                ),
                400,
            )
        raw_mode = body.get("mode")
        mode = str(raw_mode).strip().lower() if isinstance(raw_mode, str) else ""
        if mode not in {"sandbox", "live"}:
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_mode",
                        "message": "Explicit mode ('sandbox' or 'live') is required on start.",
                    }
                ),
                400,
            )

        if chirify_live_gate.is_emergency_kill_switch_engaged():
            _emit_internal_worm_safe(
                "chirify_strategy_start_blocked",
                {
                    "strategy_id": strategy_id,
                    "mode": mode,
                    "reason": "emergency_kill_switch_engaged",
                },
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "emergency_kill_switch_engaged",
                        "message": "Emergency kill switch is engaged; strategy execution is blocked across Sandbox and Live.",
                    }
                ),
                403,
            )

        if mode == "live":
            active_broker = _resolve_active_broker(username)
            verdict = chirify_live_gate.check_live_mode_transition(
                current_mode=True,
                target_mode=False,
                broker=active_broker,
            )
            if not verdict.allowed:
                _emit_internal_worm_safe(
                    "chirify_strategy_start_blocked",
                    {
                        "strategy_id": strategy_id,
                        "mode": "live",
                        "code": verdict.code,
                        "reasons": list(verdict.reasons),
                    },
                )
                return (
                    jsonify(
                        {
                            "status": "error",
                            "code": verdict.code,
                            "message": verdict.message,
                            "reasons": list(verdict.reasons),
                        }
                    ),
                    403,
                )

            if not row.live_enabled:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "code": "strategy_live_disabled",
                            "message": "Strategy is not enabled for live trading.",
                        }
                    ),
                    409,
                )

        result = engine.start_run(strategy_id, username, mode, trigger_source="manual")
        if not result.ok:
            err_lower = str(result.error or "").lower()
            status_code = 409 if "already running" in err_lower else 400
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "start_failed",
                        "message": result.error or "Failed to start strategy.",
                        "run_id": result.run_id,
                        "legs": result.legs,
                    }
                ),
                status_code,
            )

        worm_record = _emit_internal_worm_safe(
            "chirify_strategy_started",
            {
                "strategy_id": strategy_id,
                "run_id": result.run_id,
                "mode": mode,
                "legs_count": len(result.legs or []),
            },
        )
        return (
            jsonify(
                {
                    "status": "success",
                    "action": "start",
                    "strategy_id": strategy_id,
                    "run_id": result.run_id,
                    "mode": mode,
                    "legs": result.legs,
                    "worm_audit": {
                        "seq_no": worm_record.seq_no,
                        "record_hash": worm_record.record_hash,
                    },
                }
            ),
            200,
        )

    # stop or close_all
    run_id = row.current_run_id
    if not run_id:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "strategy_not_running",
                    "message": "This strategy is not currently running.",
                }
            ),
            409,
        )

    if clean_action == "close_all":
        try:
            store.record_event(
                strategy_id,
                username,
                "close_all_manual",
                "Manual close-all requested via internal ops bridge",
                run_id=run_id,
            )
        except Exception:
            pass

    stop_result = engine.stop_run(run_id, username, reason="manual")
    if not stop_result.get("ok"):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "stop_failed",
                    "message": stop_result.get("error") or "Failed to stop strategy run.",
                    "stop_pending": bool(stop_result.get("stop_pending", False)),
                    "exits": stop_result.get("exits", []),
                }
            ),
            409,
        )

    event_name = "chirify_strategy_close_all" if clean_action == "close_all" else "chirify_strategy_stopped"
    worm_record = _emit_internal_worm_safe(
        event_name,
        {
            "strategy_id": strategy_id,
            "run_id": run_id,
            "stop_pending": bool(stop_result.get("stop_pending", False)),
            "exits_count": len(stop_result.get("exits", [])),
        },
    )
    return (
        jsonify(
            {
                "status": "success",
                "action": clean_action,
                "strategy_id": strategy_id,
                "run_id": run_id,
                "stop_pending": bool(stop_result.get("stop_pending", False)),
                "exits": stop_result.get("exits", []),
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )


@internal_ops_bp.route("/strategies/<int:strategy_id>/runs", methods=["GET"])
def internal_strategy_runs(strategy_id: int):
    username = _resolve_pod_username()
    if not username:
        return jsonify({"status": "error", "code": "pod_not_bootstrapped", "message": "No tenant user provisioned."}), 503
    store = _init_strategy_store()
    if store.get_strategy(strategy_id, username) is None:
        return jsonify({"status": "error", "code": "strategy_not_found", "message": f"Strategy {strategy_id} not found."}), 404
    try:
        limit = max(1, min(500, int(request.args.get("limit", "100"))))
    except ValueError:
        return jsonify({"status": "error", "code": "invalid_limit", "message": "limit must be an integer."}), 400
    runs = store.list_runs(strategy_id, limit=limit)
    return jsonify({"status": "success", "strategy_id": strategy_id, "runs": runs, "data": runs}), 200


@internal_ops_bp.route("/strategies/<int:strategy_id>/orders", methods=["GET"])
def internal_strategy_orders(strategy_id: int):
    username = _resolve_pod_username()
    if not username:
        return jsonify({"status": "error", "code": "pod_not_bootstrapped", "message": "No tenant user provisioned."}), 503
    store = _init_strategy_store()
    if store.get_strategy(strategy_id, username) is None:
        return jsonify({"status": "error", "code": "strategy_not_found", "message": f"Strategy {strategy_id} not found."}), 404
    run_id_raw = request.args.get("run_id")
    run_id: int | None = None
    if run_id_raw is not None and str(run_id_raw).strip():
        try:
            run_id = int(str(run_id_raw).strip())
        except ValueError:
            return jsonify({"status": "error", "code": "invalid_run_id", "message": "run_id must be an integer."}), 400
    orders = store.list_orders_for_strategy(strategy_id, run_id=run_id)
    return jsonify({"status": "success", "strategy_id": strategy_id, "orders": orders, "data": orders}), 200


@internal_ops_bp.route("/strategies/<int:strategy_id>/events", methods=["GET"])
def internal_strategy_events(strategy_id: int):
    username = _resolve_pod_username()
    if not username:
        return jsonify({"status": "error", "code": "pod_not_bootstrapped", "message": "No tenant user provisioned."}), 503
    store = _init_strategy_store()
    if store.get_strategy(strategy_id, username) is None:
        return jsonify({"status": "error", "code": "strategy_not_found", "message": f"Strategy {strategy_id} not found."}), 404
    run_id_raw = request.args.get("run_id")
    run_id: int | None = None
    if run_id_raw is not None and str(run_id_raw).strip():
        try:
            run_id = int(str(run_id_raw).strip())
        except ValueError:
            return jsonify({"status": "error", "code": "invalid_run_id", "message": "run_id must be an integer."}), 400
    kind = (request.args.get("kind") or "").strip() or None
    if kind and hasattr(store, "EVENT_KINDS") and kind not in store.EVENT_KINDS:
        return jsonify({"status": "error", "code": "invalid_kind", "message": f"Unknown event kind {kind!r}."}), 400
    severity = (request.args.get("severity") or "").strip() or None
    if severity and hasattr(store, "EVENT_SEVERITIES") and severity not in store.EVENT_SEVERITIES:
        return jsonify({"status": "error", "code": "invalid_severity", "message": f"Unknown severity {severity!r}."}), 400
    try:
        limit = max(1, min(1000, int(request.args.get("limit", "500"))))
    except ValueError:
        return jsonify({"status": "error", "code": "invalid_limit", "message": "limit must be an integer."}), 400
    events = store.list_events(strategy_id, run_id=run_id, kind=kind, severity=severity, limit=limit)
    return jsonify({"status": "success", "strategy_id": strategy_id, "events": events, "data": events}), 200


# =============================================================================
# Options Analytics Bridge (`GET /internal/v1/options/analytics`)
# =============================================================================


def _normalize_expiry_pair(raw: str) -> tuple[str, str] | None:
    """Convert ``26NOV26`` / ``26-NOV-26`` / ``26-NOV-2026`` into ``('26NOV26', '26-NOV-26')``."""
    m = _EXPIRY_NORMALIZE_RE.match((raw or "").strip().upper())
    if not m:
        return None
    dd, mmm, yy_raw = m.groups()
    yy = yy_raw[-2:]
    return f"{dd}{mmm}{yy}", f"{dd}-{mmm}-{yy}"


def _parse_expiry_date_obj(raw: str) -> datetime | None:
    pair = _normalize_expiry_pair(raw)
    if pair is None:
        return None
    try:
        return datetime.strptime(pair[0], "%d%b%y")
    except ValueError:
        return None


def _compute_max_pain(chain_rows: list[dict[str, Any]]) -> float:
    if not chain_rows:
        return 0.0
    strikes = [float(r["strike"]) for r in chain_rows]
    best_strike = strikes[0]
    best_pain: float | None = None
    for candidate in strikes:
        pain = 0.0
        for r in chain_rows:
            k_i = float(r["strike"])
            if k_i < candidate:
                pain += (candidate - k_i) * int(r["ce_oi"])
            elif k_i > candidate:
                pain += (k_i - candidate) * int(r["pe_oi"])
        if best_pain is None or pain < best_pain:
            best_pain = pain
            best_strike = candidate
    return float(best_strike)


@internal_ops_bp.route("/options/analytics", methods=["GET"])
def internal_options_analytics():
    """Return real Option Chain, Black-76 Greeks, GEX Profile, IV Smile, PCR & Max Pain."""
    from broker.chirify_sandbox.api.data import get_sandbox_market_feed
    from database import historify_db
    from database import symbol as symbol_db
    from database.symbol import SymToken
    from services import option_chain_service, option_greeks_service, quotes_service
    from utils import black_scholes

    underlying = str(request.args.get("underlying") or "NIFTY").strip().upper()
    exchange = str(request.args.get("exchange") or "NFO").strip().upper()
    raw_expiry = str(request.args.get("expiry") or "").strip()

    if not _OPT_UNDERLYING_RE.match(underlying):
        return jsonify({"status": "error", "code": "invalid_underlying", "message": f"Invalid underlying {underlying!r}."}), 400
    if not _OPT_EXCHANGE_RE.match(exchange):
        return jsonify({"status": "error", "code": "invalid_exchange", "message": f"Invalid exchange {exchange!r}."}), 400

    try:
        strike_count = max(1, min(50, int(request.args.get("strike_count", "15"))))
    except ValueError:
        return jsonify({"status": "error", "code": "invalid_strike_count", "message": "strike_count must be an integer."}), 400

    options_exchange = {
        "NSE": "NFO",
        "NSE_INDEX": "NFO",
        "BSE": "BFO",
        "BSE_INDEX": "BFO",
    }.get(exchange, exchange)

    quote_exchange = (
        "NSE_INDEX"
        if underlying in {"NIFTY", "BANKNIFTY", "FINNIFTY", "MIDCPNIFTY"}
        else ("BSE_INDEX" if underlying in {"SENSEX", "BANKEX"} else "NSE")
    )

    # 1. Resolve expiry from query param or nearest available SymToken expiry >= today
    expiry_sym: str | None = None
    expiry_db: str | None = None
    if raw_expiry:
        pair = _normalize_expiry_pair(raw_expiry)
        if pair is None:
            return jsonify({"status": "error", "code": "invalid_expiry", "message": f"Invalid expiry format {raw_expiry!r}."}), 400
        expiry_sym, expiry_db = pair
    else:
        try:
            exact_opt_prefix_re = re.compile(rf"^{re.escape(underlying)}\d{{2}}[A-Z]{{3}}\d{{2}}")
            exp_rows = (
                symbol_db.db_session.query(SymToken.symbol, SymToken.expiry)
                .filter(
                    SymToken.exchange == options_exchange,
                    SymToken.symbol.like(f"{underlying}%"),
                    SymToken.instrumenttype.in_(["CE", "PE", "OPTIDX", "OPTSTK"]),
                    SymToken.expiry.isnot(None),
                    SymToken.expiry != "",
                )
                .distinct()
                .all()
            )
            seen_expiries: set[str] = set()
            parsed_expiries: list[tuple[datetime, str, str]] = []
            for raw_sym, raw_e in exp_rows:
                if not exact_opt_prefix_re.match(str(raw_sym or "").upper()):
                    continue
                exp_str = str(raw_e)
                if exp_str in seen_expiries:
                    continue
                seen_expiries.add(exp_str)
                pair = _normalize_expiry_pair(exp_str)
                dt_obj = _parse_expiry_date_obj(exp_str)
                if pair and dt_obj:
                    parsed_expiries.append((dt_obj, pair[0], pair[1]))
            parsed_expiries.sort(key=lambda item: item[0])
            today_naive = datetime.now(UTC).replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
            future = [item for item in parsed_expiries if item[0] >= today_naive]
            chosen = future[0] if future else (parsed_expiries[-1] if parsed_expiries else None)
            if chosen is not None:
                expiry_sym, expiry_db = chosen[1], chosen[2]
        except Exception as exc:
            logger.debug(f"[OptionsAnalytics] Expiry lookup failed: {exc}")

    if not expiry_sym or not expiry_db:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "no_option_contracts",
                    "message": f"No option contracts found for {underlying} on {options_exchange}.",
                }
            ),
            404,
        )

    # 2. Load contracts from SymToken for this underlying + expiry
    contracts = (
        symbol_db.db_session.query(SymToken)
        .filter(
            SymToken.exchange == options_exchange,
            SymToken.expiry == expiry_db,
            SymToken.symbol.like(f"{underlying}{expiry_sym}%"),
            SymToken.instrumenttype.in_(["CE", "PE"]),
        )
        .all()
    )
    if not contracts:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "no_option_contracts",
                    "message": f"No CE/PE contracts found for {underlying} expiry {expiry_sym} on {options_exchange}.",
                }
            ),
            404,
        )

    # 3. Resolve underlying spot price
    api_key = _resolve_pod_api_key()
    spot_price = 0.0
    if api_key:
        try:
            ok_q, q_resp, _ = quotes_service.get_quotes(
                symbol=underlying,
                exchange=quote_exchange,
                api_key=api_key,
            )
            if ok_q and isinstance(q_resp, dict):
                spot_price = float((q_resp.get("data") or {}).get("ltp") or 0.0)
        except Exception:
            spot_price = 0.0

    if spot_price <= 0:
        try:
            df_spot = historify_db.get_ohlcv(underlying, quote_exchange, "D")
            if df_spot is not None and not df_spot.empty:
                spot_price = float(df_spot["close"].iloc[-1])
        except Exception:
            spot_price = 0.0

    if spot_price <= 0:
        try:
            spot_price = float(get_sandbox_market_feed().get_quote(underlying, quote_exchange).get("ltp") or 0.0)
        except Exception:
            spot_price = 0.0

    strikes_all = sorted({float(c.strike) for c in contracts if c.strike and float(c.strike) > 0})
    if spot_price <= 0 and strikes_all:
        spot_price = strikes_all[len(strikes_all) // 2]

    # 4. Try primary OpenAlgo option_chain_service (already backed by pure-Python Black-76)
    chain_by_strike: dict[float, dict[str, Any]] = {}
    lot_size = int(contracts[0].lotsize or 1)
    if api_key:
        try:
            ok_oc, oc_resp, _ = option_chain_service.get_option_chain(
                underlying=underlying,
                exchange=options_exchange,
                expiry_date=expiry_sym,
                strike_count=strike_count,
                api_key=api_key,
                with_quotes=True,
                with_greeks=True,
            )
            if ok_oc and isinstance(oc_resp, dict):
                if float(oc_resp.get("underlying_ltp") or 0.0) > 0:
                    spot_price = float(oc_resp["underlying_ltp"])
                for entry in oc_resp.get("chain") or []:
                    k = float(entry.get("strike") or 0.0)
                    if k > 0:
                        chain_by_strike[k] = entry
        except Exception as exc:
            logger.debug(f"[OptionsAnalytics] option_chain_service fallback engaged: {exc}")

    # Organize SymToken contracts by strike for guaranteed completeness & fallback pricing
    by_strike_contracts: dict[float, dict[str, SymToken]] = {}
    for c in contracts:
        k = float(c.strike or 0.0)
        if k <= 0:
            continue
        opt_t = str(c.instrumenttype or "").upper()
        if opt_t in ("CE", "PE"):
            by_strike_contracts.setdefault(k, {})[opt_t] = c

    # Select strikes centered around ATM
    atm_strike = min(strikes_all, key=lambda k: abs(k - spot_price))
    atm_idx = strikes_all.index(atm_strike)
    lo_idx = max(0, atm_idx - strike_count)
    hi_idx = min(len(strikes_all), atm_idx + strike_count + 1)
    selected_strikes = strikes_all[lo_idx:hi_idx]

    expiry_dt = option_greeks_service.get_expiry_datetime(expiry_sym, options_exchange)
    t_years, _ = option_greeks_service.calculate_time_to_expiry(expiry_dt)
    if t_years <= 0:
        t_years = 1.0 / 365.0
    rate_dec = float(option_greeks_service.DEFAULT_INTEREST_RATES.get(options_exchange, 0.0)) / 100.0
    feed = get_sandbox_market_feed()

    def _hydrate_leg(strike: float, opt_type: str, oc_leg: dict[str, Any] | None) -> dict[str, Any]:
        contract = by_strike_contracts.get(strike, {}).get(opt_type)
        sym = (
            (oc_leg.get("symbol") if isinstance(oc_leg, dict) else None)
            or (contract.symbol if contract is not None else f"{underlying}{expiry_sym}{int(strike)}{opt_type}")
        )
        ltp = float(oc_leg.get("ltp") or 0.0) if isinstance(oc_leg, dict) else 0.0
        oi = int(oc_leg.get("oi") or 0) if isinstance(oc_leg, dict) else 0
        if ltp <= 0.0 or oi <= 0:
            q = feed.get_quote(sym, options_exchange)
            if ltp <= 0.0:
                ltp = float(q.get("ltp") or 0.0)
            if oi <= 0:
                oi = int(q.get("oi") or 0)

        raw_iv = (
            (oc_leg.get("implied_volatility") if oc_leg.get("implied_volatility") is not None else oc_leg.get("iv"))
            if isinstance(oc_leg, dict)
            else None
        )
        iv_val = float(raw_iv or 0.0)
        delta_val = float(oc_leg.get("delta") or 0.0) if isinstance(oc_leg, dict) else 0.0
        gamma_val = float(oc_leg.get("gamma") or 0.0) if isinstance(oc_leg, dict) else 0.0
        theta_val = float(oc_leg.get("theta") or 0.0) if isinstance(oc_leg, dict) else 0.0
        vega_val = float(oc_leg.get("vega") or 0.0) if isinstance(oc_leg, dict) else 0.0

        # Ensure genuine Black-76 Greeks are populated even when option_chain_service fallback ran
        if iv_val <= 0.0 or gamma_val == 0.0:
            flag = "c" if opt_type == "CE" else "p"
            try:
                sigma = black_scholes.implied_volatility(ltp, spot_price, strike, rate_dec, t_years, flag)
            except Exception:
                sigma = 0.16
            iv_val = round(sigma * 100.0, 2)
            delta_val = round(black_scholes.delta(flag, spot_price, strike, t_years, rate_dec, sigma), 4)
            gamma_val = round(black_scholes.gamma(flag, spot_price, strike, t_years, rate_dec, sigma), 6)
            theta_val = round(black_scholes.theta(flag, spot_price, strike, t_years, rate_dec, sigma), 4)
            vega_val = round(black_scholes.vega(flag, spot_price, strike, t_years, rate_dec, sigma), 4)

        return {
            "symbol": str(sym),
            "ltp": round(float(ltp), 2),
            "iv": round(float(iv_val), 2),
            "oi": int(oi),
            "delta": round(float(delta_val), 4),
            "gamma": round(float(gamma_val), 6),
            "theta": round(float(theta_val), 4),
            "vega": round(float(vega_val), 4),
        }

    chain: list[dict[str, Any]] = []
    gex_profile: list[dict[str, Any]] = []
    iv_smile: list[dict[str, Any]] = []

    for strike in selected_strikes:
        oc_entry = chain_by_strike.get(strike) or {}
        ce = _hydrate_leg(strike, "CE", oc_entry.get("ce"))
        pe = _hydrate_leg(strike, "PE", oc_entry.get("pe"))

        chain.append(
            {
                "strike": float(strike),
                "ce_symbol": ce["symbol"],
                "ce_ltp": ce["ltp"],
                "ce_iv": ce["iv"],
                "ce_oi": ce["oi"],
                "ce_delta": ce["delta"],
                "ce_gamma": ce["gamma"],
                "ce_theta": ce["theta"],
                "ce_vega": ce["vega"],
                "pe_symbol": pe["symbol"],
                "pe_ltp": pe["ltp"],
                "pe_iv": pe["iv"],
                "pe_oi": pe["oi"],
                "pe_delta": pe["delta"],
                "pe_gamma": pe["gamma"],
                "pe_theta": pe["theta"],
                "pe_vega": pe["vega"],
            }
        )

        # Note: NFO/broker OI is already denominated in contract units (lots * lot_size)
        call_gex = round(ce["gamma"] * ce["oi"], 2)
        put_gex = round(pe["gamma"] * pe["oi"], 2)
        gex_profile.append(
            {
                "strike": float(strike),
                "call_gex": call_gex,
                "put_gex": put_gex,
                "net_gex": round(call_gex - put_gex, 2),
            }
        )
        iv_smile.append(
            {
                "strike": float(strike),
                "call_iv": ce["iv"],
                "put_iv": pe["iv"],
            }
        )

    total_ce_oi = sum(r["ce_oi"] for r in chain)
    total_pe_oi = sum(r["pe_oi"] for r in chain)
    pcr = round(total_pe_oi / total_ce_oi, 4) if total_ce_oi > 0 else 0.0
    max_pain = _compute_max_pain(chain)

    return (
        jsonify(
            {
                "status": "success",
                "underlying": underlying,
                "exchange": options_exchange,
                "spot_price": round(float(spot_price), 2),
                "expiry": expiry_sym,
                "lot_size": lot_size,
                "pcr": pcr,
                "max_pain": max_pain,
                "chain": chain,
                "gex_profile": gex_profile,
                "iv_smile": iv_smile,
            }
        ),
        200,
    )


# =============================================================================
# MCP Tool Catalog & Three-Gate Invoke Bridge (`/internal/v1/mcp/{tools,invoke}`)
# =============================================================================

_MCP_CLIENT_LOCK = real_threading.Lock()
_MCP_ATTACHED_APP_ID: int | None = None
_MCP_ATTACHED_API_KEY: str | None = None

_GUARD_LOCK = real_threading.Lock()
_INTERNAL_GATE2_MANAGER: Any = None
_INTERNAL_GATE3_GUARD: Any = None


def _build_gate3_policy_from_env():
    from services.chirify_agent_guard import Gate3Policy

    def _int_env(name: str, default: int) -> int:
        try:
            return int(os.getenv(name) or default)
        except ValueError:
            return default

    def _dec_env(name: str, default: str) -> Decimal:
        try:
            val = Decimal(str(os.getenv(name) or default))
            return val if val.is_finite() and val > 0 else Decimal(default)
        except (InvalidOperation, ValueError):
            return Decimal(default)

    def _float_env(name: str, default: float) -> float:
        try:
            return float(os.getenv(name) or default)
        except ValueError:
            return default

    return Gate3Policy(
        max_orders_per_second=max(1, min(9, _int_env("CHIRIFY_MAX_OPS", 9))),
        max_quantity=max(1, _int_env("CHIRIFY_MAX_ORDER_QUANTITY", 1000)),
        max_order_notional=_dec_env("CHIRIFY_MAX_ORDER_NOTIONAL", "500000"),
        max_ltp_deviation_pct=_dec_env("CHIRIFY_MAX_LTP_DEVIATION_PCT", "5.0"),
        duplicate_cooldown_seconds=max(0.0, _float_env("CHIRIFY_DUPLICATE_COOLDOWN_SEC", 5.0)),
    )


def _get_internal_three_gate_managers():
    from services.chirify_agent_guard import Gate2ConfirmationManager, PromptBlindOrderGuard

    global _INTERNAL_GATE2_MANAGER, _INTERNAL_GATE3_GUARD
    with _GUARD_LOCK:
        if _INTERNAL_GATE2_MANAGER is None:
            secret = (
                (os.getenv("CHIRIFY_GATE2_SECRET") or "").strip()
                or (os.getenv("CHIRIFY_INTERNAL_OPS_TOKEN") or "").strip()
                or None
            )
            _INTERNAL_GATE2_MANAGER = Gate2ConfirmationManager(
                signing_secret=secret,
                ttl_seconds=180.0,
            )
        if _INTERNAL_GATE3_GUARD is None:
            _INTERNAL_GATE3_GUARD = PromptBlindOrderGuard(policy=_build_gate3_policy_from_env())
        return _INTERNAL_GATE2_MANAGER, _INTERNAL_GATE3_GUARD


def reset_internal_mcp_guards() -> None:
    """Reset process-scoped Gate 2 & Gate 3 singletons (used in isolated unit tests)."""
    global _INTERNAL_GATE2_MANAGER, _INTERNAL_GATE3_GUARD, _MCP_ATTACHED_APP_ID, _MCP_ATTACHED_API_KEY
    with _GUARD_LOCK:
        _INTERNAL_GATE2_MANAGER = None
        _INTERNAL_GATE3_GUARD = None
    with _MCP_CLIENT_LOCK:
        _MCP_ATTACHED_APP_ID = None
        _MCP_ATTACHED_API_KEY = None


def _load_internal_mcp_module():
    from utils.mcp_tool_registry import _load_mcpserver_module

    os.environ["OPENALGO_MCP_HTTP_BOOT"] = "1"
    return _load_mcpserver_module()


def _ensure_internal_mcp_client():
    """Ensure ``mcp_module.client`` is bound to active API key and current Flask WSGI app."""
    from blueprints.mcp_http import _InProcessWsgi

    global _MCP_ATTACHED_APP_ID, _MCP_ATTACHED_API_KEY

    mcp_module = _load_internal_mcp_module()
    api_key = _resolve_pod_api_key(provision_if_missing=False) or "<not-configured>"
    http_port = int(os.getenv("FLASK_PORT") or os.getenv("PORT") or 5000)
    host = f"http://127.0.0.1:{http_port}"
    app_obj = current_app._get_current_object() if has_app_context() else None
    app_id = id(app_obj) if app_obj is not None else None

    with _MCP_CLIENT_LOCK:
        needs_rebind = (
            getattr(mcp_module, "client", None) is None
            or _MCP_ATTACHED_API_KEY != api_key
            or _MCP_ATTACHED_APP_ID != app_id
        )
        if needs_rebind:
            prev_sdk = getattr(mcp_module, "client", None)
            prev_http = getattr(prev_sdk, "client", None)
            mcp_module.init_for_http(api_key, host)
            sdk = getattr(mcp_module, "client", None)
            if app_obj is not None and sdk is not None and isinstance(getattr(sdk, "client", None), httpx.Client):
                old_default = sdk.client
                sdk.client = httpx.Client(
                    transport=httpx.WSGITransport(app=_InProcessWsgi(app_obj)),
                    timeout=getattr(sdk, "timeout", 120.0),
                    trust_env=False,
                )
                try:
                    old_default.close()
                except Exception:
                    pass
            if isinstance(prev_http, httpx.Client):
                try:
                    prev_http.close()
                except Exception:
                    pass
            _MCP_ATTACHED_API_KEY = api_key
            _MCP_ATTACHED_APP_ID = app_id

    return mcp_module, api_key


@internal_ops_bp.route("/mcp/tools", methods=["GET"])
def internal_mcp_tools():
    """Enumerate all 51 MCP tools filtered deterministically through Gate 1 surface policy."""
    from services.chirify_agent_guard import (
        ALL_ORDER_MUTATING_TOOL_NAMES,
        filter_surface_tool_schemas,
        verify_surface_exclusion,
    )
    from utils.mcp_tool_registry import SCOPE_WRITE_ORDERS, TOOL_SCOPES

    surface = str(request.args.get("surface") or "copilot").strip().lower()
    if surface not in {"copilot", "trading_chart"}:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_surface",
                    "message": "surface must be 'copilot' or 'trading_chart'.",
                }
            ),
            400,
        )

    mcp_module = _load_internal_mcp_module()
    tool_meta = getattr(mcp_module, "TOOL_META", {})
    registered = getattr(getattr(mcp_module, "mcp", None), "_tool_manager", None)
    tools_map = getattr(registered, "_tools", {}) if registered is not None else {}

    all_tools: list[dict[str, Any]] = []
    for name in sorted(TOOL_SCOPES.keys()):
        meta = tool_meta.get(name)
        tool_obj = tools_map.get(name)
        is_mutating = (name in ALL_ORDER_MUTATING_TOOL_NAMES) or (
            TOOL_SCOPES.get(name) == SCOPE_WRITE_ORDERS
        )
        desc = (getattr(tool_obj, "description", None) or "").strip()
        if not desc and meta is not None:
            desc = str(getattr(meta, "title", name))
        params_schema = getattr(tool_obj, "parameters", None)
        if not isinstance(params_schema, dict):
            params_schema = {"type": "object", "properties": {}}
        all_tools.append(
            {
                "name": name,
                "toolset": str(getattr(meta, "toolset", "utility")) if meta is not None else "utility",
                "mutating": bool(is_mutating),
                "description": desc,
                "input_schema": params_schema,
            }
        )

    filtered = filter_surface_tool_schemas(surface, all_tools)
    verdict = verify_surface_exclusion(surface, filtered)
    if not verdict.allowed:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": verdict.code,
                    "message": verdict.reason,
                }
            ),
            500,
        )

    return (
        jsonify(
            {
                "status": "success",
                "surface": surface,
                "total_tools": len(filtered),
                "filtered_mutating_tools": len(all_tools) - len(filtered),
                "catalog_total": len(all_tools),
                "tools": filtered,
            }
        ),
        200,
    )


def _lookup_reference_ltp(symbol: str, exchange: str, api_key: str | None) -> float | None:
    from broker.chirify_sandbox.api.data import get_sandbox_market_feed
    from database import historify_db
    from services import quotes_service

    sym = str(symbol or "").strip().upper()
    ex = str(exchange or "NSE").strip().upper()
    if not sym:
        return None
    if api_key and api_key != "<not-configured>":
        try:
            ok, resp, _ = quotes_service.get_quotes(symbol=sym, exchange=ex, api_key=api_key)
            if ok and isinstance(resp, dict):
                ltp = float((resp.get("data") or {}).get("ltp") or 0.0)
                if ltp > 0:
                    return ltp
        except Exception:
            pass
    try:
        df = historify_db.get_ohlcv(sym, ex, "D")
        if df is not None and not df.empty:
            c = float(df["close"].iloc[-1])
            if c > 0:
                return c
    except Exception:
        pass
    try:
        q = get_sandbox_market_feed().get_quote(sym, ex)
        ltp = float(q.get("ltp") or 0.0)
        if ltp > 0:
            return ltp
    except Exception:
        pass
    return None


def _extract_gate3_order_intents(tool_name: str, arguments: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    """Extract ONLY structured numeric/enum order intents for Gate 3 (zero prompt/actor text)."""
    if tool_name in {"place_order", "place_smart_order", "place_split_order", "modify_order"}:
        return [
            {
                "symbol": arguments.get("symbol", ""),
                "exchange": arguments.get("exchange", "NSE"),
                "action": arguments.get("action", ""),
                "quantity": arguments.get("quantity"),
                "product": arguments.get("product", "MIS"),
                "price_type": arguments.get("price_type") or arguments.get("pricetype") or "MARKET",
                "price": arguments.get("price"),
                "trigger_price": arguments.get("trigger_price"),
            }
        ], None

    if tool_name == "place_basket_order":
        orders = arguments.get("orders")
        if not isinstance(orders, list) or not orders:
            return [], "'orders' must be a non-empty list for place_basket_order."
        extracted = []
        for idx, item in enumerate(orders):
            if not isinstance(item, dict):
                return [], f"orders[{idx}] must be an object."
            extracted.append(
                {
                    "symbol": item.get("symbol", ""),
                    "exchange": item.get("exchange", "NSE"),
                    "action": item.get("action", ""),
                    "quantity": item.get("quantity"),
                    "product": item.get("product", "MIS"),
                    "price_type": item.get("price_type") or item.get("pricetype") or "MARKET",
                    "price": item.get("price"),
                    "trigger_price": item.get("trigger_price"),
                }
            )
        return extracted, None

    if tool_name == "place_options_order":
        return [
            {
                "symbol": arguments.get("underlying", ""),
                "exchange": arguments.get("exchange", "NFO"),
                "action": arguments.get("action", ""),
                "quantity": arguments.get("quantity"),
                "product": arguments.get("product", "MIS"),
                "price_type": arguments.get("price_type") or arguments.get("pricetype") or "MARKET",
                "price": arguments.get("price"),
                "trigger_price": arguments.get("trigger_price"),
            }
        ], None

    if tool_name == "place_options_multi_order":
        legs = arguments.get("legs")
        if not isinstance(legs, list) or not legs:
            return [], "'legs' must be a non-empty list for place_options_multi_order."
        extracted = []
        for idx, leg in enumerate(legs):
            if not isinstance(leg, dict):
                return [], f"legs[{idx}] must be an object."
            extracted.append(
                {
                    "symbol": arguments.get("underlying", ""),
                    "exchange": arguments.get("exchange", "NFO"),
                    "action": leg.get("action", ""),
                    "quantity": leg.get("quantity"),
                    "product": leg.get("product", arguments.get("product", "MIS")),
                    "price_type": leg.get("price_type") or leg.get("pricetype") or "MARKET",
                    "price": leg.get("price"),
                    "trigger_price": leg.get("trigger_price"),
                }
            )
        return extracted, None

    return [], None


@internal_ops_bp.route("/mcp/invoke", methods=["POST"])
def internal_mcp_invoke():
    """Execute an MCP tool through strict sequential Gate 1 -> Gate 2 -> Gate 3 -> Handler."""
    from services.chirify_agent_guard import ALL_ORDER_MUTATING_TOOL_NAMES
    from utils.mcp_tool_registry import SCOPE_WRITE_ORDERS, TOOL_SCOPES, get_tool_callable

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_payload",
                    "message": "Request body must be a JSON object.",
                }
            ),
            400,
        )

    tool_name = str(body.get("tool_name") or "").strip()
    if not tool_name:
        return jsonify({"status": "error", "code": "missing_tool_name", "message": "tool_name is required."}), 400

    arguments = body.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return jsonify({"status": "error", "code": "invalid_arguments", "message": "arguments must be an object."}), 400

    surface = str(body.get("surface") or "copilot").strip().lower()
    if surface not in {"copilot", "trading_chart"}:
        return jsonify({"status": "error", "code": "invalid_surface", "message": "surface must be 'copilot' or 'trading_chart'."}), 400

    actor = str(body.get("actor") or "unknown").strip() or "unknown"
    session_id = str(body.get("session_id") or actor or "default").strip() or "default"

    # Load MCP module & resolve tool callable
    _load_internal_mcp_module()
    if tool_name not in TOOL_SCOPES:
        return jsonify({"status": "error", "code": "unknown_tool", "message": f"Unknown MCP tool {tool_name!r}."}), 404
    fn = get_tool_callable(tool_name)
    if fn is None:
        return jsonify({"status": "error", "code": "unknown_tool", "message": f"MCP tool {tool_name!r} is unavailable."}), 404

    is_mutating = (tool_name in ALL_ORDER_MUTATING_TOOL_NAMES) or (
        TOOL_SCOPES.get(tool_name) == SCOPE_WRITE_ORDERS
    )

    # -------------------------------------------------------------------------
    # GATE 1: Surface Exclusion (trading_chart strips/blocks ALL mutating tools)
    # -------------------------------------------------------------------------
    if surface == "trading_chart" and is_mutating:
        _emit_internal_worm_safe(
            "chirify_mcp_gate1_blocked",
            {
                "tool_name": tool_name,
                "surface": surface,
                "actor": actor,
            },
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "surface_mutating_tools_forbidden",
                    "message": f"Tool {tool_name!r} is forbidden on surface 'trading_chart'.",
                    "executed": False,
                    "gate1_verdict": {
                        "allowed": False,
                        "code": "surface_mutating_tools_forbidden",
                    },
                }
            ),
            403,
        )

    gate1_verdict = {"allowed": True, "code": "ok"}

    # -------------------------------------------------------------------------
    # GATE 2: Single-Use HMAC-SHA256 HITL Confirmation (all 11 mutating tools)
    # -------------------------------------------------------------------------
    gate2_mgr, gate3_guard = _get_internal_three_gate_managers()
    gate2_verdict_dict: dict[str, Any] = {"allowed": True, "code": "non_mutating_tool"}

    if is_mutating:
        raw_conf_id = body.get("confirmation_id")
        raw_conf_token = body.get("confirmation_token")

        conf_id: str | None = None
        approval_sig: str | None = None

        if raw_conf_id is not None and str(raw_conf_id).strip():
            conf_id = str(raw_conf_id).strip()
            approval_sig = str(raw_conf_token or "").strip() or "invalid"
        elif raw_conf_token is not None and str(raw_conf_token).strip():
            tok_str = str(raw_conf_token).strip()
            if "." in tok_str:
                conf_id, approval_sig = tok_str.split(".", 1)
                if not conf_id or not approval_sig:
                    conf_id = tok_str
                    approval_sig = "invalid"
            else:
                # Non-empty malformed token MUST be rejected (403), never treated as fresh draft (202)
                conf_id = tok_str
                approval_sig = "invalid"

        g2 = gate2_mgr.verify_or_pause(
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            confirmation_id=conf_id,
            approval_token=approval_sig,
        )
        if not g2.allowed:
            if g2.code == "hitl_confirmation_required" and g2.pending_confirmation is not None:
                pending = g2.pending_confirmation
                combined_token = f"{pending.confirmation_id}.{pending.approval_token}"
                _emit_internal_worm_safe(
                    "chirify_mcp_gate2_pending",
                    {
                        "tool_name": tool_name,
                        "confirmation_id": pending.confirmation_id,
                        "actor": actor,
                        "confirmation_token": REDACTED_VALUE,
                    },
                )
                return (
                    jsonify(
                        {
                            "status": "pending_confirmation",
                            "executed": False,
                            "tool_name": tool_name,
                            "surface": surface,
                            "confirmation_id": pending.confirmation_id,
                            "confirmation_token": combined_token,
                            "pending_confirmation": pending.public_payload(),
                            "gate1_verdict": gate1_verdict,
                            "gate2_verdict": {
                                "allowed": False,
                                "code": g2.code,
                                "reason": g2.reason,
                            },
                        }
                    ),
                    202,
                )

            _emit_internal_worm_safe(
                "chirify_mcp_gate2_rejected",
                {
                    "tool_name": tool_name,
                    "code": g2.code,
                    "actor": actor,
                    "confirmation_token": REDACTED_VALUE,
                },
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": g2.code,
                        "message": g2.reason,
                        "executed": False,
                        "gate1_verdict": gate1_verdict,
                        "gate2_verdict": {
                            "allowed": False,
                            "code": g2.code,
                            "reason": g2.reason,
                        },
                    }
                ),
                403,
            )

        gate2_verdict_dict = {"allowed": True, "code": g2.code, "reason": g2.reason}

    # -------------------------------------------------------------------------
    # GATE 3: Prompt-Blind Deterministic Risk Guard (ZERO prompt/actor tokens!)
    # -------------------------------------------------------------------------
    gate3_verdict_dict: dict[str, Any] = {"allowed": True, "code": "not_applicable"}
    _, active_api_key = _ensure_internal_mcp_client()

    if is_mutating:
        # 3a. Global emergency kill-switch halts ALL 11 mutating tools
        if chirify_live_gate.is_emergency_kill_switch_engaged():
            _emit_internal_worm_safe(
                "chirify_mcp_gate3_blocked",
                {"tool_name": tool_name, "code": "kill_switch_engaged"},
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "kill_switch_engaged",
                        "message": "Global emergency kill switch is engaged; mutating tool blocked.",
                        "executed": False,
                        "gate1_verdict": gate1_verdict,
                        "gate2_verdict": gate2_verdict_dict,
                        "gate3_verdict": {
                            "allowed": False,
                            "code": "kill_switch_engaged",
                            "reason": "Global emergency kill switch is engaged.",
                        },
                    }
                ),
                403,
            )

        # 3b. Live-gate protection on analyzer_toggle(mode=False)
        if tool_name in {"analyzer_toggle", "toggle_analyzer_mode"}:
            target_mode = arguments.get("mode")
            if target_mode is False or str(target_mode).strip().lower() == "false":
                lg_verdict = chirify_live_gate.check_live_mode_transition(
                    current_mode=True,
                    target_mode=False,
                    broker=_resolve_active_broker(_resolve_pod_username()),
                )
                if not lg_verdict.allowed:
                    _emit_internal_worm_safe(
                        "chirify_mcp_gate3_blocked",
                        {"tool_name": tool_name, "code": lg_verdict.code},
                    )
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "code": lg_verdict.code,
                                "message": lg_verdict.message,
                                "executed": False,
                                "gate1_verdict": gate1_verdict,
                                "gate2_verdict": gate2_verdict_dict,
                                "gate3_verdict": {
                                    "allowed": False,
                                    "code": lg_verdict.code,
                                    "reason": lg_verdict.message,
                                },
                            }
                        ),
                        403,
                    )

        # 3c. Order identifier hygiene for cancel_order
        if tool_name == "cancel_order":
            oid = str(arguments.get("order_id") or "").strip()
            if not oid or not _ORDER_ID_RE.match(oid):
                return (
                    jsonify(
                        {
                            "status": "error",
                            "code": "invalid_order_id",
                            "message": f"Invalid order_id {oid!r}.",
                            "executed": False,
                            "gate3_verdict": {
                                "allowed": False,
                                "code": "invalid_order_id",
                                "reason": "order_id failed strict identifier validation.",
                            },
                        }
                    ),
                    403,
                )

        # 3d. Prompt-blind numeric/structural order validation (ZERO conversation/actor fields)
        order_intents, extract_err = _extract_gate3_order_intents(tool_name, arguments)
        if extract_err:
            return (
                jsonify(
                    {
                        "status": "error",
                        "code": "invalid_order_arguments",
                        "message": extract_err,
                        "executed": False,
                    }
                ),
                400,
            )

        for intent in order_intents:
            ref_ltp = _lookup_reference_ltp(
                str(intent.get("symbol") or ""),
                str(intent.get("exchange") or "NSE"),
                active_api_key,
            )
            g3 = gate3_guard.validate_order(
                symbol=str(intent.get("symbol") or ""),
                exchange=str(intent.get("exchange") or "NSE"),
                action=str(intent.get("action") or ""),
                quantity=intent.get("quantity"),
                product=str(intent.get("product") or "MIS"),
                price_type=str(intent.get("price_type") or "MARKET"),
                price=intent.get("price"),
                trigger_price=intent.get("trigger_price"),
                ltp=ref_ltp,
            )
            if not g3.allowed:
                _emit_internal_worm_safe(
                    "chirify_mcp_gate3_blocked",
                    {
                        "tool_name": tool_name,
                        "code": g3.code,
                        "details": dict(g3.details),
                    },
                )
                return (
                    jsonify(
                        {
                            "status": "error",
                            "code": g3.code,
                            "message": g3.reason,
                            "details": dict(g3.details),
                            "executed": False,
                            "gate1_verdict": gate1_verdict,
                            "gate2_verdict": gate2_verdict_dict,
                            "gate3_verdict": {
                                "allowed": False,
                                "code": g3.code,
                                "reason": g3.reason,
                                "details": dict(g3.details),
                            },
                        }
                    ),
                    403,
                )
            gate3_verdict_dict = {
                "allowed": True,
                "code": g3.code,
                "reason": g3.reason,
                "details": dict(g3.details),
            }

        if not order_intents:
            gate3_verdict_dict = {"allowed": True, "code": "ok"}

    # -------------------------------------------------------------------------
    # Real MCP Tool Handler Execution (via in-process WSGI SDK client)
    # -------------------------------------------------------------------------
    try:
        raw_output = fn(**arguments)
    except TypeError as exc:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "invalid_tool_arguments",
                    "message": str(exc),
                    "executed": False,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.exception(f"[InternalOps] MCP tool {tool_name!r} execution failed")
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "tool_execution_failed",
                    "message": str(exc),
                    "executed": False,
                }
            ),
            500,
        )

    parsed_result: Any = raw_output
    if isinstance(raw_output, str):
        try:
            parsed_result = json.loads(raw_output)
        except json.JSONDecodeError:
            parsed_result = {"raw": raw_output}

    unwrapped_data = (
        parsed_result.get("data", parsed_result)
        if isinstance(parsed_result, dict) and "_openalgo_mcp_security" in parsed_result
        else parsed_result
    )

    worm_record = _emit_internal_worm_safe(
        "chirify_mcp_tool_invoked",
        {
            "tool_name": tool_name,
            "surface": surface,
            "actor": actor,
            "mutating": bool(is_mutating),
            "outcome": "success",
            "confirmation_token": REDACTED_VALUE,
        },
    )

    return (
        jsonify(
            {
                "status": "success",
                "executed": True,
                "tool_name": tool_name,
                "surface": surface,
                "mutating": bool(is_mutating),
                "gate1_verdict": gate1_verdict,
                "gate2_verdict": gate2_verdict_dict,
                "gate3_verdict": gate3_verdict_dict,
                "result": parsed_result,
                "data": unwrapped_data,
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )



