"""Internal Cluster Operations Blueprint (`/internal/v1/*`).

Provides authenticated, private-network-only operational endpoints for the
Chirify Control Plane and Cilium static-egress failover controller:

- ``GET  /internal/v1/health/egress``
- ``POST /internal/v1/failover-reconcile``
- ``POST /internal/v1/historify/export-parquet``
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
import os
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

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

    worm_record = emit_worm_audit_event(
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


@internal_ops_bp.route("/historify/export-parquet", methods=["POST"])
def export_parquet_endpoint():
    """Trigger a lock-free DuckDB-to-Parquet snapshot export for Qlib research workers."""
    body: dict[str, Any] = request.get_json(silent=True) or {}
    output_path = str(body.get("output_path") or "/app/tmp/historify_snapshot.parquet").strip()

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

    worm_record = emit_worm_audit_event(
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

    with _KILL_SWITCH_LOCK:
        settings_db.Base.metadata.create_all(settings_db.engine)
        if engaged:
            os.environ["CHIRIFY_EMERGENCY_KILL_SWITCH"] = "true"
            current_analyze_mode = bool(apply_analyze_mode(True))
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
                "worm_audit": {
                    "seq_no": worm_record.seq_no,
                    "timestamp_utc": worm_record.timestamp_utc,
                    "record_hash": worm_record.record_hash,
                },
            }
        ),
        200,
    )


