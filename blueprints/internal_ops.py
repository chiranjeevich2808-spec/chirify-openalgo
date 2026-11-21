"""Internal Cluster Operations Blueprint (`/internal/v1/*`).

Provides authenticated, private-network-only operational endpoints for the
Chirify Control Plane and Cilium static-egress failover controller:

- ``GET  /internal/v1/health/egress``
- ``POST /internal/v1/failover-reconcile``
- ``POST /internal/v1/historify/export-parquet``

Security controls:
1. Restricted strictly to loopback, RFC1918 private, link-local, ULA, or
   cluster CGNAT (``100.64.0.0/10``) peer IP addresses via raw
   ``request.remote_addr`` (never trusting spoofable ``X-Forwarded-For``).
2. Constant-time ``hmac.compare_digest`` bearer/header authentication against
   ``CHIRIFY_INTERNAL_OPS_TOKEN`` (fails closed when the token env var is unset).
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

from services.qlib_snapshot_service import export_historify_parquet
from services.strategy_module import ack_reconciliation
from subscribers.worm_audit_subscriber import emit_worm_audit_event
from utils.logging import get_logger
from utils.startup_invariants import DEFAULT_EGRESS_STATE_PATH, is_truthy

logger = get_logger(__name__)

internal_ops_bp = Blueprint("internal_ops_bp", __name__, url_prefix="/internal/v1")

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
    """Extract internal ops token from ``Authorization: Bearer`` or ``X-Chirify-Internal-Token``."""
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return (request.headers.get("X-Chirify-Internal-Token") or "").strip()


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
            "old_egress_ip": body.get("old_egress_ip"),
            "new_egress_ip": body.get("new_egress_ip"),
            "reason": body.get("reason", "cilium_egress_gateway_failover"),
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
