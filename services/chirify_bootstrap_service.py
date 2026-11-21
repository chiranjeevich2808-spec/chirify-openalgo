"""Headless First-Boot Provisioning for Chirify Managed SaaS Pods.

When ``CHIRIFY_MANAGED_POD`` is unset or falsy, :func:`is_managed_pod` returns
``False`` and :func:`bootstrap_managed_tenant` acts as a no-op returning
``{"bootstrapped": False, "reason": "standalone_mode"}``, leaving standalone
OpenAlgo deployments and ``/setup`` completely unchanged.

When ``CHIRIFY_MANAGED_POD`` is in ``{"true", "1", "yes", "on"}``:
1. ``start.sh`` invokes ``python -m services.chirify_bootstrap_service`` right
   after ``python -m utils.startup_invariants`` and before Gunicorn accepts
   external traffic, eliminating the first-boot ``/setup`` admin-claim race.
2. Creates the single tenant admin owner idempotently with either
   ``CHIRIFY_TENANT_BOOTSTRAP_PASSWORD`` or a random 256-bit hex secret
   (``secrets.token_hex(32)``) that is never logged or persisted in plaintext.
3. Initializes Analyzer (Sandbox) Mode to ``True`` on first boot without
   clobbering ``analyze_mode`` on subsequent restarts if Live Mode has already
   been legitimately unlocked.
4. Emits a hash-chained UTC WORM audit event (``chirify_pod_bootstrapped``)
   when WORM auditing is enabled.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from utils.logging import get_logger

logger = get_logger(__name__)

MANAGED_POD_TRUTHY: frozenset[str] = frozenset({"true", "1", "yes", "on"})
WORM_TRUTHY: frozenset[str] = frozenset({"true", "1", "yes", "on", "t"})
_USERNAME_CLEAN_RE = re.compile(r"[^a-zA-Z0-9_]+")


class ManagedPodBootstrapError(RuntimeError, ValueError):
    """Raised when required Chirify managed-pod bootstrap configuration is invalid or missing."""


def _clean_env_val(value: str | None) -> str:
    """Strip surrounding whitespace and matching single/double quotes."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def is_managed_pod(env: Mapping[str, str] | None = None) -> bool:
    """Return True iff ``CHIRIFY_MANAGED_POD`` is in ``{"true", "1", "yes", "on"}``."""
    source = env if env is not None else os.environ
    raw = _clean_env_val(source.get("CHIRIFY_MANAGED_POD")).lower()
    return raw in MANAGED_POD_TRUTHY


def managed_pod_setup_blocked_response() -> tuple[Any, int] | None:
    """Return ``(Response, 403)`` if ``is_managed_pod()`` is True, otherwise ``None``."""
    if not is_managed_pod():
        return None
    from flask import jsonify

    return (
        jsonify(
            {
                "status": "error",
                "code": "managed_pod_setup_disabled",
                "message": "Initial setup is managed by Chirify Control Plane.",
            }
        ),
        403,
    )


def install_managed_pod_setup_guard(app: Any) -> None:
    """Register a ``before_request`` guard rejecting ``/setup`` on Chirify managed pods."""

    @app.before_request
    def enforce_managed_pod_setup_lockdown():
        from flask import request

        if request.path.rstrip("/") == "/setup":
            return managed_pod_setup_blocked_response()
        return None


def is_worm_audit_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Return True when WORM audit logging is enabled via env flag or explicit path."""
    source = env if env is not None else os.environ
    flag = _clean_env_val(source.get("CHIRIFY_WORM_AUDIT_ENABLED")).lower()
    log_path = _clean_env_val(source.get("CHIRIFY_WORM_LOG_PATH"))
    return flag in WORM_TRUTHY or bool(log_path)


def sanitize_username(raw: str | None, *, fallback: str = "trader") -> str:
    """Normalize a username or email local-part into a safe OpenAlgo username."""
    candidate = _clean_env_val(raw)
    sanitized = _USERNAME_CLEAN_RE.sub("_", candidate).strip("_").lower()[:80]
    return sanitized if sanitized else fallback


def _derive_default_username(email: str) -> str:
    local_part = email.split("@", 1)[0] if "@" in email else email
    return sanitize_username(local_part, fallback="trader")


def _ensure_sqlite_parent_dir(db_url: str | None) -> None:
    effective = _clean_env_val(db_url) or "sqlite:///db/openalgo.db"
    if effective.startswith("sqlite:///"):
        db_path = effective.replace("sqlite:///", "", 1)
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)


def _emit_bootstrap_worm_event(
    payload: Mapping[str, Any],
    *,
    env: Mapping[str, str] | None = None,
) -> int | None:
    """Append ``chirify_pod_bootstrapped`` to WORM JSONL log if enabled."""
    if not is_worm_audit_enabled(env):
        return None

    from subscribers.worm_audit_subscriber import WormAuditWriter, emit_worm_audit_event

    source = env if env is not None else os.environ
    explicit_path = _clean_env_val(source.get("CHIRIFY_WORM_LOG_PATH"))
    try:
        if env is not None and explicit_path:
            record = WormAuditWriter(explicit_path).append("chirify_pod_bootstrapped", payload)
        else:
            record = emit_worm_audit_event("chirify_pod_bootstrapped", payload)
        return record.seq_no
    except OSError:
        # Fallback to local LOG_DIR when /app/log is unavailable in non-container environments
        fallback_dir = Path(_clean_env_val(source.get("LOG_DIR")) or "log")
        record = WormAuditWriter(fallback_dir / "worm_audit.jsonl").append(
            "chirify_pod_bootstrapped", payload
        )
        return record.seq_no


def bootstrap_managed_tenant(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Idempotently provision the tenant admin owner and lock Sandbox Mode on first boot.

    Args:
        env: Optional environment mapping override (defaults to ``os.environ``).

    Returns:
        Summary dictionary describing bootstrap outcome (never includes secrets).

    Raises:
        ManagedPodBootstrapError: If required tenant configuration is missing or
            user creation fails unexpectedly.
    """
    if not is_managed_pod(env):
        return {"bootstrapped": False, "reason": "standalone_mode"}

    source = env if env is not None else os.environ
    tenant_id = _clean_env_val(source.get("CHIRIFY_TENANT_ID"))
    if not tenant_id:
        raise ManagedPodBootstrapError(
            "CHIRIFY_TENANT_ID is required when CHIRIFY_MANAGED_POD is enabled."
        )

    admin_email = _clean_env_val(source.get("CHIRIFY_TENANT_ADMIN_EMAIL")).lower()
    if not admin_email or "@" not in admin_email:
        raise ManagedPodBootstrapError(
            "CHIRIFY_TENANT_ADMIN_EMAIL must be a valid email address when CHIRIFY_MANAGED_POD is enabled."
        )

    raw_username = _clean_env_val(source.get("CHIRIFY_TENANT_ADMIN_USERNAME"))
    admin_username = (
        sanitize_username(raw_username, fallback="trader")
        if raw_username
        else _derive_default_username(admin_email)
    )

    configured_password = _clean_env_val(source.get("CHIRIFY_TENANT_BOOTSTRAP_PASSWORD"))
    bootstrap_password = configured_password if configured_password else secrets.token_hex(32)

    if env is None and not _clean_env_val(os.environ.get("CHIRIFY_ENFORCE_LIVE_GATE")):
        os.environ["CHIRIFY_ENFORCE_LIVE_GATE"] = "true"

    _ensure_sqlite_parent_dir(source.get("DATABASE_URL") or os.getenv("DATABASE_URL"))

    from database import analyzer_db, auth_db, settings_db, user_db
    from database.db_init_helper import init_db_with_logging

    user_db.init_db()
    auth_db.init_db()
    analyzer_db.init_db()
    init_db_with_logging(settings_db.Base, settings_db.engine, "Settings DB", logger)

    had_settings_row = settings_db.Settings.query.first() is not None
    existing_user = (
        user_db.find_user_by_username()
        or user_db.find_user_by_email(admin_email)
        or user_db.find_user_by_exact_username(admin_username)
    )

    already_existed = existing_user is not None
    if already_existed:
        user = existing_user
        if not had_settings_row:
            settings_db.set_analyze_mode(True)
    else:
        user = user_db.add_user(admin_username, admin_email, bootstrap_password, is_admin=True)
        if user is None:
            # Concurrent worker race check
            user = (
                user_db.find_user_by_username()
                or user_db.find_user_by_email(admin_email)
                or user_db.find_user_by_exact_username(admin_username)
            )
            if user is None:
                raise ManagedPodBootstrapError(
                    f"Failed to create managed tenant admin user {admin_username!r}."
                )
            already_existed = True
        else:
            # First-boot safety invariant: managed pods ALWAYS start in Analyzer (Sandbox) Mode
            settings_db.set_analyze_mode(True)

    # Ensure an initial OpenAlgo API key exists for Sandbox/Analyzer dashboard queries
    if not auth_db.get_api_key(user.username):
        auth_db.upsert_api_key(user.username, secrets.token_hex(32))

    del bootstrap_password
    del configured_password

    current_analyze_mode = bool(settings_db.get_analyze_mode())
    worm_seq_no: int | None = None
    if not already_existed:
        worm_seq_no = _emit_bootstrap_worm_event(
            {
                "tenant_id": tenant_id,
                "username": user.username,
                "email": user.email,
                "analyze_mode": current_analyze_mode,
                "already_existed": False,
            },
            env=env,
        )
        logger.info(
            f"[ChirifyBootstrap] Provisioned tenant={tenant_id} admin={user.username} "
            f"(analyze_mode={current_analyze_mode})"
        )
    else:
        logger.info(
            f"[ChirifyBootstrap] Tenant={tenant_id} admin={user.username} already provisioned "
            f"(analyze_mode={current_analyze_mode})"
        )

    return {
        "bootstrapped": True,
        "created": not already_existed,
        "already_existed": already_existed,
        "tenant_id": tenant_id,
        "username": user.username,
        "email": user.email,
        "analyze_mode": current_analyze_mode,
        "worm_seq_no": worm_seq_no,
    }


def _populate_missing_dotenv_vars() -> None:
    """Load ``/app/.env`` or ``.env`` defaults into ``os.environ`` without overriding existing vars."""
    for candidate in (Path("/app/.env"), Path(".env")):
        if candidate.is_file():
            try:
                parsed = dotenv_values(candidate)
                for key, val in parsed.items():
                    if key and val is not None and key not in os.environ:
                        os.environ[key] = _clean_env_val(val)
            except OSError:
                pass
            break


def main() -> int:
    """CLI entrypoint invoked by ``start.sh`` when ``CHIRIFY_MANAGED_POD`` is truthy."""
    _populate_missing_dotenv_vars()
    try:
        result = bootstrap_managed_tenant()
    except Exception as exc:
        print(f"[OpenAlgo] CRITICAL MANAGED POD BOOTSTRAP FAILURE: {exc}", file=sys.stderr)
        return 1

    if result.get("bootstrapped"):
        state = "already_existed" if result.get("already_existed") else "created"
        print(
            f"[OpenAlgo] Chirify pod bootstrap ok: tenant={result.get('tenant_id')} "
            f"user={result.get('username')} state={state} analyze_mode={result.get('analyze_mode')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
