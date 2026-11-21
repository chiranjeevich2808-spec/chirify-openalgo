"""Startup security invariant checks for OpenAlgo / Chirify pods.

Executed by ``start.sh`` (``python -m utils.startup_invariants``) prior to
launching ``websocket_proxy`` and Gunicorn, and directly callable in unit tests
with an explicit environment mapping and egress state file path.

Enforced invariants:
1. ``ZMQ_HOST`` must resolve strictly to loopback (``"127.0.0.1"`` or
   ``"localhost"``) so the unauthenticated ``:5555`` market-data tick bus can
   never be exposed across pod or host network interfaces.
2. ``FLASK_DEBUG`` must never be truthy when ``CHIRIFY_CLUSTER_MODE`` is truthy
   or when ``FLASK_HOST_IP`` binds to a non-loopback address (Werkzeug debug
   tracebacks and interactive pins leak secrets and allow RCE).
3. When ``CHIRIFY_CLUSTER_MODE`` is truthy, placeholder or historically leaked
   values in ``APP_KEY``, ``API_KEY_PEPPER``, or ``FERNET_SALT`` are refused.
4. When ``CHIRIFY_REQUIRE_STATIC_EGRESS`` is truthy, the egress verification
   file written by the ``egress-ip-guard`` initContainer (default
   ``/app/tmp/egress_verified.json``) must exist, be fresh within the configured
   boot window (default 300 seconds), and report ``observed_ip`` matching
   ``{EXPECTED_EGRESS_IPV4, EXPECTED_SECONDARY_IPV4}``.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from dotenv import dotenv_values

DEFAULT_EGRESS_STATE_PATH = Path("/app/tmp/egress_verified.json")
DEFAULT_MAX_EGRESS_AGE_SECONDS = 300.0

ALLOWED_ZMQ_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost"})
LOOPBACK_FLASK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
TRUTHY_VALUES: frozenset[str] = frozenset({"true", "1", "yes", "t", "on"})

# Upstream publicly-known sample keys that must also be refused in cluster mode
_KNOWN_COMPROMISED_LITERALS: frozenset[str] = frozenset(
    {
        "3daa0403ce2501ee7432b75bf100048e3cf510d63d2754f952e93d88bf07ea84",
        "3daa0403ce2501ee7432b75bf100048e3cf510d63d2754f952729a991d8e2417",
        "a25d94718479b170c16278e321ea6c989358bf499a658fd20c90033cef8ce772",
    }
)


class StartupInvariantError(RuntimeError):
    """Raised when one or more startup security invariants fail."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = list(violations)
        joined = "; ".join(self.violations)
        super().__init__(f"Startup security invariant check failed ({len(self.violations)}): {joined}")


def _clean_env_val(value: str | None) -> str:
    """Strip surrounding whitespace and optional single/double quotes."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1].strip()
    return cleaned


def is_truthy(value: str | None) -> bool:
    """Return True if an environment variable string represents a truthy flag."""
    return _clean_env_val(value).lower() in TRUTHY_VALUES


def _load_default_env() -> dict[str, str]:
    """Merge ``.env`` file values (if readable) with ``os.environ`` (process wins)."""
    merged: dict[str, str] = {}
    for candidate in (Path("/app/.env"), Path(".env")):
        if candidate.is_file():
            try:
                parsed = dotenv_values(candidate)
                for key, val in parsed.items():
                    if key and val is not None:
                        merged[key] = _clean_env_val(val)
            except OSError:
                pass
            break
    for key, val in os.environ.items():
        merged[key] = _clean_env_val(val)
    return merged


def _parse_egress_epoch(payload: Mapping[str, object], state_path: Path) -> float | None:
    """Extract verification epoch seconds from egress JSON payload or file mtime."""
    for numeric_key in ("verified_at_epoch", "checked_at_epoch", "epoch", "timestamp"):
        raw = payload.get(numeric_key)
        if raw is not None and not isinstance(raw, bool):
            if isinstance(raw, int | float):
                return float(raw)
            if isinstance(raw, str):
                text = raw.strip()
                try:
                    return float(text)
                except ValueError:
                    # Fall through to ISO-8601 parsing if timestamp is an ISO string
                    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
                    try:
                        parsed_dt = datetime.fromisoformat(iso_text)
                        if parsed_dt.tzinfo is None:
                            parsed_dt = parsed_dt.replace(tzinfo=UTC)
                        return parsed_dt.timestamp()
                    except ValueError:
                        return None

    for iso_key in ("verified_at", "checked_at", "verified_at_utc", "checked_at_utc"):
        raw = payload.get(iso_key)
        if isinstance(raw, str) and raw.strip():
            text = raw.strip()
            iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
            try:
                parsed_dt = datetime.fromisoformat(iso_text)
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=UTC)
                return parsed_dt.timestamp()
            except ValueError:
                return None

    try:
        return state_path.stat().st_mtime
    except OSError:
        return None


def _is_placeholder_or_compromised(value: str) -> bool:
    """Return True if a secret is empty, an OPENALGO_PLACEHOLDER_*, or leaked sample."""
    if not value:
        return True
    upper = value.upper()
    if "OPENALGO_PLACEHOLDER_" in upper:
        return True
    return value in _KNOWN_COMPROMISED_LITERALS


def validate_startup_invariants(
    env: Mapping[str, str] | None = None,
    egress_state_path: Path | None = None,
    *,
    now_epoch: float | None = None,
    max_egress_age_seconds: float | None = None,
) -> list[str]:
    """Validate container & cluster security invariants without side effects.

    Args:
        env: Environment mapping to inspect. Defaults to ``.env`` merged with
            ``os.environ``.
        egress_state_path: Path to the ``egress_verified.json`` file written by
            the ``egress-ip-guard`` initContainer. Defaults to
            ``CHIRIFY_EGRESS_STATE_PATH`` or ``/app/tmp/egress_verified.json``.
        now_epoch: Optional current Unix timestamp override for deterministic tests.
        max_egress_age_seconds: Maximum allowed age in seconds for the egress
            verification artifact (defaults to ``CHIRIFY_MAX_EGRESS_AGE_SECONDS``
            or 300s).

    Returns:
        List of human-readable invariant violation messages (empty when valid).
    """
    effective_env: dict[str, str] = (
        {k: _clean_env_val(v) for k, v in env.items()} if env is not None else _load_default_env()
    )
    violations: list[str] = []

    # 1. ZMQ_HOST must be strictly loopback ("127.0.0.1" or "localhost")
    if "ZMQ_HOST" in effective_env:
        zmq_host = effective_env["ZMQ_HOST"]
    else:
        zmq_host = "127.0.0.1"

    if zmq_host not in ALLOWED_ZMQ_HOSTS:
        violations.append(
            f"ZMQ_HOST={zmq_host!r} is forbidden; must be '127.0.0.1' or 'localhost' "
            "to prevent unauthenticated :5555 market-data tick bus exposure."
        )

    # 2. FLASK_DEBUG must not be truthy in cluster mode or on non-loopback bind
    cluster_mode = is_truthy(effective_env.get("CHIRIFY_CLUSTER_MODE"))
    flask_debug = is_truthy(effective_env.get("FLASK_DEBUG"))
    flask_host = (effective_env.get("FLASK_HOST_IP") or "127.0.0.1").lower()
    non_loopback_flask = flask_host not in LOOPBACK_FLASK_HOSTS

    if flask_debug and (cluster_mode or non_loopback_flask):
        reason = (
            "CHIRIFY_CLUSTER_MODE is enabled"
            if cluster_mode
            else f"FLASK_HOST_IP={flask_host!r} is non-loopback"
        )
        violations.append(
            f"FLASK_DEBUG cannot be enabled when {reason} (leaks secrets and tracebacks)."
        )

    # 3. Refuse placeholder / missing / compromised secrets in CHIRIFY_CLUSTER_MODE
    if cluster_mode:
        for secret_name in ("APP_KEY", "API_KEY_PEPPER", "FERNET_SALT"):
            secret_val = effective_env.get(secret_name, "")
            if _is_placeholder_or_compromised(secret_val):
                violations.append(
                    f"{secret_name} is missing or uses a forbidden placeholder/compromised value "
                    "while CHIRIFY_CLUSTER_MODE is enabled."
                )

    # 4. Static egress IP verification when CHIRIFY_REQUIRE_STATIC_EGRESS is truthy
    if is_truthy(effective_env.get("CHIRIFY_REQUIRE_STATIC_EGRESS")):
        resolved_path = (
            Path(egress_state_path)
            if egress_state_path is not None
            else Path(
                effective_env.get("CHIRIFY_EGRESS_STATE_PATH") or str(DEFAULT_EGRESS_STATE_PATH)
            )
        )

        allowed_ips = {
            ip
            for ip in (
                effective_env.get("EXPECTED_EGRESS_IPV4", ""),
                effective_env.get("EXPECTED_SECONDARY_IPV4", ""),
            )
            if ip
        }
        if not allowed_ips:
            violations.append(
                "CHIRIFY_REQUIRE_STATIC_EGRESS is enabled, but neither EXPECTED_EGRESS_IPV4 "
                "nor EXPECTED_SECONDARY_IPV4 is configured."
            )

        max_age = max_egress_age_seconds
        if max_age is None:
            raw_age = effective_env.get("CHIRIFY_MAX_EGRESS_AGE_SECONDS", "")
            try:
                max_age = float(raw_age) if raw_age else DEFAULT_MAX_EGRESS_AGE_SECONDS
            except ValueError:
                max_age = DEFAULT_MAX_EGRESS_AGE_SECONDS

        if not resolved_path.is_file():
            violations.append(
                f"Static egress state file {resolved_path} does not exist "
                "(egress-ip-guard initContainer must verify egress before startup)."
            )
        else:
            try:
                payload = json.loads(resolved_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                violations.append(f"Static egress state file {resolved_path} is unreadable: {exc}")
                payload = None

            if not isinstance(payload, Mapping):
                if payload is not None:
                    violations.append(
                        f"Static egress state file {resolved_path} must contain a JSON object."
                    )
            else:
                verified_epoch = _parse_egress_epoch(payload, resolved_path)
                current_epoch = now_epoch if now_epoch is not None else time.time()
                if verified_epoch is None:
                    violations.append(
                        f"Static egress state file {resolved_path} has an invalid timestamp."
                    )
                else:
                    age = current_epoch - verified_epoch
                    if age > max_age or age < -30.0:
                        violations.append(
                            f"Static egress verification in {resolved_path} is stale "
                            f"(age={age:.1f}s, max_allowed={max_age:.1f}s)."
                        )

                observed_ip = str(payload.get("observed_ip") or "").strip()
                if not observed_ip:
                    violations.append(
                        f"Static egress state file {resolved_path} is missing 'observed_ip'."
                    )
                elif allowed_ips and observed_ip not in allowed_ips:
                    violations.append(
                        f"Observed egress IP {observed_ip!r} is not in allowed static egress set "
                        f"{sorted(allowed_ips)!r}."
                    )

    return violations


def enforce_startup_invariants(
    env: Mapping[str, str] | None = None,
    egress_state_path: Path | None = None,
) -> None:
    """Validate startup invariants and raise :class:`StartupInvariantError` on failure."""
    violations = validate_startup_invariants(env=env, egress_state_path=egress_state_path)
    if violations:
        raise StartupInvariantError(violations)


def main() -> int:
    """CLI entrypoint invoked by ``start.sh`` before starting Gunicorn/websocket_proxy."""
    try:
        enforce_startup_invariants()
    except StartupInvariantError as exc:
        print("[OpenAlgo] CRITICAL STARTUP INVARIANT FAILURE:", file=sys.stderr)
        for idx, item in enumerate(exc.violations, start=1):
            print(f"  {idx}. {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
