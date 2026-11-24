"""PRR Tests: Container & Startup Security Hardening (`Dockerfile`, `start.sh`, `startup_invariants`)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from utils.startup_invariants import (
    StartupInvariantError,
    enforce_startup_invariants,
    validate_startup_invariants,
)

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "Dockerfile"
START_SH = ROOT / "start.sh"


def test_dockerfile_enforces_utc_non_world_writable_env_and_k8s_chromium_flags():
    content = DOCKERFILE.read_text(encoding="utf-8")

    assert "/usr/share/zoneinfo/UTC" in content
    assert "/usr/share/zoneinfo/Asia/Kolkata" not in content
    assert "TZ=UTC" in content
    assert "TZ=Asia/Kolkata" not in content
    assert "HISTORIFY_DATABASE_PATH=/app/db/historify.duckdb" in content
    assert 'CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage --disable-gpu"' in content
    assert "chmod 600 /app/.env" in content
    assert "chmod 666 /app/.env" not in content
    assert "USER appuser" in content


def test_start_sh_sources_eso_secrets_and_runs_startup_invariants_before_launch():
    content = START_SH.read_text(encoding="utf-8")

    assert "/run/secrets/openalgo/env" in content
    assert "utils.startup_invariants" in content

    invariants_pos = content.index("utils.startup_invariants")
    ws_proxy_pos = content.index("websocket_proxy.server")
    gthread_gunicorn_pos = content.index("/app/install/openalgo-gunicorn.sh")
    eventlet_gunicorn_pos = content.index("exec /app/.venv/bin/gunicorn")
    assert invariants_pos < ws_proxy_pos < gthread_gunicorn_pos < eventlet_gunicorn_pos


@pytest.mark.parametrize("valid_host", ["127.0.0.1", "localhost"])
def test_zmq_host_accepts_loopback(valid_host: str):
    violations = validate_startup_invariants(env={"ZMQ_HOST": valid_host})
    assert violations == []


@pytest.mark.parametrize("bad_host", ["0.0.0.0", "::", "10.244.0.12", "192.168.1.5", ""])
def test_zmq_host_refuses_non_loopback_tick_bus_exposure(bad_host: str):
    violations = validate_startup_invariants(env={"ZMQ_HOST": bad_host})
    assert len(violations) == 1
    assert "ZMQ_HOST" in violations[0]
    assert ":5555" in violations[0]


@pytest.mark.parametrize("debug_val", ["true", "True", "1", "yes"])
def test_flask_debug_refused_in_cluster_mode_or_non_loopback_bind(debug_val: str):
    v_cluster = validate_startup_invariants(
        env={
            "ZMQ_HOST": "127.0.0.1",
            "CHIRIFY_CLUSTER_MODE": "true",
            "FLASK_HOST_IP": "127.0.0.1",
            "FLASK_DEBUG": debug_val,
            "APP_KEY": "a" * 64,
            "API_KEY_PEPPER": "b" * 64,
            "FERNET_SALT": "c" * 32,
        }
    )
    assert any("FLASK_DEBUG" in v for v in v_cluster)

    v_non_loopback = validate_startup_invariants(
        env={
            "ZMQ_HOST": "127.0.0.1",
            "FLASK_HOST_IP": "0.0.0.0",
            "FLASK_DEBUG": debug_val,
        }
    )
    assert any("FLASK_DEBUG" in v for v in v_non_loopback)

    # Local standalone loopback debug stays allowed
    v_local = validate_startup_invariants(
        env={
            "ZMQ_HOST": "127.0.0.1",
            "FLASK_HOST_IP": "127.0.0.1",
            "FLASK_DEBUG": debug_val,
        }
    )
    assert v_local == []


@pytest.mark.parametrize("secret_field", ["APP_KEY", "API_KEY_PEPPER", "FERNET_SALT"])
def test_cluster_mode_refuses_placeholder_and_missing_secrets(secret_field: str):
    base_env = {
        "ZMQ_HOST": "127.0.0.1",
        "CHIRIFY_CLUSTER_MODE": "true",
        "FLASK_DEBUG": "false",
        "APP_KEY": "a" * 64,
        "API_KEY_PEPPER": "b" * 64,
        "FERNET_SALT": "c" * 32,
    }

    placeholder_env = {
        **base_env,
        secret_field: f"OPENALGO_PLACEHOLDER_{secret_field}_REGENERATE_BEFORE_USE",
    }
    violations = validate_startup_invariants(env=placeholder_env)
    assert any(secret_field in v for v in violations)

    missing_env = {**base_env, secret_field: ""}
    violations_missing = validate_startup_invariants(env=missing_env)
    assert any(secret_field in v for v in violations_missing)


def test_static_egress_verification_accepts_primary_and_secondary_and_rejects_stale_or_wrong_ip(
    tmp_path: Path,
):
    egress_file = tmp_path / "egress_verified.json"
    now = 1_795_244_400.0
    env = {
        "ZMQ_HOST": "127.0.0.1",
        "CHIRIFY_REQUIRE_STATIC_EGRESS": "true",
        "EXPECTED_EGRESS_IPV4": "13.232.100.10",
        "EXPECTED_SECONDARY_IPV4": "13.232.100.11",
    }

    # Missing file -> blocked
    v_missing = validate_startup_invariants(env=env, egress_state_path=egress_file, now_epoch=now)
    assert any("does not exist" in v for v in v_missing)

    # Valid primary IP within 300s -> allowed
    egress_file.write_text(
        json.dumps({"observed_ip": "13.232.100.10", "verified_at_epoch": now - 15.0}),
        encoding="utf-8",
    )
    assert (
        validate_startup_invariants(env=env, egress_state_path=egress_file, now_epoch=now) == []
    )

    # Valid secondary failover IP within 300s -> allowed
    egress_file.write_text(
        json.dumps({"observed_ip": "13.232.100.11", "verified_at": "2026-11-21T06:58:00Z"}),
        encoding="utf-8",
    )
    # 2026-11-21T07:00:00Z == 1795244400
    assert (
        validate_startup_invariants(env=env, egress_state_path=egress_file, now_epoch=now) == []
    )

    # Stale egress file (> 300s old) -> blocked
    egress_file.write_text(
        json.dumps({"observed_ip": "13.232.100.10", "verified_at_epoch": now - 600.0}),
        encoding="utf-8",
    )
    v_stale = validate_startup_invariants(env=env, egress_state_path=egress_file, now_epoch=now)
    assert any("stale" in v for v in v_stale)

    # Wrong observed IP -> blocked
    egress_file.write_text(
        json.dumps({"observed_ip": "52.66.99.99", "verified_at_epoch": now - 5.0}),
        encoding="utf-8",
    )
    v_wrong_ip = validate_startup_invariants(env=env, egress_state_path=egress_file, now_epoch=now)
    assert any("52.66.99.99" in v for v in v_wrong_ip)


def test_cli_entrypoint_exits_nonzero_on_violation():
    with pytest.raises(StartupInvariantError):
        enforce_startup_invariants(env={"ZMQ_HOST": "0.0.0.0"})

    bad_run = subprocess.run(
        [sys.executable, "-m", "utils.startup_invariants"],
        cwd=str(ROOT),
        env={"PATH": "", "PYTHONPATH": str(ROOT), "ZMQ_HOST": "0.0.0.0"},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert bad_run.returncode == 1
    assert "ZMQ_HOST" in bad_run.stderr
