"""PRR Tests: 5-Year Hash-Chained UTC WORM Audit & `/internal/v1/failover-reconcile`."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask import Flask

from blueprints.internal_ops import internal_ops_bp
from services.strategy_module import ack_reconciliation
from services.strategy_module.ack_reconciliation import (
    AckRepairSummary,
    OpenRunAckRepairSummary,
)
from subscribers.worm_audit_subscriber import (
    GENESIS_PREV_HASH,
    REDACTED_VALUE,
    WormAuditWriter,
    verify_worm_chain,
)


def test_worm_audit_redacts_secrets_maintains_monotonic_seq_and_verifies_hash_chain(
    tmp_path: Path,
):
    worm_file = tmp_path / "worm_audit.jsonl"
    writer = WormAuditWriter(worm_file)

    r1 = writer.append(
        "order.placed",
        {
            "symbol": "INFY",
            "apikey": "super-secret-oa-key-111",
            "nested": {
                "api_secret": "raw-broker-secret-222",
                "access_token": "eyJhbGciOi...",
                "password": "hunter2-password",
                "totp": "123456",
                "Authorization": "Bearer live-secret-token",
                "quantity": 25,
            },
        },
    )
    assert r1.seq_no == 1
    assert r1.prev_hash == GENESIS_PREV_HASH
    assert r1.timestamp_utc.endswith("Z")
    assert r1.payload["apikey"] == REDACTED_VALUE
    assert r1.payload["nested"]["api_secret"] == REDACTED_VALUE
    assert r1.payload["nested"]["access_token"] == REDACTED_VALUE
    assert r1.payload["nested"]["password"] == REDACTED_VALUE
    assert r1.payload["nested"]["totp"] == REDACTED_VALUE
    assert r1.payload["nested"]["Authorization"] == REDACTED_VALUE
    assert r1.payload["nested"]["quantity"] == 25

    # Concurrent multi-threaded writes preserve strict seq_no & hash chain
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(writer.append, "order.modified", {"idx": i, "apikey": f"leak-{i}"})
            for i in range(15)
        ]
        for f in futures:
            f.result()

    # Re-open a fresh writer instance against the existing log (simulates pod restart)
    reopened = WormAuditWriter(worm_file)
    r17 = reopened.append("position.closed", {"symbol": "INFY"})
    assert r17.seq_no == 17

    raw_disk = worm_file.read_text(encoding="utf-8")
    for leaked in (
        "super-secret-oa-key-111",
        "raw-broker-secret-222",
        "eyJhbGciOi",
        "hunter2-password",
        "live-secret-token",
        "leak-0",
    ):
        assert leaked not in raw_disk

    verification = verify_worm_chain(worm_file)
    assert verification.valid is True
    assert verification.records_checked == 17
    assert verification.head_hash == r17.record_hash


def test_worm_chain_detects_byte_tampering_line_deletion_and_reordering(tmp_path: Path):
    worm_file = tmp_path / "tamper_test.jsonl"
    writer = WormAuditWriter(worm_file)
    for i in range(5):
        writer.append("order.placed", {"symbol": f"SYM{i}", "qty": i + 1})

    original_lines = worm_file.read_text(encoding="utf-8").splitlines()
    assert verify_worm_chain(worm_file).valid is True

    # 1. Modify a single value on line 3 -> detected!
    tampered_edit = list(original_lines)
    rec3 = json.loads(tampered_edit[2])
    rec3["payload"]["qty"] = 9999
    tampered_edit[2] = json.dumps(rec3, sort_keys=True, separators=(",", ":"))
    edited_path = tmp_path / "edited.jsonl"
    edited_path.write_text("\n".join(tampered_edit) + "\n", encoding="utf-8")
    res_edit = verify_worm_chain(edited_path)
    assert res_edit.valid is False
    assert res_edit.failed_line == 3

    # 2. Delete middle line (line 2) -> detected!
    deleted_mid_path = tmp_path / "deleted_mid.jsonl"
    deleted_mid_path.write_text(
        "\n".join([original_lines[0], *original_lines[2:]]) + "\n", encoding="utf-8"
    )
    res_del_mid = verify_worm_chain(deleted_mid_path)
    assert res_del_mid.valid is False
    assert res_del_mid.failed_line == 2

    # 3. Delete genesis line (line 1) -> detected!
    deleted_gen_path = tmp_path / "deleted_genesis.jsonl"
    deleted_gen_path.write_text("\n".join(original_lines[1:]) + "\n", encoding="utf-8")
    res_del_gen = verify_worm_chain(deleted_gen_path)
    assert res_del_gen.valid is False
    assert res_del_gen.failed_line == 1

    # 4. Reorder lines 3 and 4 -> detected!
    reordered = list(original_lines)
    reordered[2], reordered[3] = reordered[3], reordered[2]
    reordered_path = tmp_path / "reordered.jsonl"
    reordered_path.write_text("\n".join(reordered) + "\n", encoding="utf-8")
    res_reord = verify_worm_chain(reordered_path)
    assert res_reord.valid is False


def test_internal_ops_failover_reconcile_auth_ip_restriction_and_worm_emission(
    tmp_path: Path, monkeypatch
):
    worm_path = tmp_path / "failover_worm.jsonl"
    egress_path = tmp_path / "egress_verified.json"
    egress_path.write_text(json.dumps({"observed_ip": "13.232.100.11"}), encoding="utf-8")

    monkeypatch.setenv("CHIRIFY_WORM_LOG_PATH", str(worm_path))
    monkeypatch.setenv("CHIRIFY_EGRESS_STATE_PATH", str(egress_path))
    monkeypatch.setenv("CHIRIFY_REQUIRE_STATIC_EGRESS", "true")
    monkeypatch.setenv("EXPECTED_EGRESS_IPV4", "13.232.100.10")
    monkeypatch.setenv("EXPECTED_SECONDARY_IPV4", "13.232.100.11")

    app = Flask(__name__)
    app.register_blueprint(internal_ops_bp)
    client = app.test_client()

    # 1. Token not configured -> fails closed (503)
    monkeypatch.delenv("CHIRIFY_INTERNAL_OPS_TOKEN", raising=False)
    r_disabled = client.post(
        "/internal/v1/failover-reconcile",
        headers={"Authorization": "Bearer anything"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert r_disabled.status_code == 503

    monkeypatch.setenv("CHIRIFY_INTERNAL_OPS_TOKEN", "ops-secret-token-2026")

    # 2. Public internet IP rejected (403) even with valid token and spoofed X-Forwarded-For!
    r_pub_ip = client.post(
        "/internal/v1/failover-reconcile",
        headers={
            "Authorization": "Bearer ops-secret-token-2026",
            "X-Forwarded-For": "127.0.0.1",
        },
        environ_base={"REMOTE_ADDR": "203.0.113.55"},
    )
    assert r_pub_ip.status_code == 403
    assert r_pub_ip.get_json()["code"] == "forbidden_ip"

    # 3. Missing token -> 401; wrong token -> 403
    r_missing = client.post(
        "/internal/v1/failover-reconcile",
        environ_base={"REMOTE_ADDR": "10.244.1.9"},
    )
    assert r_missing.status_code == 401

    r_bad_tok = client.post(
        "/internal/v1/failover-reconcile",
        headers={"Authorization": "Bearer wrong-token"},
        environ_base={"REMOTE_ADDR": "10.244.1.9"},
    )
    assert r_bad_tok.status_code == 403

    # 4. Egress health check passes on secondary IP
    r_egress = client.get(
        "/internal/v1/health/egress",
        headers={"Authorization": "Bearer ops-secret-token-2026"},
        environ_base={"REMOTE_ADDR": "10.244.1.9"},
    )
    assert r_egress.status_code == 200
    assert r_egress.get_json()["matched"] is True

    # 5. Valid failover-reconcile invokes ack_reconciliation and appends hash-chained WORM event
    monkeypatch.setattr(
        ack_reconciliation,
        "reconcile_open_runs",
        lambda **kwargs: OpenRunAckRepairSummary(
            examined=3, repaired=2, already_bound=1, unresolved=0, polled=2, folded=2, failed=0
        ),
    )
    r_ok = client.post(
        "/internal/v1/failover-reconcile",
        json={"old_egress_ip": "13.232.100.10", "new_egress_ip": "13.232.100.11"},
        headers={"Authorization": "Bearer ops-secret-token-2026"},
        environ_base={"REMOTE_ADDR": "10.244.1.9"},
    )
    assert r_ok.status_code == 200
    body = r_ok.get_json()
    assert body["event"] == "cilium_egress_failover_reconciled"
    assert body["metrics"]["examined"] == 3
    assert body["metrics"]["repaired"] == 2

    # Explicit run_ids path also calls ack_reconciliation.reconcile(run_id)
    reconciled_ids: list[int] = []
    monkeypatch.setattr(
        ack_reconciliation,
        "reconcile",
        lambda rid, **kw: (reconciled_ids.append(rid) or AckRepairSummary(total=1, repaired=1)),
    )
    r_explicit = client.post(
        "/internal/v1/failover-reconcile",
        json={"run_ids": [101, 102]},
        headers={"X-Chirify-Internal-Token": "ops-secret-token-2026"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert r_explicit.status_code == 200
    assert reconciled_ids == [101, 102]
    assert r_explicit.get_json()["metrics"]["repaired"] == 2

    chain = verify_worm_chain(worm_path)
    assert chain.valid is True
    assert chain.records_checked == 2
