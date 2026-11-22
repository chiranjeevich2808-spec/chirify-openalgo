"""5-Year Regulatory Hash-Chained UTC WORM Audit Writer & Chain Verifier.

Emits append-only UTC ISO-8601 JSON Lines records to ``CHIRIFY_WORM_LOG_PATH``
(default ``/app/log/worm_audit.jsonl``) for SEBI / MiFID II / SEC FINRA 5-year
audit-trail retention.

Security & Integrity Guarantees:
1. **Strict UTC Timestamps**: Every event carries ``timestamp_utc`` formatted as
   ``YYYY-MM-DDTHH:MM:SS.ffffffZ``.
2. **Recursive Credential Redaction**: Sensitive keys (``apikey``, ``api_secret``,
   ``access_token``, ``password``, ``totp``, ``authorization``, etc.) are
   recursively replaced with ``"[REDACTED]"`` before hashing or disk I/O.
3. **Cryptographic Hash Chaining**:
   - ``seq_no``: Strictly monotonic 1-based integer (``1, 2, 3, ...``).
   - ``prev_hash``: 64-char hex digest of the preceding record (``"0" * 64``
     for genesis ``seq_no == 1``).
   - ``record_hash``: ``sha256(canonical_json_without_record_hash)``.
4. **Tamper Detection**: :func:`verify_worm_chain` validates ``seq_no``
   continuity, ``prev_hash`` linkage, and ``record_hash`` digests across the
   entire JSONL file, immediately catching byte edits, line deletions,
   truncation of genesis, or line reordering.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows compatibility
    fcntl = None  # type: ignore[assignment]

from utils import real_threading
from utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_WORM_LOG_PATH = "/app/log/worm_audit.jsonl"
GENESIS_PREV_HASH = "0" * 64
REDACTED_VALUE = "[REDACTED]"

# Normalized (lowercase, underscores/hyphens stripped) sensitive key identifiers
_SENSITIVE_KEY_NORMS: frozenset[str] = frozenset(
    {
        "apikey",
        "apisecret",
        "accesstoken",
        "refreshtoken",
        "password",
        "passwd",
        "totp",
        "totpsecret",
        "authorization",
        "clientsecret",
        "secretkey",
        "privatekey",
        "bearertoken",
        "authtoken",
        "feedtoken",
        "webhooktoken",
        "confirmationtoken",
        "approvaltoken",
        "entitlementtoken",
        "ssoticket",
        "launchticket",
    }
)
_SENSITIVE_KEY_SUFFIXES: tuple[str, ...] = (
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
    "ticket",
    "cookie",
)
_NON_SENSITIVE_METADATA_NORMS: frozenset[str] = frozenset(
    {
        "tokencount",
        "prompttokens",
        "completiontokens",
        "totaltokens",
        "maxtokens",
        "tokenbudget",
        "hasentitlementtoken",
        "hasapikey",
        "hastoken",
    }
)

_PATH_LOCKS_GUARD = real_threading.Lock()
_PATH_LOCKS: dict[Path, real_threading.RLock] = {}


def _get_path_lock(path: Path) -> real_threading.RLock:
    resolved = path.resolve()
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(resolved)
        if lock is None:
            if len(_PATH_LOCKS) >= 512:
                _PATH_LOCKS.clear()
            lock = real_threading.RLock()
            _PATH_LOCKS[resolved] = lock
        return lock


@dataclass(frozen=True, slots=True)
class WormAuditRecord:
    """In-memory representation of a committed WORM audit record."""

    seq_no: int
    timestamp_utc: str
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq_no": self.seq_no,
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


@dataclass(frozen=True, slots=True)
class WormChainVerification:
    """Result returned by :func:`verify_worm_chain`."""

    valid: bool
    records_checked: int
    head_hash: str
    error: str | None = None
    failed_line: int | None = None
    failed_seq_no: int | None = None

    def __bool__(self) -> bool:
        return self.valid


def _normalize_key_name(key: str) -> str:
    return key.strip().lower().replace("_", "").replace("-", "")


def _is_sensitive_key(norm_key: str, raw_value: Any) -> bool:
    if norm_key in _SENSITIVE_KEY_NORMS:
        return True
    if norm_key in _NON_SENSITIVE_METADATA_NORMS:
        return False
    if isinstance(raw_value, bool | int | float) or raw_value is None:
        return False
    return norm_key.endswith(_SENSITIVE_KEY_SUFFIXES)


def redact_sensitive_fields(value: Any) -> Any:
    """Recursively redact credentials and secrets from arbitrary structures."""
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for raw_k, raw_v in value.items():
            key_str = str(raw_k)
            if _is_sensitive_key(_normalize_key_name(key_str), raw_v):
                sanitized[key_str] = REDACTED_VALUE
            else:
                sanitized[key_str] = redact_sensitive_fields(raw_v)
        return sanitized
    if isinstance(value, list | tuple):
        return [redact_sensitive_fields(item) for item in value]
    if isinstance(value, set | frozenset):
        return [redact_sensitive_fields(item) for item in sorted(value, key=str)]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def canonical_json_without_hash(record: Mapping[str, Any]) -> str:
    """Serialize a WORM record (excluding ``record_hash``) into canonical deterministic JSON."""
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_record_hash(record_without_hash: Mapping[str, Any]) -> str:
    """Compute lowercase 64-char SHA-256 hex digest over canonical JSON without ``record_hash``."""
    canonical = canonical_json_without_hash(record_without_hash)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utc_iso_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class WormAuditWriter:
    """Thread-safe and multi-process-safe append-only hash-chained WORM JSONL writer."""

    def __init__(self, log_path: str | Path | None = None, *, fsync: bool = True) -> None:
        self._explicit_path = Path(log_path) if log_path is not None else None
        self._fsync = fsync
        self._lock = real_threading.RLock()
        self._initialized_path: Path | None = None
        self._last_synced_size: int = -1
        self._next_seq_no: int = 1
        self._last_hash: str = GENESIS_PREV_HASH

    def resolve_path(self) -> Path:
        """Return explicit log path or current ``CHIRIFY_WORM_LOG_PATH`` env path."""
        if self._explicit_path is not None:
            return self._explicit_path
        raw = os.getenv("CHIRIFY_WORM_LOG_PATH", DEFAULT_WORM_LOG_PATH).strip()
        return Path(raw or DEFAULT_WORM_LOG_PATH)

    def _sync_chain_state_locked(self, path: Path, *, current_size: int | None = None) -> None:
        """Initialize or resume ``seq_no`` and ``prev_hash`` from an existing JSONL file."""
        stat_size = current_size if current_size is not None else (path.stat().st_size if path.exists() else 0)
        if self._initialized_path == path and stat_size == self._last_synced_size and path.exists():
            return

        if stat_size == 0 or not path.exists():
            self._next_seq_no = 1
            self._last_hash = GENESIS_PREV_HASH
            self._initialized_path = path
            self._last_synced_size = 0
            return

        last_non_empty = ""
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_non_empty = stripped

        if not last_non_empty:
            self._next_seq_no = 1
            self._last_hash = GENESIS_PREV_HASH
        else:
            parsed = json.loads(last_non_empty)
            self._next_seq_no = int(parsed["seq_no"]) + 1
            self._last_hash = str(parsed["record_hash"])
        self._initialized_path = path
        self._last_synced_size = stat_size

    def append(self, event_type: str, payload: Mapping[str, Any] | None = None) -> WormAuditRecord:
        """Redact, hash-chain, and atomically append a UTC event line to the WORM log."""
        clean_event_type = str(event_type or "audit.event").strip()
        redacted_payload = redact_sensitive_fields(dict(payload or {}))
        target_path = self.resolve_path()
        path_lock = _get_path_lock(target_path)

        with path_lock, self._lock:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target_path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                current_size = os.fstat(fd).st_size
                self._sync_chain_state_locked(target_path, current_size=current_size)

                seq_no = self._next_seq_no
                prev_hash = self._last_hash
                ts_utc = _utc_iso_now()

                unsigned = {
                    "seq_no": seq_no,
                    "timestamp_utc": ts_utc,
                    "event_type": clean_event_type,
                    "payload": redacted_payload,
                    "prev_hash": prev_hash,
                }
                record_hash = compute_record_hash(unsigned)
                signed = {**unsigned, "record_hash": record_hash}
                serialized_line = (
                    json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
                )

                os.write(fd, serialized_line.encode("utf-8"))
                if self._fsync:
                    os.fsync(fd)

                self._next_seq_no = seq_no + 1
                self._last_hash = record_hash
                self._last_synced_size = os.fstat(fd).st_size
            finally:
                if fcntl is not None:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(fd)

        return WormAuditRecord(
            seq_no=seq_no,
            timestamp_utc=ts_utc,
            event_type=clean_event_type,
            payload=redacted_payload,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )


_default_writer = WormAuditWriter()


def emit_worm_audit_event(
    event_type: str,
    payload: Mapping[str, Any] | None = None,
    *,
    writer: WormAuditWriter | None = None,
) -> WormAuditRecord:
    """Emit a single hash-chained UTC WORM audit record."""
    active_writer = writer if writer is not None else _default_writer
    return active_writer.append(event_type, payload)


def on_bus_event(event: Any) -> None:
    """EventBus subscriber callback converting OpenAlgo order/GTT events to WORM records."""
    topic = str(getattr(event, "topic", "") or "bus.event")
    payload: dict[str, Any] = {}
    for attr in ("mode", "api_type", "request_data", "response_data", "user_id", "broker"):
        val = getattr(event, attr, None)
        if val is not None:
            payload[attr] = val
    try:
        emit_worm_audit_event(topic, payload)
    except Exception:
        logger.exception(f"Failed to append WORM audit record for topic {topic}")


def verify_worm_chain(jsonl_path: str | Path) -> WormChainVerification:
    """Verify cryptographic hash-chain integrity and monotonic ``seq_no`` continuity.

    Detects:
    - Modified characters/fields in any line (``record_hash`` mismatch).
    - Deleted first, middle, or arbitrary lines (``seq_no`` gap or ``prev_hash`` break).
    - Reordered or inserted lines (``seq_no`` or ``prev_hash`` break).
    - Corrupted/non-JSON lines.
    """
    path = Path(jsonl_path)
    if not path.is_file():
        return WormChainVerification(
            valid=False,
            records_checked=0,
            head_hash=GENESIS_PREV_HASH,
            error=f"WORM audit log file not found: {path}",
        )

    expected_seq = 1
    expected_prev_hash = GENESIS_PREV_HASH
    records_checked = 0

    with open(path, encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            stripped = raw_line.rstrip("\r\n")
            if not stripped:
                return WormChainVerification(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_prev_hash,
                    error=f"Unexpected blank line at line {line_no}",
                    failed_line=line_no,
                )

            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return WormChainVerification(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_prev_hash,
                    error=f"Malformed JSON at line {line_no}: {exc}",
                    failed_line=line_no,
                )

            if not isinstance(record, Mapping):
                return WormChainVerification(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_prev_hash,
                    error=f"Record at line {line_no} is not a JSON object",
                    failed_line=line_no,
                )

            seq_no = record.get("seq_no")
            if not isinstance(seq_no, int) or isinstance(seq_no, bool) or seq_no != expected_seq:
                return WormChainVerification(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_prev_hash,
                    error=(
                        f"Sequence discontinuity at line {line_no}: "
                        f"expected seq_no={expected_seq}, got {seq_no!r}"
                    ),
                    failed_line=line_no,
                    failed_seq_no=seq_no if isinstance(seq_no, int) else None,
                )

            prev_hash = str(record.get("prev_hash") or "")
            if not hmac.compare_digest(prev_hash, expected_prev_hash):
                return WormChainVerification(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_prev_hash,
                    error=(
                        f"Broken prev_hash link at line {line_no} (seq_no={seq_no}): "
                        f"expected {expected_prev_hash}, got {prev_hash!r}"
                    ),
                    failed_line=line_no,
                    failed_seq_no=seq_no,
                )

            stored_hash = str(record.get("record_hash") or "")
            computed_hash = compute_record_hash(record)
            if len(stored_hash) != 64 or not hmac.compare_digest(stored_hash, computed_hash):
                return WormChainVerification(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_prev_hash,
                    error=(
                        f"Record hash mismatch at line {line_no} (seq_no={seq_no}): "
                        "tampering detected"
                    ),
                    failed_line=line_no,
                    failed_seq_no=seq_no,
                )

            expected_prev_hash = stored_hash
            expected_seq += 1
            records_checked += 1

    return WormChainVerification(
        valid=True,
        records_checked=records_checked,
        head_hash=expected_prev_hash,
    )
