"""Lock-free DuckDB-to-Parquet OHLCV Snapshot Exporter for Qlib / Research Workers.

Exports candles (``timestamp``, ``symbol``, ``exchange``, ``interval``, ``open``,
``high``, ``low``, ``close``, ``volume``, ``oi``) from Historify's DuckDB
``market_data`` table using DuckDB's native MVCC snapshot reader and vectorized
``COPY (...) TO '<path>.parquet' (FORMAT PARQUET, COMPRESSION ZSTD)`` engine.

Concurrency design:
- Opens an in-process DuckDB connection with the exact same configuration mode
  as :mod:`database.historify_db` (never mixing ``read_only=True`` with open
  read-write connections in the same process, which DuckDB forbids).
- Wraps the metadata aggregation and ``COPY (...) TO`` inside a single MVCC read
  transaction so ``row_count``, ``symbol_count``, ``min_timestamp_utc``, and
  ``max_timestamp_utc`` are 100% consistent with the exported Parquet rows even
  while writer threads concurrently upsert new bars under ``_historify_write_lock``.
- Writes to a unique sibling temporary file first and atomically ``os.replace``s
  the destination path so downstream consumers never observe partial files.
- Optionally streams the finished Parquet artifact in fixed-size chunks via
  ``httpx`` ``PUT`` to a presigned S3/R2 object-storage URL.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import httpx

from database import historify_db
from utils.logging import get_logger

logger = get_logger(__name__)

EXPORT_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "symbol",
    "exchange",
    "interval",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "oi",
)

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:&/-]{1,64}$")
_STREAM_CHUNK_BYTES = 1024 * 1024  # 1 MiB streaming chunks


@dataclass(frozen=True, slots=True)
class ParquetSnapshotResult:
    """Metadata and integrity digest for an exported Historify Parquet snapshot."""

    parquet_path: str
    sha256: str
    size_bytes: int
    row_count: int
    symbol_count: int
    min_timestamp_epoch: int | None
    max_timestamp_epoch: int | None
    min_timestamp_utc: str | None
    max_timestamp_utc: str | None
    compression: str = "ZSTD"
    uploaded: bool = False
    upload_status_code: int | None = None

    def as_dict(self) -> dict[str, Any]:
        """Convert snapshot metadata to a JSON-serializable dictionary."""
        return asdict(self)


def _resolve_duckdb_path(db_path: str | Path | None = None) -> str:
    """Resolve the active Historify DuckDB path."""
    if db_path is not None:
        return str(Path(db_path).resolve())
    # Respect runtime monkeypatching of historify_db.HISTORIFY_DB_PATH or env override
    if historify_db.HISTORIFY_DB_PATH != "db/historify.duckdb":
        return historify_db.get_db_path()
    env_override = os.getenv("HISTORIFY_DATABASE_PATH", "").strip()
    if env_override:
        if os.path.isabs(env_override):
            return env_override
        return str((Path(historify_db.__file__).resolve().parents[1] / env_override).resolve())
    return historify_db.get_db_path()


def _sql_quote(token: str, field_name: str) -> str:
    """Validate and quote a filter literal safely for DuckDB ``COPY (...)`` SQL."""
    cleaned = str(token).strip()
    if not _SAFE_TOKEN_RE.match(cleaned):
        raise ValueError(f"Unsafe or malformed {field_name} filter value: {token!r}")
    escaped = cleaned.replace("'", "''")
    return f"'{escaped}'"


def _epoch_to_utc_iso(value: Any) -> tuple[int | None, str | None]:
    """Normalize a DuckDB epoch seconds/ms integer or datetime to (epoch_sec, ISO-8601Z)."""
    if value is None:
        return None, None
    if isinstance(value, datetime):
        dt = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return int(dt.timestamp()), dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    epoch = int(value)
    # Heuristic: values > 10^11 are milliseconds epoch
    epoch_sec = epoch // 1000 if abs(epoch) > 100_000_000_000 else epoch
    dt = datetime.fromtimestamp(epoch_sec, tz=UTC)
    return epoch_sec, dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_file_sha256(path: str | Path) -> str:
    """Compute hex SHA-256 digest of a file in streaming chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_STREAM_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_file_chunks(path: Path, chunk_size: int = _STREAM_CHUNK_BYTES) -> Iterator[bytes]:
    """Yield binary chunks from ``path`` without buffering the full Parquet file in RAM."""
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            yield chunk


def upload_to_presigned_url(
    parquet_path: str | Path,
    presigned_url: str,
    *,
    sha256_hex: str | None = None,
    client: httpx.Client | None = None,
    timeout: float = 120.0,
    allow_insecure_http: bool = False,
) -> int:
    """Stream a Parquet snapshot via HTTP PUT to a presigned S3/R2 object-storage URL.

    Args:
        parquet_path: Local Parquet file to upload.
        presigned_url: Presigned HTTPS PUT URL.
        sha256_hex: Precomputed SHA-256 hex digest attached as ``x-amz-meta-sha256``.
        client: Optional ``httpx.Client`` (e.g. ``MockTransport`` in tests).
        timeout: Upload timeout in seconds.
        allow_insecure_http: Keep ``False`` in production; only allows ``https://``.

    Returns:
        HTTP status code returned by the object store (e.g. ``200``).
    """
    file_path = Path(parquet_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Parquet file does not exist: {file_path}")

    clean_url = (presigned_url or "").strip()
    if not clean_url:
        raise ValueError("presigned_url must be non-empty.")
    if not allow_insecure_http and not clean_url.lower().startswith("https://"):
        raise ValueError("presigned_url must use https:// transport.")

    digest = sha256_hex or compute_file_sha256(file_path)
    size_bytes = file_path.stat().st_size
    headers = {
        "Content-Type": "application/vnd.apache.parquet",
        "Content-Length": str(size_bytes),
        "x-amz-meta-sha256": digest,
    }

    owns_client = client is None
    active_client = client if client is not None else httpx.Client(timeout=timeout)
    try:
        response = active_client.put(
            clean_url,
            content=_iter_file_chunks(file_path),
            headers=headers,
            timeout=timeout,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"Presigned Parquet PUT failed with HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )
        return int(response.status_code)
    finally:
        if owns_client:
            active_client.close()


def _connect_duckdb_with_retry(
    resolved_db_path: str,
    *,
    max_retries: int = 8,
    base_delay: float = 0.02,
) -> duckdb.DuckDBPyConnection:
    """Open an isolated in-process DuckDB cursor sharing Historify's warm anchor connection."""
    db_dir = os.path.dirname(resolved_db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return historify_db.acquire_duckdb_cursor(
        resolved_db_path,
        max_retries=max_retries,
        retry_delay=base_delay,
    )


def export_historify_parquet(
    output_path: str | Path,
    *,
    db_path: str | Path | None = None,
    symbols: Sequence[str] | None = None,
    exchange: str | None = None,
    interval: str | None = None,
    start_timestamp: int | None = None,
    end_timestamp: int | None = None,
    presigned_url: str | None = None,
    http_client: httpx.Client | None = None,
) -> ParquetSnapshotResult:
    """Export Historify ``market_data`` OHLCV candles to a ZSTD-compressed Parquet file.

    Args:
        output_path: Destination ``.parquet`` file path.
        db_path: Optional explicit DuckDB path (defaults to Historify DB path).
        symbols: Optional list of symbols to filter (case-insensitive).
        exchange: Optional exchange code filter (e.g. ``"NSE"`` or ``"US_EQUITY"``).
        interval: Optional bar interval filter (e.g. ``"1m"``, ``"D"``).
        start_timestamp: Optional inclusive minimum epoch seconds filter.
        end_timestamp: Optional inclusive maximum epoch seconds filter.
        presigned_url: Optional presigned S3/R2 HTTPS URL to PUT the snapshot to.
        http_client: Optional ``httpx.Client`` used when ``presigned_url`` is supplied.

    Returns:
        :class:`ParquetSnapshotResult` with SHA-256 digest, row/symbol counts,
        and UTC timestamp bounds.
    """
    target_path = Path(output_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.parent / f".{target_path.name}.tmp.{uuid.uuid4().hex}.parquet"

    where_clauses: list[str] = []
    if symbols:
        quoted_syms = ", ".join(_sql_quote(s.upper(), "symbol") for s in symbols if s and s.strip())
        if quoted_syms:
            where_clauses.append(f"UPPER(symbol) IN ({quoted_syms})")
    if exchange and exchange.strip():
        where_clauses.append(f"UPPER(exchange) = {_sql_quote(exchange.upper(), 'exchange')}")
    if interval and interval.strip():
        where_clauses.append(f"interval = {_sql_quote(interval, 'interval')}")
    if start_timestamp is not None:
        where_clauses.append(f"timestamp >= {int(start_timestamp)}")
    if end_timestamp is not None:
        where_clauses.append(f"timestamp <= {int(end_timestamp)}")

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    select_sql = (
        "SELECT timestamp, symbol, exchange, interval, open, high, low, close, "
        f"volume, COALESCE(oi, 0) AS oi FROM market_data {where_sql} "
        "ORDER BY symbol, exchange, interval, timestamp"
    )
    stats_sql = (
        "SELECT COUNT(*) AS row_count, COUNT(DISTINCT symbol) AS symbol_count, "
        f"MIN(timestamp) AS min_ts, MAX(timestamp) AS max_ts FROM market_data {where_sql}"
    )

    escaped_tmp = str(tmp_path).replace("'", "''")
    copy_sql = f"COPY ({select_sql}) TO '{escaped_tmp}' (FORMAT PARQUET, COMPRESSION ZSTD)"

    resolved_db = _resolve_duckdb_path(db_path)

    def _run_coordinated_copy() -> tuple[Any, ...]:
        with historify_db._historify_write_lock:
            conn = _connect_duckdb_with_retry(resolved_db)
            try:
                conn.execute("BEGIN TRANSACTION")
                try:
                    row = conn.execute(stats_sql).fetchone()
                    conn.execute(copy_sql)
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise
                return row or (0, 0, None, None)
            finally:
                conn.close()

    from utils import real_threading

    try:
        stats_row = real_threading.run_on_hub(_run_coordinated_copy, timeout=None)
        os.replace(tmp_path, target_path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    row_count = int(stats_row[0] or 0) if stats_row else 0
    symbol_count = int(stats_row[1] or 0) if stats_row else 0
    min_epoch, min_utc = _epoch_to_utc_iso(stats_row[2] if stats_row else None)
    max_epoch, max_utc = _epoch_to_utc_iso(stats_row[3] if stats_row else None)

    sha256_hex = compute_file_sha256(target_path)
    size_bytes = target_path.stat().st_size

    uploaded = False
    upload_status: int | None = None
    if presigned_url:
        upload_status = upload_to_presigned_url(
            target_path,
            presigned_url,
            sha256_hex=sha256_hex,
            client=http_client,
        )
        uploaded = True

    logger.info(
        f"Exported Historify Parquet snapshot to {target_path} "
        f"(rows={row_count}, symbols={symbol_count}, sha256={sha256_hex[:12]}...)"
    )
    return ParquetSnapshotResult(
        parquet_path=str(target_path),
        sha256=sha256_hex,
        size_bytes=size_bytes,
        row_count=row_count,
        symbol_count=symbol_count,
        min_timestamp_epoch=min_epoch,
        max_timestamp_epoch=max_epoch,
        min_timestamp_utc=min_utc,
        max_timestamp_utc=max_utc,
        compression="ZSTD",
        uploaded=uploaded,
        upload_status_code=upload_status,
    )
