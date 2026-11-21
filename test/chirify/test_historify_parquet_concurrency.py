"""PRR Tests: Lock-Free DuckDB-to-Parquet Concurrency & Presigned S3 Streaming."""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import duckdb
import httpx
import pandas as pd
import pyarrow.parquet as pq
import pytest

from database import historify_db
from services.qlib_snapshot_service import (
    EXPORT_COLUMNS,
    compute_file_sha256,
    export_historify_parquet,
    upload_to_presigned_url,
)


def _make_bars(base_ts: int, count: int, base_price: float) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "timestamp": base_ts + i * 60,
                "open": base_price + i,
                "high": base_price + i + 2.5,
                "low": base_price + i - 1.5,
                "close": base_price + i + 1.0,
                "volume": 1000 + i * 10,
                "oi": 500 + i,
            }
            for i in range(count)
        ]
    )


def test_concurrent_duckdb_readers_writers_and_zstd_parquet_snapshot_zero_lock_errors(
    tmp_path: Path, monkeypatch
):
    db_file = tmp_path / "historify_concurrent.duckdb"
    monkeypatch.setattr(historify_db, "HISTORIFY_DB_PATH", str(db_file))
    historify_db.init_database()

    # Keep one warm anchor connection open for the life of the test (mirrors a live
    # long-running OpenAlgo worker) and seed initial multi-symbol OHLCV candles.
    seed_symbols = ["RELIANCE", "INFY", "TCS"]
    base_epoch = 1_795_200_000
    for idx, sym in enumerate(seed_symbols):
        inserted = historify_db.upsert_market_data(
            _make_bars(base_epoch, 50, 1000.0 + idx * 500.0),
            symbol=sym,
            exchange="NSE",
            interval="1m",
        )
        assert inserted == 50

    errors: list[Exception] = []
    errors_lock = threading.Lock()
    stop_flag = threading.Event()

    def _record_err(exc: Exception) -> None:
        with errors_lock:
            errors.append(exc)

    def _writer_worker(worker_id: int) -> int:
        writes = 0
        sym = f"WRITER_{worker_id}"
        for batch in range(8):
            try:
                df = _make_bars(base_epoch + batch * 600, 10, 200.0 + worker_id * 10)
                historify_db.upsert_market_data(df, symbol=sym, exchange="NSE", interval="1m")
                writes += 1
            except Exception as exc:
                _record_err(exc)
        return writes

    def _reader_worker() -> int:
        reads = 0
        while not stop_flag.is_set():
            try:
                with historify_db.get_connection() as conn:
                    cnt = conn.execute("SELECT COUNT(*) FROM market_data").fetchone()[0]
                    assert cnt >= 150
                reads += 1
            except Exception as exc:
                _record_err(exc)
                break
        return reads

    def _exporter_worker(export_idx: int):
        out_file = tmp_path / f"snapshot_{export_idx}.parquet"
        try:
            return export_historify_parquet(out_file, db_path=db_file)
        except Exception as exc:
            _record_err(exc)
            raise

    with ThreadPoolExecutor(max_workers=8) as pool:
        reader_futures = [pool.submit(_reader_worker) for _ in range(2)]
        writer_futures = [pool.submit(_writer_worker, wid) for wid in range(2)]
        export_futures = [pool.submit(_exporter_worker, eid) for eid in range(4)]

        for wf in as_completed(writer_futures):
            assert wf.result() == 8
        export_results = [ef.result() for ef in export_futures]
        stop_flag.set()
        for rf in as_completed(reader_futures):
            assert rf.result() > 0

    assert errors == [], f"Expected 0 DuckDB lock/concurrency errors, got: {errors}"

    # Final deterministic export after writers settled (3 seed * 50 + 2 writers * 80 = 310 rows, 5 symbols)
    final_parquet = tmp_path / "final_qlib.parquet"
    uploaded_payloads: list[tuple[dict[str, str], bytes]] = []

    def _mock_s3(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        body = request.read()
        uploaded_payloads.append((dict(request.headers), body))
        return httpx.Response(200, text="")

    mock_client = httpx.Client(transport=httpx.MockTransport(_mock_s3))
    snapshot = export_historify_parquet(
        final_parquet,
        db_path=db_file,
        presigned_url="https://s3.eu-central-1.amazonaws.com/chirify-qlib/snapshots/final.parquet?X-Amz-Signature=abc",
        http_client=mock_client,
    )

    assert snapshot.row_count == 310
    assert snapshot.symbol_count == 5
    assert snapshot.compression == "ZSTD"
    assert snapshot.uploaded is True
    assert snapshot.upload_status_code == 200
    assert snapshot.min_timestamp_utc is not None and snapshot.min_timestamp_utc.endswith("Z")
    assert snapshot.max_timestamp_utc is not None and snapshot.max_timestamp_utc.endswith("Z")

    # Verify SHA-256 matches both disk file and uploaded S3 stream bytes
    expected_sha = hashlib.sha256(final_parquet.read_bytes()).hexdigest()
    assert snapshot.sha256 == expected_sha
    assert compute_file_sha256(final_parquet) == expected_sha
    assert len(uploaded_payloads) == 1
    s3_headers, s3_bytes = uploaded_payloads[0]
    assert s3_headers["x-amz-meta-sha256"] == expected_sha
    assert hashlib.sha256(s3_bytes).hexdigest() == expected_sha

    # Verify Parquet metadata & ZSTD compression via PyArrow
    pf = pq.ParquetFile(final_parquet)
    assert pf.metadata.num_rows == 310
    assert tuple(pf.schema_arrow.names) == EXPORT_COLUMNS
    assert pf.metadata.row_group(0).column(0).compression == "ZSTD"

    # Verify DuckDB native Parquet readback
    readback_count = duckdb.sql(
        f"SELECT COUNT(*) FROM read_parquet('{final_parquet}')"
    ).fetchall()[0][0]
    assert readback_count == 310

    # Also verify every intermediate concurrent snapshot is a valid, consistent Parquet file
    for snap in export_results:
        table = pq.read_table(snap.parquet_path)
        assert table.num_rows == snap.row_count
        assert snap.row_count >= 150


def test_presigned_upload_refuses_plaintext_http(tmp_path: Path):
    dummy = tmp_path / "sample.parquet"
    dummy.write_bytes(b"PAR1dummyPAR1")
    with pytest.raises(ValueError, match="https://"):
        upload_to_presigned_url(dummy, "http://insecure.example.com/upload.parquet")
