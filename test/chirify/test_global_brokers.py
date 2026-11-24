"""PRR Tests: Global Multi-Asset Brokers (`alpaca`, `ibkr`, `ccxt`) & Plugin Discovery."""

from __future__ import annotations

import json
import random
import socket
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
import zmq
from flask import Flask

from broker.alpaca.api.auth_api import (
    LIVE_TRADING_BASE_URL,
    PAPER_TRADING_BASE_URL,
    AlpacaEnvironmentMismatchError,
    resolve_alpaca_environment,
)
from broker.alpaca.api.order_api import place_order_api as alpaca_place_order
from broker.alpaca.api.rate_limiter import (
    AlpacaRateLimitError,
    TokenBucketLimiter,
    exponential_backoff_with_jitter,
)
from broker.alpaca.streaming.alpaca_ws_bridge import (
    FAKEPACA_SYMBOL,
    AlpacaSingleConnectionError,
    AlpacaSubscriptionLimitError,
    AlpacaWebSocketBridge,
)
from broker.ccxt.api.precision_and_nonce import (
    ApiKeyNonceLockRegistry,
    CCXTConfigError,
    CCXTPrecisionError,
    DuplicateApiKeyNonceError,
    PreciseFormatter,
    build_ccxt_exchange_config,
    configure_sandbox_mode,
    contracts_to_base_amount,
    normalize_contract_quantity,
)
from broker.ccxt.streaming.ccxt_ws_bridge import CCXTWebSocketBridge
from broker.ibkr.api.oauth_web_api import (
    IBKRCompetingSessionError,
    IBKROAuthWebClient,
    IBKRTickleScheduler,
    SingleBrokerageSessionGuard,
)
from broker.ibkr.api.tws_gateway_probe import (
    IBKRPacingLimitError,
    Sunday2FAScheduler,
    TWSGatewayReadinessProbe,
    TWSPacingGovernor,
)
from utils.plugin_loader import load_broker_auth_functions, load_broker_capabilities

ROOT = Path(__file__).resolve().parents[2]


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# =============================================================================
# 1. OpenAlgo Plugin Discovery (`utils/plugin_loader.py`)
# =============================================================================


def test_plugin_loader_discovers_alpaca_ibkr_and_ccxt_cleanly():
    app = Flask(__name__, root_path=str(ROOT))
    with app.app_context():
        caps = load_broker_capabilities()
        auth_map = load_broker_auth_functions()

        assert "deltaexchange" in caps  # Upstream plugin intact
        assert caps["alpaca"] == {
            "broker_name": "alpaca",
            "broker_type": "US_multi",
            "supported_exchanges": ["US_EQUITY", "US_OPTIONS", "CRYPTO"],
            "leverage_config": True,
        }
        assert caps["ibkr"] == {
            "broker_name": "ibkr",
            "broker_type": "GLOBAL_multi",
            "supported_exchanges": [
                "US_EQUITY",
                "US_OPTIONS",
                "EU_EQUITY",
                "FUTURES",
                "FOREX",
            ],
            "leverage_config": True,
        }
        assert caps["ccxt"] == {
            "broker_name": "ccxt",
            "broker_type": "crypto",
            "supported_exchanges": ["CRYPTO", "CRYPTO_SWAP", "CRYPTO_OPTIONS"],
            "leverage_config": True,
        }

        for name in ("alpaca", "ibkr", "ccxt"):
            auth_fn = auth_map.get(f"{name}_auth")
            assert callable(auth_fn), f"Lazy auth loader failed for {name}"


# =============================================================================
# 2. Alpaca Markets Adapter Tests
# =============================================================================


def test_alpaca_200_rpm_token_bucket_and_429_backoff_with_jitter():
    clock = [0.0]
    limiter = TokenBucketLimiter(
        capacity=200.0,
        refill_rate_per_sec=200.0 / 60.0,
        clock=lambda: clock[0],
        sleeper=lambda dt: clock.__setitem__(0, clock[0] + dt),
    )

    # Consume all 200 tokens instantaneously
    for _ in range(200):
        assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False

    # Non-waiting acquire with tiny max_wait raises AlpacaRateLimitError
    with pytest.raises(AlpacaRateLimitError):
        limiter.acquire(max_wait=0.05)

    # Advancing 30s refills exactly 100 tokens
    clock[0] += 30.0
    assert abs(limiter.available_tokens - 100.0) < 1e-6

    rng = random.Random(42)
    d0 = exponential_backoff_with_jitter(0, base_delay=0.5, rng=rng)
    d2 = exponential_backoff_with_jitter(2, base_delay=0.5, rng=rng)
    assert 0.25 <= d0 <= 1.0
    assert d2 > d0


def test_alpaca_strict_paper_vs_live_host_and_credential_isolation():
    paper_cfg = resolve_alpaca_environment("PK_TEST_PAPER_KEY", paper=True)
    assert paper_cfg.paper is True
    assert paper_cfg.trading_base_url == PAPER_TRADING_BASE_URL

    live_cfg = resolve_alpaca_environment("AK_TEST_LIVE_KEY", paper=False)
    assert live_cfg.paper is False
    assert live_cfg.trading_base_url == LIVE_TRADING_BASE_URL

    # Live key cannot hit Paper or paper=True
    with pytest.raises(AlpacaEnvironmentMismatchError):
        resolve_alpaca_environment("AK_TEST_LIVE_KEY", paper=True)
    with pytest.raises(AlpacaEnvironmentMismatchError):
        resolve_alpaca_environment("AK_TEST_LIVE_KEY", base_url=PAPER_TRADING_BASE_URL)

    # Paper key cannot hit Live or paper=False
    with pytest.raises(AlpacaEnvironmentMismatchError):
        resolve_alpaca_environment("PK_TEST_PAPER_KEY", paper=False)
    with pytest.raises(AlpacaEnvironmentMismatchError):
        resolve_alpaca_environment("PK_TEST_PAPER_KEY", base_url=LIVE_TRADING_BASE_URL)

    # End-to-end order retries once on 429 and maps OpenAlgo schema cleanly
    calls = []

    def _handler(req: httpx.Request) -> httpx.Response:
        calls.append((str(req.url), json.loads(req.content.decode("utf-8"))))
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "0.01"}, json={"message": "rate limit"})
        return httpx.Response(200, json={"id": "alp-ord-99", "status": "accepted"})

    shim, resp, oid = alpaca_place_order(
        {
            "symbol": "BTCUSDT",
            "exchange": "CRYPTO",
            "action": "BUY",
            "pricetype": "LIMIT",
            "quantity": "0.25",
            "price": "82000",
        },
        "PK_PAPER_123",
        api_secret="sec_456",
        client=httpx.Client(transport=httpx.MockTransport(_handler)),
        sleeper=lambda _s: None,
    )
    assert shim.status_code == 200
    assert oid == "alp-ord-99"
    assert resp["status"] == "success"
    assert len(calls) == 2
    assert calls[0][0] == "https://paper-api.alpaca.markets/v2/orders"
    assert calls[0][1]["symbol"] == "BTC/USDT"
    assert calls[0][1]["time_in_force"] == "gtc"


def test_alpaca_ws_bridge_iex_30_cap_sip_fakepaca_and_zmq_connect_only():
    port = _free_local_port()
    ctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    sub.bind(f"tcp://127.0.0.1:{port}")
    sub.setsockopt_string(zmq.SUBSCRIBE, "")

    try:
        # Non-loopback ZMQ host refused
        with pytest.raises(ValueError, match="loopback"):
            AlpacaWebSocketBridge("PK_1", "sec", zmq_host="0.0.0.0", zmq_port=port, zmq_context=ctx)

        bridge = AlpacaWebSocketBridge(
            "PK_IEX_ACCT", "secret", feed="iex", zmq_port=port, zmq_context=ctx
        )
        try:
            # Verify connect-only invariant: bind() on pub_socket is forbidden!
            assert bridge.pub_socket.connected_endpoints == [f"tcp://127.0.0.1:{port}"]
            with pytest.raises(RuntimeError, match="NEVER bind"):
                bridge.pub_socket.bind(f"tcp://127.0.0.1:{port + 1}")

            # Duplicate connection for same account + feed rejected
            with pytest.raises(AlpacaSingleConnectionError):
                AlpacaWebSocketBridge(
                    "PK_IEX_ACCT", "secret", feed="iex", zmq_port=port, zmq_context=ctx
                )

            # Basic IEX caps at 30 symbols; 31st raises AlpacaSubscriptionLimitError
            for i in range(30):
                bridge.subscribe(f"SYM{i}", "US_EQUITY")
            with pytest.raises(AlpacaSubscriptionLimitError):
                bridge.subscribe("SYM30", "US_EQUITY")

            # Allow ZMQ PUB/SUB slow-joiner handshake then verify tick relay
            time.sleep(0.05)
            bridge.handle_upstream_frame({"T": "t", "S": "SYM0", "p": 195.25, "s": 100})
            if sub.poll(timeout=1000):
                topic_b, data_b = sub.recv_multipart()
                assert topic_b.decode("utf-8") == "US_EQUITY_SYM0_LTP"
                assert json.loads(data_b.decode("utf-8"))["ltp"] == 195.25
        finally:
            bridge.close()

        # SIP allows > 30 symbols
        sip_bridge = AlpacaWebSocketBridge(
            "PK_SIP_ACCT", "secret", feed="sip", zmq_port=port, zmq_context=ctx
        )
        try:
            for i in range(45):
                sip_bridge.subscribe(f"SIP{i}", "US_EQUITY")
            assert len(sip_bridge.subscribed_symbols) == 45
        finally:
            sip_bridge.close()

        # Weekend FAKEPACA test stream
        test_bridge = AlpacaWebSocketBridge(
            "PK_TEST_ACCT", "secret", fakepaca=True, zmq_port=port, zmq_context=ctx
        )
        try:
            assert test_bridge.ws_url == "wss://stream.data.alpaca.markets/v2/test"
            assert FAKEPACA_SYMBOL in test_bridge.subscribed_symbols
        finally:
            test_bridge.close()
    finally:
        sub.close(linger=0)
        ctx.term()


# =============================================================================
# 3. Interactive Brokers (IBKR) Adapter Tests
# =============================================================================


def test_ibkr_45_msg_per_sec_governor_close_wait_recycle_and_sunday_2fa():
    clock = [10.0]
    gov = TWSPacingGovernor(max_messages_per_second=45, clock=lambda: clock[0])

    for _ in range(45):
        assert gov.try_acquire() is True
    assert gov.try_acquire() is False

    with pytest.raises(IBKRPacingLimitError):
        gov.acquire(max_wait=0.01)

    clock[0] += 1.01
    assert gov.try_acquire() is True

    # Active reqCurrentTime() readiness probe detecting >30s CLOSE_WAIT silent hang
    probe_clock = [1000.0]
    sock_state = ["ESTABLISHED"]
    recycled_reasons: list[str] = []

    probe = TWSGatewayReadinessProbe(
        req_current_time_fn=lambda: 1_795_244_400 if sock_state[0] == "ESTABLISHED" else None,
        hang_threshold_seconds=30.0,
        on_recycle_gateway=recycled_reasons.append,
        socket_state_fn=lambda: sock_state[0],
        clock=lambda: probe_clock[0],
    )
    assert probe.check().healthy is True

    sock_state[0] = "CLOSE_WAIT"
    probe_clock[0] = 1015.0  # 15s < 30s threshold -> unhealthy, not recycled yet
    r_mid = probe.check()
    assert r_mid.healthy is False and r_mid.recycled is False

    probe_clock[0] = 1035.0  # 35s > 30s threshold -> triggers recycle callback!
    r_hung = probe.check()
    assert r_hung.healthy is False and r_hung.recycled is True
    assert len(recycled_reasons) == 1
    assert "CLOSE_WAIT" in recycled_reasons[0]

    # Sunday 00:45 America/New_York 2FA scheduler (2026-11-22 is Sunday, EST = UTC-5 -> 05:45 UTC)
    notified: list[datetime] = []
    sched = Sunday2FAScheduler(notify_fn=notified.append)

    saturday_utc = datetime(2026, 11, 21, 18, 0, 0, tzinfo=UTC)
    next_2fa = sched.next_sunday_2fa_utc(saturday_utc)
    assert next_2fa == datetime(2026, 11, 22, 5, 45, 0, tzinfo=UTC)
    assert sched.check_and_notify(saturday_utc) is False

    sunday_2fa_utc = datetime(2026, 11, 22, 5, 46, 0, tzinfo=UTC)
    assert sched.check_and_notify(sunday_2fa_utc) is True
    # Duplicate check in same Sunday window does not spam user twice
    assert sched.check_and_notify(sunday_2fa_utc) is False
    assert len(notified) == 1


def test_ibkr_oauth_single_session_guard_and_tickle_keepalive():
    guard = SingleBrokerageSessionGuard()
    tickle_state = {"authenticated": True, "competing": False}

    def _ibkr_mock(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/tickle"):
            return httpx.Response(
                200,
                json={"session": "sess-ib-1", "iserver": {"authStatus": dict(tickle_state)}},
            )
        return httpx.Response(200, json={"authenticated": True, "competing": False})

    mock_http = httpx.Client(transport=httpx.MockTransport(_ibkr_mock))
    c1 = IBKROAuthWebClient(
        "oauth-bearer-1",
        username="ibuser01",
        owner_id="pod-a",
        client=mock_http,
        session_guard=guard,
    )
    try:
        assert c1.init_brokerage_session()["authenticated"] is True

        # Second competing client for same username rejected by SingleBrokerageSessionGuard
        with pytest.raises(IBKRCompetingSessionError):
            IBKROAuthWebClient(
                "oauth-bearer-2",
                username="ibuser01",
                owner_id="pod-b",
                client=mock_http,
                session_guard=guard,
            )

        lost_events = []
        scheduler = IBKRTickleScheduler(c1, interval_seconds=55.0, on_session_lost=lost_events.append)
        s_ok = scheduler.step(now_epoch=100.0)
        assert s_ok.ok is True and scheduler.tickle_count == 1

        # Simulate competing mobile login dropping brokerage auth
        tickle_state["competing"] = True
        s_lost = scheduler.step(now_epoch=155.0)
        assert s_lost.ok is False and s_lost.competing is True
        assert len(lost_events) == 1
    finally:
        c1.close()


# =============================================================================
# 4. CCXT Unified Crypto Adapter Tests
# =============================================================================


def test_ccxt_decimal_precision_contract_size_normalization_and_sandbox_check():
    spot_mkt = {
        "precision": {"amount": 4, "price": "0.05"},
        "limits": {"amount": {"min": "0.001", "max": "100"}},
    }
    # Truncates amount (0.12349 -> 0.1234) so order never exceeds wallet balance
    assert PreciseFormatter.amount_to_precision("BTC/USDT", "0.12349", spot_mkt) == "0.1234"
    # Snaps price to exact 0.05 tick (82100.074 -> 82100.05)
    assert PreciseFormatter.price_to_precision("BTC/USDT", "82100.074", spot_mkt) == "82100.05"
    # Classic float drift check: 0.1 + 0.2
    assert (
        PreciseFormatter.amount_to_precision(
            "ETH/USDT", Decimal("0.1") + Decimal("0.2"), {"precision": {"amount": 2}}
        )
        == "0.30"
    )

    with pytest.raises(CCXTPrecisionError, match="below exchange minimum"):
        PreciseFormatter.amount_to_precision("BTC/USDT", "0.0005", spot_mkt)

    # Spot vs Linear Swap vs Inverse Swap contractSize normalization
    spot_norm = normalize_contract_quantity("BTC/USDT", "0.25", spot_mkt)
    assert spot_norm.market_kind == "spot"
    assert spot_norm.order_amount == Decimal("0.25")

    linear_mkt = {"swap": True, "linear": True, "contractSize": "0.001", "precision": {"amount": 0}}
    lin_norm = normalize_contract_quantity("BTC/USDT:USDT", "0.05", linear_mkt)
    assert lin_norm.market_kind == "linear_swap"
    assert lin_norm.order_amount == Decimal("50")
    assert contracts_to_base_amount(lin_norm.order_amount, linear_mkt) == Decimal("0.050")

    inverse_mkt = {"swap": True, "inverse": True, "contractSize": "100", "precision": {"amount": 0}}
    inv_norm = normalize_contract_quantity(
        "BTC/USD:BTC", "0.25", inverse_mkt, reference_price="80000"
    )
    assert inv_norm.market_kind == "inverse_swap"
    assert inv_norm.order_amount == Decimal("200")  # (0.25 * 80,000) / 100 = 200 USD contracts

    # enableRateLimit=True enforced
    cfg = build_ccxt_exchange_config(api_key="k", api_secret="s")
    assert cfg["enableRateLimit"] is True
    with pytest.raises(CCXTConfigError):
        build_ccxt_exchange_config(extra_options={"enableRateLimit": False})

    # set_sandbox_mode(True) catches NotSupported cleanly
    class NotSupported(Exception):
        pass

    class _NoTestnetExchange:
        id = "kraken"
        has = {"sandbox": True}

        def set_sandbox_mode(self, _enabled: bool) -> None:
            raise NotSupported("kraken does not have a sandbox URL")

    sb_res = configure_sandbox_mode(_NoTestnetExchange(), enabled=True)
    assert sb_res.supported is False and sb_res.enabled is False


def test_ccxt_duplicate_apikey_sha256_nonce_lock_and_zmq_connect_only(tmp_path: Path):
    reg = ApiKeyNonceLockRegistry(lock_dir=tmp_path / "locks")
    fp = reg.register("binance", "raw-secret-api-key-999", holder_id="worker-1")
    assert len(fp) == 64
    assert "raw-secret-api-key-999" not in fp

    # Second worker in same pod/process rejected to prevent InvalidNonce collisions
    with pytest.raises(DuplicateApiKeyNonceError):
        reg.register("binance", "raw-secret-api-key-999", holder_id="worker-2")

    # Second registry pointing at same lock_dir also blocked via OS fcntl.flock!
    reg2 = ApiKeyNonceLockRegistry(lock_dir=tmp_path / "locks")
    with pytest.raises(DuplicateApiKeyNonceError):
        reg2.register("binance", "raw-secret-api-key-999", holder_id="process-2")

    # Nonces are strictly monotonic even in tight loops
    nonces = [reg.next_nonce("binance", "raw-secret-api-key-999") for _ in range(50)]
    assert nonces == sorted(set(nonces))

    reg.release("binance", "raw-secret-api-key-999", holder_id="worker-1")
    assert reg2.register("binance", "raw-secret-api-key-999", holder_id="process-2") == fp
    reg2.release("binance", "raw-secret-api-key-999", holder_id="process-2")

    # CCXTWebSocketBridge ZMQ connect-only check
    port = _free_local_port()
    bridge = CCXTWebSocketBridge("bybit", zmq_port=port)
    try:
        assert bridge.pub_socket.connected_endpoints == [f"tcp://127.0.0.1:{port}"]
        with pytest.raises(RuntimeError, match="NEVER bind"):
            bridge.pub_socket.bind(f"tcp://127.0.0.1:{port + 1}")
        assert bridge.publish_ticker({"symbol": "BTC/USDT:USDT", "last": 84500.0}) is True
    finally:
        bridge.close()
