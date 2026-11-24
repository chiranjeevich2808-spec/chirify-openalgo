"""Historify-Anchored Loopback ZMQ Tick Emitter for Chirify Analyzer Sandbox.

Exported class name MUST be ``Chirify_sandboxWebSocketAdapter`` to match
``websocket_proxy/broker_factory.py``'s ``f"{broker_name.capitalize()}WebSocketAdapter"``
convention (with ``ChirifySandboxWebSocketAdapter`` exported as a convenience alias).

Publishes smooth, bounded, Historify-anchored micro-ticks (zero ``math.sin()``!)
over loopback ``tcp://127.0.0.1:5555`` ZMQ, sharing live quote state with
:class:`broker.chirify_sandbox.api.data.SandboxMarketFeed` so REST quotes,
order fills, WebSocket ``:8765`` clients, and ``WebSocketExecutionEngine`` stay
100% synchronized.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from broker.chirify_sandbox.api.data import get_sandbox_market_feed
from utils import real_threading
from utils.logging import get_logger
from websocket_proxy.base_adapter import BaseBrokerWebSocketAdapter

logger = get_logger("chirify_sandbox_websocket")


def _tick_interval_seconds() -> float:
    raw = (os.getenv("CHIRIFY_SANDBOX_TICK_INTERVAL_SEC") or "0.75").strip()
    try:
        val = float(raw)
        return max(0.1, min(10.0, val))
    except ValueError:
        return 0.75


class Chirify_sandboxWebSocketAdapter(BaseBrokerWebSocketAdapter):
    """Real-time Historify-anchored ZMQ tick publisher for Chirify Analyzer Sandbox."""

    def __init__(self, use_shared_zmq: bool = False, shared_publisher=None) -> None:
        super().__init__(use_shared_zmq=use_shared_zmq, shared_publisher=shared_publisher)
        self.broker_name = "chirify_sandbox"
        self.user_id: str | None = None
        self.connected = False
        self.running = False
        self.subscriptions: dict[tuple[str, str], dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stop_event = real_threading.Event()
        self._tick_thread: Any = None
        self._feed = get_sandbox_market_feed()

    def initialize(
        self,
        broker_name: str,
        user_id: str,
        auth_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.broker_name = "chirify_sandbox"
        self.user_id = user_id
        logger.info(f"[ChirifySandboxWS] Initialized adapter for user={user_id}")
        return self._create_success_response("Chirify Sandbox adapter initialized")

    def connect(self) -> dict[str, Any]:
        with self._lock:
            if self.running and self._tick_thread is not None and self._tick_thread.is_alive():
                self.connected = True
                return self._create_success_response("Already connected to Chirify Sandbox tick bus")
            self.connected = True
            self.running = True
            self._stop_event.clear()
            self._tick_thread = real_threading.Thread(
                target=self._streaming_loop,
                daemon=True,
                name="ChirifySandboxTickBus",
            )
            self._tick_thread.start()
        logger.info("[ChirifySandboxWS] Connected and started real-time loopback ZMQ tick publisher")
        return self._create_success_response("Connected to Chirify Sandbox tick bus")

    def disconnect(self) -> dict[str, Any]:
        thread_to_join = None
        with self._lock:
            self.running = False
            self.connected = False
            self._stop_event.set()
            thread_to_join = self._tick_thread
            self._tick_thread = None
            self.subscriptions.clear()
        if thread_to_join is not None and thread_to_join.is_alive():
            try:
                thread_to_join.join(timeout=2.0)
            except Exception:
                pass
        try:
            self.cleanup_zmq()
        except Exception:
            pass
        logger.info("[ChirifySandboxWS] Disconnected")
        return self._create_success_response("Disconnected from Chirify Sandbox tick bus")

    def _build_and_publish_tick(
        self,
        symbol: str,
        exchange: str,
        modes: set[int],
        depth_level: int = 5,
        *,
        advance: bool = True,
    ) -> None:
        sym = symbol.upper()
        ex = exchange.upper()
        quote = self._feed.advance_tick(sym, ex) if advance else self._feed.get_quote(sym, ex)
        now_ms = int(time.time() * 1000)

        max_mode = max(modes) if modes else 2
        # Publish on each active mode so exact-mode subscribers AND MarketDataService both receive frames
        publish_modes = sorted(modes) if modes else [max_mode]
        depth_data: dict[str, Any] | None = None
        if any(m >= 3 for m in publish_modes):
            depth_data = self._feed.get_depth(sym, ex, levels=max(1, min(depth_level, 5)))

        for mode in publish_modes:
            mode_int = int(mode)
            if mode_int <= 1:
                mode_str = "LTP"
                payload: dict[str, Any] = {
                    "symbol": sym,
                    "exchange": ex,
                    "mode": "ltp",
                    "ltp": quote["ltp"],
                    "ltt": now_ms,
                    "timestamp": now_ms,
                }
            elif mode_int == 2:
                mode_str = "QUOTE"
                payload = {
                    "symbol": sym,
                    "exchange": ex,
                    "mode": "quote",
                    "ltp": quote["ltp"],
                    "open": quote["open"],
                    "high": quote["high"],
                    "low": quote["low"],
                    "close": quote["close"],
                    "prev_close": quote["prev_close"],
                    "bid": quote["bid"],
                    "ask": quote["ask"],
                    "bid_qty": quote["bid_qty"],
                    "ask_qty": quote["ask_qty"],
                    "volume": quote["volume"],
                    "oi": quote["oi"],
                    "average_price": round((quote["high"] + quote["low"] + quote["ltp"]) / 3.0, 2),
                    "total_buy_quantity": quote["bid_qty"] * 5,
                    "total_sell_quantity": quote["ask_qty"] * 5,
                    "ltt": now_ms,
                    "timestamp": now_ms,
                }
            else:
                mode_str = "DEPTH"
                d = depth_data or self._feed.get_depth(sym, ex, levels=5)
                payload = {
                    "symbol": sym,
                    "exchange": ex,
                    "mode": "depth",
                    "ltp": quote["ltp"],
                    "open": quote["open"],
                    "high": quote["high"],
                    "low": quote["low"],
                    "close": quote["close"],
                    "prev_close": quote["prev_close"],
                    "bid": quote["bid"],
                    "ask": quote["ask"],
                    "bid_qty": quote["bid_qty"],
                    "ask_qty": quote["ask_qty"],
                    "volume": quote["volume"],
                    "oi": quote["oi"],
                    "average_price": round((quote["high"] + quote["low"] + quote["ltp"]) / 3.0, 2),
                    "total_buy_quantity": d["totalbuyqty"],
                    "total_sell_quantity": d["totalsellqty"],
                    "bids": d["bids"],
                    "asks": d["asks"],
                    "depth": {"buy": d["bids"], "sell": d["asks"]},
                    "ltt": now_ms,
                    "timestamp": now_ms,
                }

            topic = f"{ex}_{sym}_{mode_str}"
            self.publish_market_data(topic, payload)

    def subscribe(
        self,
        symbol: str,
        exchange: str,
        mode: int = 2,
        depth_level: int = 5,
    ) -> dict[str, Any]:
        sym = str(symbol or "").strip().upper()
        ex = str(exchange or "").strip().upper()
        if not sym or not ex:
            return self._create_error_response("INVALID_SYMBOL", "Symbol and exchange are required.")
        mode_int = int(mode or 2)
        depth_int = max(1, min(int(depth_level or 5), 5))
        key = (sym, ex)
        with self._lock:
            existing = self.subscriptions.get(key)
            if existing is None:
                self.subscriptions[key] = {
                    "symbol": sym,
                    "exchange": ex,
                    "modes": {mode_int},
                    "depth_level": depth_int,
                }
            else:
                existing["modes"].add(mode_int)
                existing["depth_level"] = max(existing["depth_level"], depth_int)
            modes_copy = set(self.subscriptions[key]["modes"])

        # Publish an immediate initial snapshot tick so clients don't wait for the first interval
        try:
            self._build_and_publish_tick(sym, ex, modes_copy, depth_int, advance=False)
        except Exception as exc:
            logger.debug(f"[ChirifySandboxWS] Initial tick publish failed for {ex}:{sym}: {exc}")

        return self._create_success_response(
            f"Subscribed to {ex}:{sym}",
            broker=self.broker_name,
            exchange=ex,
            symbol=sym,
            mode=mode_int,
            actual_depth=depth_int,
            supported_depth=5,
            fallback_depth=5,
        )

    def unsubscribe(
        self,
        symbol: str,
        exchange: str,
        mode: int | None = None,
        depth_level: int | None = None,
    ) -> dict[str, Any]:
        sym = str(symbol or "").strip().upper()
        ex = str(exchange or "").strip().upper()
        key = (sym, ex)
        with self._lock:
            existing = self.subscriptions.get(key)
            if existing is not None:
                if mode is None:
                    self.subscriptions.pop(key, None)
                else:
                    existing["modes"].discard(int(mode))
                    if not existing["modes"]:
                        self.subscriptions.pop(key, None)
        return self._create_success_response(f"Unsubscribed from {ex}:{sym}")

    def unsubscribe_all(self) -> dict[str, Any]:
        with self._lock:
            self.subscriptions.clear()
        return self._create_success_response("Unsubscribed from all Chirify Sandbox symbols")

    def _streaming_loop(self) -> None:
        while self.running and not self._stop_event.is_set():
            interval = _tick_interval_seconds()
            try:
                with self._lock:
                    snapshot = [
                        (s["symbol"], s["exchange"], set(s["modes"]), int(s["depth_level"]))
                        for s in self.subscriptions.values()
                    ]
                for sym, ex, modes, depth_level in snapshot:
                    if not self.running:
                        break
                    self._build_and_publish_tick(sym, ex, modes, depth_level, advance=True)
            except Exception as exc:
                logger.exception(f"[ChirifySandboxWS] Error in streaming loop: {exc}")
            self._stop_event.wait(timeout=interval)


# Convenience CamelCase alias
ChirifySandboxWebSocketAdapter = Chirify_sandboxWebSocketAdapter
