"""CCXT WebSocket Bridge -> OpenAlgo Loopback ZMQ Bus (`127.0.0.1:5555`).

Connects as a ``zmq.PUB`` publisher strictly to ``tcp://127.0.0.1:5555``
(never calling ``bind()`` and refusing non-loopback hosts) to relay normalized
spot (``CRYPTO``), swap (``CRYPTO_SWAP``), and option (``CRYPTO_OPTIONS``) ticks
into OpenAlgo's ``websocket_proxy``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import zmq

from broker.alpaca.streaming.alpaca_ws_bridge import (
    ALLOWED_LOOPBACK_HOSTS,
    _ConnectOnlyPubSocketProxy,
)
from utils import real_threading


class CCXTWebSocketBridge:
    """Relays CCXT Pro / WebSocket ticks onto OpenAlgo's loopback ZMQ bus."""

    def __init__(
        self,
        exchange_id: str = "binance",
        *,
        zmq_host: str = "127.0.0.1",
        zmq_port: int = 5555,
        zmq_context: zmq.Context | None = None,
    ) -> None:
        clean_host = (zmq_host or "").strip()
        if clean_host not in ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"CCXTWebSocketBridge ZMQ host must be loopback ('127.0.0.1' or 'localhost'), "
                f"got {zmq_host!r}."
            )

        self.exchange_id = (exchange_id or "binance").strip().lower()
        self.zmq_endpoint = f"tcp://{clean_host}:{int(zmq_port)}"
        self._owns_context = zmq_context is None
        self._ctx = zmq_context or zmq.Context()
        self._lock = real_threading.RLock()
        self._subscriptions: dict[str, str] = {}
        self._closed = False

        raw_sock = self._ctx.socket(zmq.PUB)
        raw_sock.setsockopt(zmq.LINGER, 0)
        raw_sock.setsockopt(zmq.SNDHWM, 2000)
        self.pub_socket = _ConnectOnlyPubSocketProxy(raw_sock)
        self.pub_socket.connect(self.zmq_endpoint)

    def subscribe(self, symbol: str, exchange: str = "CRYPTO") -> None:
        clean_sym = symbol.strip().upper()
        exch = exchange.strip().upper()
        with self._lock:
            self._subscriptions[clean_sym] = exch

    def publish_ticker(self, ticker: Mapping[str, Any]) -> bool:
        """Normalize a CCXT ticker dict and publish onto ``127.0.0.1:5555``."""
        sym = str(ticker.get("symbol") or "").strip().upper()
        if not sym:
            return False

        with self._lock:
            default_exch = "CRYPTO_SWAP" if ":" in sym else "CRYPTO"
            exch = self._subscriptions.get(sym, default_exch)

        oa_sym = sym.replace("/", "").replace(":", "_")
        topic = f"{exch}_{oa_sym}_QUOTE"
        payload = {
            "exchange_id": self.exchange_id,
            "symbol": sym,
            "exchange": exch,
            "ltp": float(ticker.get("last") or 0.0),
            "bid": float(ticker.get("bid") or 0.0),
            "ask": float(ticker.get("ask") or 0.0),
            "volume": float(ticker.get("baseVolume") or 0.0),
            "timestamp": ticker.get("timestamp"),
        }
        self.pub_socket.send_multipart(
            [topic.encode("utf-8"), json.dumps(payload).encode("utf-8")]
        )
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._subscriptions.clear()
            try:
                self.pub_socket.close(linger=0)
            finally:
                if self._owns_context:
                    self._ctx.term()
