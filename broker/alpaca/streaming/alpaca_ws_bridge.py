"""Alpaca Single-WebSocket Multiplexer -> OpenAlgo Loopback ZMQ Bus (`127.0.0.1:5555`).

Architectural invariants enforced:
1. **Single Upstream WebSocket per Account/Feed**: Alpaca rejects a second
   simultaneous WebSocket connection for the same account/feed with
   ``406 connection limit exceeded``. :class:`AlpacaWebSocketBridge` registers
   active account/feed streams in-process and multiplexes all OpenAlgo symbol
   subscriptions across that single connection.
2. **Feed Tier Symbol Ceiling**:
   - Basic ``"iex"`` (``wss://stream.data.alpaca.markets/v2/iex``): max ``30``
     concurrent symbols (:class:`AlpacaSubscriptionLimitError` on the 31st).
   - Algo Trader Plus ``"sip"`` (``wss://stream.data.alpaca.markets/v2/sip``):
     unlimited symbols.
   - ``"crypto"`` (``wss://stream.data.alpaca.markets/v1beta3/crypto/us``):
     unlimited symbols.
   - Weekend test stream ``"test"`` / ``fakepaca=True``
     (``wss://stream.data.alpaca.markets/v2/test``): subscribes to synthetic
     ``"FAKEPACA"`` ticker for 24x7 integration verification.
3. **Connect-Only Loopback ZMQ Publisher**: Connects as ``zmq.PUB`` to
   ``tcp://127.0.0.1:5555`` (``websocket_proxy`` is the sole ``SUB`` binder) and
   **never** calls ``bind()`` or connects to a non-loopback host.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

import zmq

from utils import real_threading
from utils.logging import get_logger

logger = get_logger(__name__)

ALPACA_WS_URLS: Mapping[str, str] = {
    "iex": "wss://stream.data.alpaca.markets/v2/iex",
    "sip": "wss://stream.data.alpaca.markets/v2/sip",
    "crypto": "wss://stream.data.alpaca.markets/v1beta3/crypto/us",
    "test": "wss://stream.data.alpaca.markets/v2/test",
}

BASIC_IEX_MAX_SYMBOLS = 30
FAKEPACA_SYMBOL = "FAKEPACA"
ALLOWED_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost"})


class AlpacaSubscriptionLimitError(ValueError):
    """Raised when subscribing beyond the Basic IEX 30-symbol limit."""


class AlpacaSingleConnectionError(RuntimeError):
    """Raised when a duplicate upstream WebSocket is opened for the same account/feed."""


class _ConnectOnlyPubSocketProxy:
    """Wraps a ``zmq.Socket(zmq.PUB)`` so ``bind()`` is structurally forbidden."""

    def __init__(self, raw_socket: zmq.Socket) -> None:
        self._raw = raw_socket
        self.connected_endpoints: list[str] = []
        self.bind_attempts: int = 0

    def connect(self, endpoint: str) -> None:
        self._raw.connect(endpoint)
        self.connected_endpoints.append(endpoint)

    def bind(self, endpoint: str) -> None:
        self.bind_attempts += 1
        raise RuntimeError(
            f"ZMQ PUB adapter must NEVER bind ({endpoint!r}); websocket_proxy SUB is the sole binder."
        )

    def send_multipart(self, parts: list[bytes], flags: int = 0) -> None:
        self._raw.send_multipart(parts, flags=flags)

    def close(self, linger: int = 0) -> None:
        self._raw.close(linger=linger)


class AlpacaWebSocketBridge:
    """Multiplexes Alpaca streaming market data onto OpenAlgo's loopback ZMQ bus."""

    _registry_lock = real_threading.RLock()
    _active_streams: set[tuple[str, str]] = set()

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        *,
        feed: str = "iex",
        fakepaca: bool = False,
        zmq_host: str = "127.0.0.1",
        zmq_port: int = 5555,
        zmq_context: zmq.Context | None = None,
    ) -> None:
        clean_host = (zmq_host or "").strip()
        if clean_host not in ALLOWED_LOOPBACK_HOSTS:
            raise ValueError(
                f"AlpacaWebSocketBridge ZMQ host must be loopback ('127.0.0.1' or 'localhost'), "
                f"got {zmq_host!r}."
            )

        resolved_feed = "test" if fakepaca else (feed or "iex").strip().lower()
        if resolved_feed not in ALPACA_WS_URLS:
            raise ValueError(
                f"Unsupported Alpaca WebSocket feed {resolved_feed!r}; "
                f"expected one of {sorted(ALPACA_WS_URLS)}."
            )

        self.api_key = (api_key or "").strip()
        self.api_secret = (api_secret or "").strip()
        if not self.api_key or not self.api_secret:
            raise ValueError("Alpaca WebSocket requires non-empty api_key and api_secret.")

        self.feed = resolved_feed
        self.ws_url = ALPACA_WS_URLS[resolved_feed]
        self.max_symbols: int | None = BASIC_IEX_MAX_SYMBOLS if resolved_feed == "iex" else None
        self.zmq_endpoint = f"tcp://{clean_host}:{int(zmq_port)}"

        self._key_hash = hashlib.sha256(self.api_key.encode("utf-8")).hexdigest()[:16]
        self._stream_slot = (self._key_hash, self.feed)

        with self._registry_lock:
            if self._stream_slot in self._active_streams:
                raise AlpacaSingleConnectionError(
                    f"An active Alpaca {self.feed!r} WebSocket already exists for this account; "
                    "multiplex symbols onto the existing bridge instead of opening a second connection."
                )
            self._active_streams.add(self._stream_slot)

        self._owns_context = zmq_context is None
        self._ctx = zmq_context or zmq.Context()
        self._lock = real_threading.RLock()
        self._subscribed_symbols: dict[str, str] = {}  # alpaca_symbol -> exchange
        self._closed = False

        try:
            raw_sock = self._ctx.socket(zmq.PUB)
            raw_sock.setsockopt(zmq.LINGER, 0)
            raw_sock.setsockopt(zmq.SNDHWM, 2000)
            self.pub_socket = _ConnectOnlyPubSocketProxy(raw_sock)
            self.pub_socket.connect(self.zmq_endpoint)
        except Exception:
            with self._registry_lock:
                self._active_streams.discard(self._stream_slot)
            if self._owns_context:
                self._ctx.term()
            raise

        if self.feed == "test":
            self._subscribed_symbols[FAKEPACA_SYMBOL] = "US_EQUITY"

    @property
    def subscribed_symbols(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._subscribed_symbols.keys())

    def build_auth_frame(self) -> dict[str, str]:
        """Build Alpaca WebSocket authentication frame."""
        return {"action": "auth", "key": self.api_key, "secret": self.api_secret}

    def subscribe(self, symbol: str, exchange: str = "US_EQUITY") -> dict[str, Any]:
        """Multiplex ``symbol`` onto the single upstream WebSocket subscription table."""
        clean_sym = FAKEPACA_SYMBOL if self.feed == "test" and symbol.upper() == FAKEPACA_SYMBOL else symbol.strip().upper()
        if not clean_sym:
            raise ValueError("Symbol cannot be empty.")

        with self._lock:
            if clean_sym not in self._subscribed_symbols:
                if self.max_symbols is not None and len(self._subscribed_symbols) >= self.max_symbols:
                    raise AlpacaSubscriptionLimitError(
                        f"Alpaca Basic IEX feed is capped at {self.max_symbols} concurrent symbols; "
                        "upgrade to Algo Trader Plus ('sip') for unlimited symbols."
                    )
                self._subscribed_symbols[clean_sym] = exchange.strip().upper()

        return {
            "action": "subscribe",
            "trades": [clean_sym],
            "quotes": [clean_sym],
            "bars": [clean_sym],
        }

    def unsubscribe(self, symbol: str) -> dict[str, Any]:
        """Remove ``symbol`` from multiplexed subscriptions."""
        clean_sym = symbol.strip().upper()
        with self._lock:
            self._subscribed_symbols.pop(clean_sym, None)
        return {"action": "unsubscribe", "trades": [clean_sym], "quotes": [clean_sym]}

    def handle_upstream_frame(self, message: Mapping[str, Any]) -> bool:
        """Normalize an Alpaca ``t`` (trade) or ``q`` (quote) frame and publish to ZMQ."""
        msg_type = message.get("T")
        sym = str(message.get("S") or "").strip().upper()
        if not sym or msg_type not in {"t", "q", "b"}:
            return False

        with self._lock:
            exch = self._subscribed_symbols.get(sym, "US_EQUITY")

        oa_sym = sym.replace("/", "")
        if msg_type == "t":
            topic = f"{exch}_{oa_sym}_LTP"
            payload = {
                "symbol": oa_sym,
                "exchange": exch,
                "ltp": float(message.get("p") or 0.0),
                "volume": int(message.get("s") or 0),
                "timestamp": str(message.get("t") or ""),
            }
        else:
            topic = f"{exch}_{oa_sym}_QUOTE"
            payload = {
                "symbol": oa_sym,
                "exchange": exch,
                "bid": float(message.get("bp") or 0.0),
                "ask": float(message.get("ap") or 0.0),
                "ltp": float(message.get("c") or message.get("ap") or 0.0),
                "timestamp": str(message.get("t") or ""),
            }

        self.pub_socket.send_multipart(
            [topic.encode("utf-8"), json.dumps(payload).encode("utf-8")]
        )
        return True

    def close(self) -> None:
        """Release ZMQ socket and free single-WebSocket account slot."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._subscribed_symbols.clear()
            try:
                self.pub_socket.close(linger=0)
            finally:
                with self._registry_lock:
                    self._active_streams.discard(self._stream_slot)
                if self._owns_context:
                    self._ctx.term()
