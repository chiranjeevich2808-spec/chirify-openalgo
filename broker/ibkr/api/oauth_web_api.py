"""Cloud-Native IBKR Unified OAuth 2.0 Web API Client & `/tickle` Keepalive.

Implements:
1. **Unified OAuth 2.0 Web API Client** (``https://api.ibkr.com/v1/api``):
   - Bearer access-token authentication, ``/iserver/auth/ssodh/init`` brokerage
     session initialization, and ``/iserver/auth/status`` verification.
2. **Single-Brokerage-Session Guard**:
   - Interactive Brokers enforces a single active ``iserver`` brokerage session
     per username across Web API, TWS/IB Gateway, and Mobile.
   - :class:`SingleBrokerageSessionGuard` prevents concurrent competing session
     claims within the cluster/process and raises
     :class:`IBKRCompetingSessionError` when a duplicate holder or
     ``competing=True`` status is detected.
3. **`/tickle` Keepalive Scheduler**:
   - Periodically calls ``POST /tickle`` (default every 55s) so the brokerage
     session never times out during quiet market periods, invoking an optional
     re-init / alert callback if ``authenticated=False`` or ``competing=True``.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from utils import real_threading
from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)

IBKR_WEB_API_BASE_URL = "https://api.ibkr.com/v1/api"
DEFAULT_TICKLE_INTERVAL_SECONDS = 55.0


class IBKRCompetingSessionError(RuntimeError):
    """Raised when a competing IBKR brokerage session is active or already claimed."""


class IBKRAuthError(PermissionError):
    """Raised when IBKR OAuth 2.0 or brokerage session authentication fails."""


class SingleBrokerageSessionGuard:
    """Registry ensuring only one active brokerage session claims an IBKR username."""

    def __init__(self) -> None:
        self._lock = real_threading.RLock()
        self._owners: dict[str, str] = {}  # username_hash -> owner_id

    @staticmethod
    def _hash_user(username: str) -> str:
        clean = (username or "").strip().lower()
        if not clean:
            raise ValueError("IBKR username/account identifier must be non-empty.")
        return hashlib.sha256(clean.encode("utf-8")).hexdigest()[:24]

    def acquire(self, username: str, owner_id: str) -> None:
        """Claim the exclusive brokerage session for ``username``."""
        key = self._hash_user(username)
        clean_owner = (owner_id or "").strip()
        if not clean_owner:
            raise ValueError("owner_id must be non-empty.")

        with self._lock:
            existing = self._owners.get(key)
            if existing is not None and existing != clean_owner:
                raise IBKRCompetingSessionError(
                    f"IBKR single-brokerage-session guard: user already bound to "
                    f"active session owner {existing!r}."
                )
            self._owners[key] = clean_owner

    def release(self, username: str, owner_id: str) -> None:
        """Release the brokerage session claim if held by ``owner_id``."""
        key = self._hash_user(username)
        with self._lock:
            if self._owners.get(key) == owner_id:
                self._owners.pop(key, None)


GLOBAL_IBKR_SESSION_GUARD = SingleBrokerageSessionGuard()


@dataclass(frozen=True, slots=True)
class TickleStatus:
    """Snapshot returned by each ``/tickle`` keepalive probe."""

    ok: bool
    authenticated: bool
    competing: bool
    session_id: str
    timestamp_epoch: float


class IBKROAuthWebClient:
    """IBKR Unified OAuth 2.0 Web API transport client."""

    def __init__(
        self,
        access_token: str,
        *,
        username: str = "default_ibkr_user",
        owner_id: str = "openalgo_pod",
        base_url: str = IBKR_WEB_API_BASE_URL,
        client: httpx.Client | None = None,
        session_guard: SingleBrokerageSessionGuard | None = None,
    ) -> None:
        clean_token = (access_token or "").strip()
        if not clean_token:
            raise IBKRAuthError("IBKR OAuth 2.0 access_token must not be empty.")
        clean_url = (base_url or IBKR_WEB_API_BASE_URL).strip().rstrip("/")
        if not clean_url.startswith("https://"):
            raise ValueError("IBKR Web API base_url must use https://.")

        self.access_token = clean_token
        self.username = username
        self.owner_id = owner_id
        self.base_url = clean_url
        self._client = client
        self._guard = session_guard or GLOBAL_IBKR_SESSION_GUARD
        self._guard.acquire(username, owner_id)

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Chirify-OpenAlgo/1.0",
        }

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | list[Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        """Send an authenticated OAuth 2.0 request to the IBKR Web API."""
        http = self._client or get_httpx_client()
        url = f"{self.base_url}{path}"
        resp = http.request(
            method.upper(),
            url,
            headers=self._headers(),
            json=json_body,
            params=dict(params) if params is not None else None,
            timeout=20.0,
        )
        if not resp.text.strip():
            return resp.status_code, {}
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"message": resp.text}

    def init_brokerage_session(self, *, compete: bool = False) -> dict[str, Any]:
        """Initialize the ``iserver`` brokerage session via ``POST /iserver/auth/ssodh/init``."""
        status_code, data = self.request(
            "POST",
            "/iserver/auth/ssodh/init",
            json_body={"publish": True, "compete": bool(compete)},
        )
        if status_code != 200 or not isinstance(data, Mapping):
            raise IBKRAuthError(f"IBKR ssodh/init failed (HTTP {status_code}): {data}")
        if data.get("competing") is True and not compete:
            raise IBKRCompetingSessionError(
                "IBKR reported competing=True on brokerage session initialization."
            )
        if not data.get("authenticated", False):
            raise IBKRAuthError("IBKR brokerage session is not authenticated.")
        return dict(data)

    def tickle(self, *, now_epoch: float | None = None) -> TickleStatus:
        """Send ``POST /tickle`` keepalive and parse ``iserver`` auth status."""
        ts = now_epoch if now_epoch is not None else time.time()
        status_code, data = self.request("POST", "/tickle")
        if status_code != 200 or not isinstance(data, Mapping):
            return TickleStatus(
                ok=False,
                authenticated=False,
                competing=False,
                session_id="",
                timestamp_epoch=ts,
            )

        iserver = data.get("iserver")
        auth_status = (
            iserver.get("authStatus")
            if isinstance(iserver, Mapping) and isinstance(iserver.get("authStatus"), Mapping)
            else data
        )
        authenticated = bool(auth_status.get("authenticated", False))
        competing = bool(auth_status.get("competing", False))
        session_id = str(data.get("session") or "")
        return TickleStatus(
            ok=authenticated and not competing,
            authenticated=authenticated,
            competing=competing,
            session_id=session_id,
            timestamp_epoch=ts,
        )

    def close(self) -> None:
        """Release the single-brokerage-session claim."""
        self._guard.release(self.username, self.owner_id)


class IBKRTickleScheduler:
    """Periodic ``/tickle`` keepalive runner with deterministic ``step()`` for tests."""

    def __init__(
        self,
        web_client: IBKROAuthWebClient,
        *,
        interval_seconds: float = DEFAULT_TICKLE_INTERVAL_SECONDS,
        on_session_lost: Callable[[TickleStatus], None] | None = None,
    ) -> None:
        self._client = web_client
        self.interval_seconds = max(5.0, float(interval_seconds))
        self._on_session_lost = on_session_lost
        self._lock = real_threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.tickle_count: int = 0
        self.consecutive_failures: int = 0
        self.last_status: TickleStatus | None = None

    def step(self, *, now_epoch: float | None = None) -> TickleStatus:
        """Execute a single ``/tickle`` probe synchronously."""
        status = self._client.tickle(now_epoch=now_epoch)
        with self._lock:
            self.tickle_count += 1
            self.last_status = status
            if status.ok:
                self.consecutive_failures = 0
            else:
                self.consecutive_failures += 1

        if not status.ok and self._on_session_lost is not None:
            try:
                self._on_session_lost(status)
            except Exception:
                logger.exception("[IBKR] on_session_lost callback raised an exception")
        return status

    def start(self) -> None:
        """Start background daemon thread running ``step()`` every ``interval_seconds``."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="ibkr-tickle-keepalive",
                daemon=True,
            )
            self._thread.start()

    def _run_loop(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self.step()
            except Exception:
                logger.exception("[IBKR] Unexpected error in /tickle keepalive loop")

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background keepalive thread."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
