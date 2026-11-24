"""IBKR TWS / IB Gateway Socket Pacing Governor, Readiness Probe & Sunday 2FA Scheduler.

Covers the post-IBC headless ``ibg-controller`` / ``ib_async`` loopback socket
deployment mode (``127.0.0.1:4002`` paper / ``127.0.0.1:4001`` live):

1. **45 msg/sec Pacing Governor** (:class:`TWSPacingGovernor`):
   - IBKR disconnects or penalizes TWS API sockets exceeding ``50 msg/sec``.
   - Caps outbound socket messages strictly at ``45 msg/sec`` over a sliding
     1.0-second window.
2. **Active ``reqCurrentTime()`` Readiness Probe** (:class:`TWSGatewayReadinessProbe`):
   - Plain TCP checks to ``:4002`` stay green when IB Gateway's upstream socket
     stalls in ``CLOSE_WAIT``.
   - Actively calls ``reqCurrentTime()`` and inspects socket state; if the
     gateway hangs in ``CLOSE_WAIT`` or fails to answer for ``> 30s``, invokes
     the configured gateway recycle callback.
3. **Sunday ``00:45 ET`` 2FA Notification Scheduler** (:class:`Sunday2FAScheduler`):
   - IBKR invalidates weekly brokerage sessions every Sunday ~``01:00 ET``.
   - Computes exact Sunday ``00:45:00 America/New_York`` timestamps across
     EST/EDT DST transitions and triggers a weekly 2FA push/alert notification.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from utils import real_threading
from utils.logging import get_logger

logger = get_logger(__name__)

NY_TZ = ZoneInfo("America/New_York")
DEFAULT_TWS_HOST = "127.0.0.1"
DEFAULT_TWS_PAPER_PORT = 4002
DEFAULT_TWS_LIVE_PORT = 4001
TWS_MAX_MESSAGES_PER_SECOND = 45  # Safety margin under IBKR's 50 msg/sec hard limit
DEFAULT_CLOSE_WAIT_HANG_SECONDS = 30.0


class IBKRPacingLimitError(RuntimeError):
    """Raised when outbound TWS socket messages exceed the 45 msg/sec governor."""


class TWSPacingGovernor:
    """Thread-safe sliding 1-second rate governor capping TWS traffic at 45 msg/sec."""

    def __init__(
        self,
        *,
        max_messages_per_second: int = TWS_MAX_MESSAGES_PER_SECOND,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if max_messages_per_second <= 0 or max_messages_per_second >= 50:
            raise ValueError(
                f"max_messages_per_second must be in [1, 49] to stay below IBKR's 50 msg/s cap, "
                f"got {max_messages_per_second}."
            )
        self.max_messages_per_second = int(max_messages_per_second)
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or time.sleep
        self._lock = real_threading.RLock()
        self._sent_timestamps: deque[float] = deque()

    def _prune_locked(self, now: float) -> None:
        cutoff = now - 1.0
        while self._sent_timestamps and self._sent_timestamps[0] <= cutoff:
            self._sent_timestamps.popleft()

    @property
    def messages_in_last_second(self) -> int:
        with self._lock:
            self._prune_locked(self._clock())
            return len(self._sent_timestamps)

    def try_acquire(self) -> bool:
        """Attempt to claim 1 message slot in the current 1.0s window without sleeping."""
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            if len(self._sent_timestamps) >= self.max_messages_per_second:
                return False
            self._sent_timestamps.append(now)
            return True

    def acquire(self, *, max_wait: float = 2.0) -> float:
        """Claim 1 message slot, sleeping until the oldest frame ages past 1.0s if needed."""
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                self._prune_locked(now)
                if len(self._sent_timestamps) < self.max_messages_per_second:
                    self._sent_timestamps.append(now)
                    return waited
                oldest = self._sent_timestamps[0]
                sleep_needed = max(0.001, (oldest + 1.0) - now)

            if waited + sleep_needed > max_wait:
                raise IBKRPacingLimitError(
                    f"IBKR TWS 45 msg/sec governor saturated ({self.max_messages_per_second} msg/s)."
                )
            self._sleeper(sleep_needed)
            waited += sleep_needed


@dataclass(frozen=True, slots=True)
class GatewayProbeResult:
    """Result of an active ``reqCurrentTime()`` readiness check."""

    healthy: bool
    state: str
    silence_seconds: float
    recycled: bool
    server_time: int | None = None
    reason: str = ""


class TWSGatewayReadinessProbe:
    """Active ``reqCurrentTime()`` readiness probe detecting silent ``CLOSE_WAIT`` hangs."""

    def __init__(
        self,
        req_current_time_fn: Callable[[], int | None],
        *,
        host: str = DEFAULT_TWS_HOST,
        port: int = DEFAULT_TWS_PAPER_PORT,
        hang_threshold_seconds: float = DEFAULT_CLOSE_WAIT_HANG_SECONDS,
        on_recycle_gateway: Callable[[str], None] | None = None,
        socket_state_fn: Callable[[], str] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if host not in {"127.0.0.1", "localhost"}:
            raise ValueError(
                f"TWS Gateway socket must bind/connect on loopback only, got {host!r}."
            )
        self.host = host
        self.port = int(port)
        self.hang_threshold_seconds = float(hang_threshold_seconds)
        self._req_current_time = req_current_time_fn
        self._on_recycle = on_recycle_gateway
        self._socket_state_fn = socket_state_fn
        self._clock = clock or time.monotonic
        self._lock = real_threading.RLock()
        self._last_healthy_at = self._clock()
        self.recycle_count: int = 0

    def check(self) -> GatewayProbeResult:
        """Run ``reqCurrentTime()`` and trigger recycle if hung in ``CLOSE_WAIT`` > 30s."""
        now = self._clock()
        sock_state = (self._socket_state_fn() if self._socket_state_fn else "ESTABLISHED").upper()

        server_time: int | None = None
        probe_error = ""
        if sock_state != "CLOSE_WAIT":
            try:
                server_time = self._req_current_time()
            except Exception as exc:
                probe_error = str(exc)

        with self._lock:
            if server_time is not None and sock_state != "CLOSE_WAIT":
                self._last_healthy_at = now
                return GatewayProbeResult(
                    healthy=True,
                    state=sock_state,
                    silence_seconds=0.0,
                    recycled=False,
                    server_time=int(server_time),
                    reason="reqCurrentTime() succeeded",
                )

            silence = max(0.0, now - self._last_healthy_at)
            recycled = False
            reason = (
                f"Socket stuck in CLOSE_WAIT for {silence:.1f}s"
                if sock_state == "CLOSE_WAIT"
                else f"reqCurrentTime() unanswered for {silence:.1f}s ({probe_error or 'timeout'})"
            )

            if silence > self.hang_threshold_seconds:
                recycled = True
                self.recycle_count += 1
                self._last_healthy_at = now  # Reset timer so recycle has time to boot
                recycle_cb = self._on_recycle
            else:
                recycle_cb = None

        if recycle_cb is not None:
            logger.warning(f"[IBKR] Recycling hung TWS/IB Gateway ({self.host}:{self.port}): {reason}")
            recycle_cb(reason)

        return GatewayProbeResult(
            healthy=False,
            state="CLOSE_WAIT" if sock_state == "CLOSE_WAIT" else "UNRESPONSIVE",
            silence_seconds=silence,
            recycled=recycled,
            server_time=None,
            reason=reason,
        )


class Sunday2FAScheduler:
    """Weekly Sunday ``00:45 America/New_York`` IBKR 2FA re-authentication notifier."""

    def __init__(
        self,
        notify_fn: Callable[[datetime], None] | None = None,
        *,
        window_minutes: int = 15,
    ) -> None:
        self._notify_fn = notify_fn
        self.window_minutes = max(1, int(window_minutes))
        self._lock = real_threading.RLock()
        self._notified_iso_weeks: set[tuple[int, int]] = set()

    @staticmethod
    def next_sunday_2fa_utc(reference_utc: datetime | None = None) -> datetime:
        """Compute the next Sunday ``00:45:00 America/New_York`` converted to UTC."""
        now_utc = (
            reference_utc.astimezone(UTC)
            if reference_utc is not None
            else datetime.now(UTC)
        )
        now_ny = now_utc.astimezone(NY_TZ)
        # Python weekday(): Monday=0 ... Sunday=6
        days_ahead = (6 - now_ny.weekday()) % 7
        candidate_date = now_ny.date() + timedelta(days=days_ahead)
        candidate_ny = datetime(
            candidate_date.year,
            candidate_date.month,
            candidate_date.day,
            0,
            45,
            0,
            tzinfo=NY_TZ,
        )
        if candidate_ny <= now_ny:
            next_week_date = candidate_date + timedelta(days=7)
            candidate_ny = datetime(
                next_week_date.year,
                next_week_date.month,
                next_week_date.day,
                0,
                45,
                0,
                tzinfo=NY_TZ,
            )
        return candidate_ny.astimezone(UTC)

    def check_and_notify(self, now_utc: datetime | None = None) -> bool:
        """Fire 2FA notification once per Sunday ``[00:45 ET, 00:45+window ET)`` window."""
        current_utc = (
            now_utc.astimezone(UTC) if now_utc is not None else datetime.now(UTC)
        )
        current_ny = current_utc.astimezone(NY_TZ)
        if current_ny.weekday() != 6:  # Sunday is 6
            return False

        window_start = current_ny.replace(hour=0, minute=45, second=0, microsecond=0)
        window_end = window_start + timedelta(minutes=self.window_minutes)
        if not (window_start <= current_ny < window_end):
            return False

        iso = current_ny.isocalendar()
        week_key = (iso.year, iso.week)
        with self._lock:
            if week_key in self._notified_iso_weeks:
                return False
            self._notified_iso_weeks.add(week_key)

        if self._notify_fn is not None:
            self._notify_fn(current_utc)
        return True
