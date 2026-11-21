"""Thread-safe TokenBucketLimiter for Alpaca's 200 req/min Trading API ceiling.

Enforces Alpaca's documented 200 requests/minute per-account Trading API limit
and implements exponential backoff with decorrelated/full jitter on HTTP 429.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Mapping

from utils import real_threading

ALPACA_TRADING_RPM = 200
ALPACA_REFILL_PER_SECOND = ALPACA_TRADING_RPM / 60.0


class AlpacaRateLimitError(RuntimeError):
    """Raised when the Alpaca 200 req/min token bucket cannot satisfy a request in time."""


class TokenBucketLimiter:
    """Thread-safe token bucket limiter (default: 200 tokens, refilling at 200/60 tokens/sec)."""

    def __init__(
        self,
        *,
        capacity: float = float(ALPACA_TRADING_RPM),
        refill_rate_per_sec: float = ALPACA_REFILL_PER_SECOND,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if capacity <= 0 or refill_rate_per_sec <= 0:
            raise ValueError("TokenBucketLimiter capacity and refill_rate_per_sec must be > 0.")
        self.capacity = float(capacity)
        self.refill_rate_per_sec = float(refill_rate_per_sec)
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or time.sleep
        self._lock = real_threading.RLock()
        self._tokens = float(capacity)
        self._last_refill = self._clock()

    def _refill_locked(self, now: float) -> None:
        elapsed = max(0.0, now - self._last_refill)
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate_per_sec)
            self._last_refill = now

    @property
    def available_tokens(self) -> float:
        """Current token count after applying elapsed time refill."""
        with self._lock:
            self._refill_locked(self._clock())
            return self._tokens

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Attempt to consume ``tokens`` without blocking. Returns True if acquired."""
        if tokens <= 0:
            return True
        with self._lock:
            self._refill_locked(self._clock())
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: float = 1.0, *, max_wait: float = 5.0) -> float:
        """Consume ``tokens``, sleeping up to ``max_wait`` seconds if needed.

        Returns:
            Total seconds waited (``0.0`` when tokens were immediately available).

        Raises:
            AlpacaRateLimitError: When required wait exceeds ``max_wait``.
        """
        if tokens <= 0:
            return 0.0
        if tokens > self.capacity:
            raise AlpacaRateLimitError(
                f"Requested {tokens} tokens exceeds bucket capacity {self.capacity}."
            )

        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                self._refill_locked(now)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                needed_sleep = deficit / self.refill_rate_per_sec

            if waited + needed_sleep > max_wait:
                raise AlpacaRateLimitError(
                    f"Alpaca 200 req/min rate limit reached; need {needed_sleep:.2f}s "
                    f"which exceeds max_wait={max_wait:.2f}s."
                )
            self._sleeper(needed_sleep)
            waited += needed_sleep


def exponential_backoff_with_jitter(
    attempt: int,
    *,
    base_delay: float = 0.5,
    max_delay: float = 30.0,
    headers: Mapping[str, str] | None = None,
    rng: random.Random | None = None,
) -> float:
    """Compute HTTP 429 retry delay with exponential backoff and positive jitter."""
    rand = rng or random
    clean_attempt = max(0, int(attempt))
    exp_cap = min(max_delay, base_delay * (2**clean_attempt))

    server_wait: float | None = None
    if headers:
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        retry_after = lower_headers.get("retry-after")
        if retry_after:
            try:
                server_wait = max(0.0, float(retry_after))
            except ValueError:
                server_wait = None

    floor = max(server_wait or 0.0, exp_cap * 0.5)
    ceiling = max(floor, min(max_delay, (server_wait or exp_cap) + base_delay))
    return rand.uniform(floor, ceiling)


DEFAULT_ALPACA_LIMITER = TokenBucketLimiter()
