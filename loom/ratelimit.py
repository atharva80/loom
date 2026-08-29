"""loom.ratelimit — Token-bucket rate limiter, shared across tools.

A scope can say: 'max 50 requests/sec against example.com'. Every tool that
hits that target must share that budget — not each one consume 50/sec.

Implementation: thread-safe + async-safe (we use the same primitive) token
bucket. acquire() blocks (sync) or awaits (async) until a token is available.

Design notes:
- We use real time, not perf_counter — because tools run across cores and we
  want the bucket to behave correctly under load.
- Burst: bucket starts full, so a tool can fire `rps` requests in a tight
  burst, then settles to `rps`/sec.
- No backoff; if a tool needs to be polite, it should acquire() before each
  request. If the bucket is empty, acquire() blocks — that's the politeness.
"""
import asyncio
import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float
    last_refill: float
    lock: threading.Lock


class RateLimiter:
    """Thread-safe + async-safe token-bucket rate limiter.

    One limiter = one (host, tool-class) pair. Or just one limiter for the
    whole program, depending on how you model it. The scope config decides.
    """

    def __init__(self, rps: float, burst: float | None = None):
        if rps <= 0:
            raise ValueError("rps must be > 0")
        self._rps = float(rps)
        self._bucket = _Bucket(
            capacity=burst if burst is not None else rps,
            refill_rate=self._rps,
            tokens=burst if burst is not None else rps,
            last_refill=time.monotonic(),
            lock=threading.Lock(),
        )

    @property
    def rps(self) -> float:
        return self._rps

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = now - self._bucket.last_refill
        if elapsed <= 0:
            return
        self._bucket.tokens = min(
            self._bucket.capacity,
            self._bucket.tokens + elapsed * self._bucket.refill_rate,
        )
        self._bucket.last_refill = now

    def acquire(self, timeout: float | None = None) -> bool:
        """Block until a token is available. Returns True on success, False on timeout."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._bucket.lock:
                self._refill_locked()
                if self._bucket.tokens >= 1.0:
                    self._bucket.tokens -= 1.0
                    return True
                # compute sleep until we have 1 token
                deficit = 1.0 - self._bucket.tokens
                sleep_for = deficit / self._bucket.refill_rate

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                sleep_for = min(sleep_for, remaining)
            time.sleep(sleep_for)

    async def aacquire(self, timeout: float | None = None) -> bool:
        """Async variant of acquire()."""
        deadline = None if timeout is None else asyncio.get_event_loop().time() + timeout
        while True:
            with self._bucket.lock:
                self._refill_locked()
                if self._bucket.tokens >= 1.0:
                    self._bucket.tokens -= 1.0
                    return True
                deficit = 1.0 - self._bucket.tokens
                sleep_for = deficit / self._bucket.refill_rate

            if deadline is not None:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    return False
                sleep_for = min(sleep_for, remaining)
            await asyncio.sleep(sleep_for)

    def try_acquire(self) -> bool:
        """Non-blocking attempt. Returns True if a token was available."""
        with self._bucket.lock:
            self._refill_locked()
            if self._bucket.tokens >= 1.0:
                self._bucket.tokens -= 1.0
                return True
            return False

    def available(self) -> float:
        """Current token count (for observability/tests)."""
        with self._bucket.lock:
            self._refill_locked()
            return self._bucket.tokens
