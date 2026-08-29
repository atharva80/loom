"""Test suite for loom.ratelimit — token-bucket rate limiter."""
import asyncio
import threading
import time

import pytest

from loom.ratelimit import RateLimiter


def test_init_rejects_zero_rps():
    with pytest.raises(ValueError, match="rps must be > 0"):
        RateLimiter(0)
    with pytest.raises(ValueError, match="rps must be > 0"):
        RateLimiter(-1)


def test_burst_initial_tokens():
    """Bucket should start full — can fire `burst` requests immediately."""
    rl = RateLimiter(rps=10, burst=20)
    assert rl.available() == pytest.approx(20, abs=0.1)


def test_burst_default_equals_rps():
    """If burst not specified, default burst = rps."""
    rl = RateLimiter(rps=10)
    assert rl.available() == pytest.approx(10, abs=0.1)


def test_acquire_consumes_one_token():
    rl = RateLimiter(rps=10, burst=2)
    assert rl.acquire()
    assert rl.available() == pytest.approx(1, abs=0.1)
    assert rl.acquire()
    assert rl.available() == pytest.approx(0, abs=0.1)


def test_acquire_blocks_when_empty_then_refills():
    rl = RateLimiter(rps=20, burst=1)  # 1 token, 20/sec
    assert rl.acquire()  # burst
    # now empty, should block ~50ms for next token
    t0 = time.monotonic()
    assert rl.acquire()
    elapsed = time.monotonic() - t0
    assert 0.04 <= elapsed <= 0.3, f"elapsed={elapsed}"


def test_acquire_timeout_returns_false():
    rl = RateLimiter(rps=1, burst=1)  # 1 token/sec
    assert rl.acquire()  # consume the burst token
    assert not rl.acquire(timeout=0.1)


def test_try_acquire_nonblocking():
    rl = RateLimiter(rps=10, burst=1)
    assert rl.try_acquire()
    assert not rl.try_acquire()


def test_shared_budget_across_threads():
    """Two threads sharing one limiter must not exceed rps × time."""
    rl = RateLimiter(rps=50, burst=2)
    count = 0
    count_lock = threading.Lock()

    def worker():
        nonlocal count
        for _ in range(20):
            rl.acquire()
            with count_lock:
                count += 1

    threads = [threading.Thread(target=worker) for _ in range(4)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0

    # 80 requests total; 2 burst + 50/sec refill => expected time >= (80-2)/50 = 1.56s
    # 4 threads of 20 requests
    assert count == 80
    assert elapsed >= 1.0, f"too fast, burst leaked: elapsed={elapsed}"


@pytest.mark.asyncio
async def test_aacquire_works():
    rl = RateLimiter(rps=10, burst=1)  # 1 token, 100ms refill
    assert await rl.aacquire()  # burst
    # bucket empty; with 100ms refill and 50ms timeout, should fail
    assert not await rl.aacquire(timeout=0.05)


@pytest.mark.asyncio
async def test_aacquire_concurrent_serialized():
    """N coroutines share the bucket; with 1 token and 200ms refill, only the
    burst call + (N-1) refills worth of calls succeed within the timeout."""
    rl = RateLimiter(rps=5, burst=1)  # 1 token, 200ms refill
    # 3 coroutines, each with 300ms timeout — first immediate, second needs 200ms
    # refill, third needs 400ms (won't make it)
    results = await asyncio.gather(
        rl.aacquire(timeout=0.3),
        rl.aacquire(timeout=0.3),
        rl.aacquire(timeout=0.3),
        return_exceptions=True,
    )
    succeeded = [r for r in results if r is True]
    failed = [r for r in results if r is False]
    # burst(1) + refill(1) within 0.3s => 2 succeed, 1 fails
    assert len(succeeded) == 2
    assert len(failed) == 1


def test_refill_does_not_exceed_capacity():
    """Idle bucket caps at capacity, not infinity."""
    rl = RateLimiter(rps=10, burst=2)
    time.sleep(0.1)
    assert rl.available() <= 2.0


def test_available_reflects_state():
    rl = RateLimiter(rps=10, burst=5)
    assert rl.available() == pytest.approx(5, abs=0.1)
    rl.acquire()
    rl.acquire()
    assert rl.available() == pytest.approx(3, abs=0.1)
