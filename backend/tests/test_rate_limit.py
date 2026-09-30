"""Unit tests for sliding window rate limiter."""

from app.core.rate_limit import SlidingWindowLimiter


def test_rate_limiter_injected_now_and_window_expiry():
    # 3 events per 10-second window
    limiter = SlidingWindowLimiter(max_events=3, window_seconds=10)
    key = "user_1"
    base_t = 1000.0

    # 3 allowed at base_t
    assert limiter.allow(key, now=base_t) is True
    assert limiter.allow(key, now=base_t + 1) is True
    assert limiter.allow(key, now=base_t + 2) is True

    # 4th request within 10s window rejected
    assert limiter.allow(key, now=base_t + 5) is False

    # After 10s from first event (base_t + 10.1s), first event expired -> allowed
    assert limiter.allow(key, now=base_t + 10.1) is True

    # After full window expires (> 20s), queue resets
    assert limiter.allow(key, now=base_t + 50.0) is True


def test_rate_limiter_keys_independent():
    limiter = SlidingWindowLimiter(max_events=2, window_seconds=60)
    now = 1000.0

    # Exhaust key_a
    assert limiter.allow("key_a", now=now) is True
    assert limiter.allow("key_a", now=now) is True
    assert limiter.allow("key_a", now=now) is False

    # key_b is completely unaffected
    assert limiter.allow("key_b", now=now) is True
    assert limiter.allow("key_b", now=now) is True
    assert limiter.allow("key_b", now=now) is False
