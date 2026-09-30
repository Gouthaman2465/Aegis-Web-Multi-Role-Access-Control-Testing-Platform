"""In-memory sliding window rate limiting."""

from collections import deque
import json
import threading
import time
from fastapi import Request, HTTPException, Depends


class SlidingWindowLimiter:
    """Thread-safe sliding window rate limiter."""

    def __init__(self, max_events: int, window_seconds: int):
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        """Record an event for key and return True if under limit, False if exceeded."""
        current_time = now if now is not None else time.time()
        cutoff = current_time - self.window_seconds

        with self._lock:
            if key not in self._events:
                self._events[key] = deque()

            event_queue = self._events[key]

            # Evict events outside the sliding window
            while event_queue and event_queue[0] <= cutoff:
                event_queue.popleft()

            if len(event_queue) < self.max_events:
                event_queue.append(current_time)
                return True
            return False

    def get_retry_after(self, key: str, now: float | None = None) -> int:
        """Calculate the remaining seconds before the oldest event expires."""
        current_time = now if now is not None else time.time()
        with self._lock:
            queue = self._events.get(key)
            if not queue:
                return 1
            oldest = queue[0]
            remaining = int((oldest + self.window_seconds) - current_time)
            return max(1, remaining)


# 5 logins per minute per (IP + email)
login_limiter = SlidingWindowLimiter(max_events=5, window_seconds=60)

# 10 scan creations per hour per user
scan_limiter = SlidingWindowLimiter(max_events=10, window_seconds=3600)


async def login_rate_limit(request: Request) -> None:
    """FastAPI dependency to rate limit login attempts by (client IP + lowercased email)."""
    client_ip = request.client.host if request.client else "unknown"
    email = ""

    try:
        body_bytes = await request.body()
        if body_bytes:
            data = json.loads(body_bytes)
            if isinstance(data, dict):
                email = str(data.get("email", "")).strip().lower()
    except Exception:
        pass

    key = f"{client_ip}:{email}"
    if not login_limiter.allow(key):
        retry_after = login_limiter.get_retry_after(key)
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
