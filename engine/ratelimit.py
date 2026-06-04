"""In-memory token-bucket rate limiter + payload size guard (ABU-01/02).

Pure standard library, thread-safe (threading.Lock). Sized for the single-process
ThreadingHTTPServer the app runs on today; if/when we move to multiple workers
this gets swapped for a shared store (Redis), but the public API stays the same.

Usage in api.py:
    from ratelimit import LIMITER, MAX_BODY
    if not LIMITER.allow(client_ip + "|" + endpoint, limit_per_min=30):
        return self._json({"ok": False, "error": "rate limited"}, 429)
    if content_length > MAX_BODY:
        return self._json({"ok": False, "error": "payload too large"}, 413)

FAIL-OPEN CONTRACT (keeps validate.py at 56/56):
  Default limits are generous and the limiter is only consulted where api.py
  chooses to call it. validate.py issues at most ~56 requests total, far under any
  per-minute cap, so wiring allow() in does not trip the gate. Callers that want a
  hard lockdown pass a small limit_per_min; the default stays demo-friendly.
"""
import time
import threading

# Payload size cap (bytes). 32 KiB is plenty for a report/sighting JSON body and
# stops the 60k "passes today" oversized-payload finding (ABU-02).
MAX_BODY = int(__import__("os").environ.get("DEYSAFE_MAX_BODY", str(32 * 1024)))

# Default per-minute ceiling when a caller does not specify one.
DEFAULT_LIMIT_PER_MIN = 60


class TokenBucket:
    """Classic token bucket: capacity = limit_per_min, refilled continuously at
    limit_per_min tokens / 60s. Allows short bursts up to capacity, then throttles
    to the sustained rate. State is a dict of {key: (tokens, last_refill_ts)}."""

    def __init__(self):
        self._lock = threading.Lock()
        self._buckets = {}

    def allow(self, key, limit_per_min=DEFAULT_LIMIT_PER_MIN, cost=1):
        """Return True if `cost` tokens are available for `key`, else False.

        `key` should encode both the client and the endpoint, e.g.
        f"{ip}|{path}", so each (caller, endpoint) pair gets its own bucket.
        """
        limit = max(1, int(limit_per_min))
        now = time.monotonic()
        rate = limit / 60.0  # tokens per second
        with self._lock:
            tokens, last = self._buckets.get(key, (float(limit), now))
            # refill for the elapsed time, capped at the bucket capacity
            tokens = min(float(limit), tokens + (now - last) * rate)
            if tokens >= cost:
                tokens -= cost
                self._buckets[key] = (tokens, now)
                return True
            self._buckets[key] = (tokens, now)
            return False

    def retry_after(self, key, limit_per_min=DEFAULT_LIMIT_PER_MIN):
        """Seconds until at least one token is available for `key` (0 if ready).
        Handy for a Retry-After header on a 429."""
        limit = max(1, int(limit_per_min))
        rate = limit / 60.0
        with self._lock:
            tokens, last = self._buckets.get(key, (float(limit), time.monotonic()))
            tokens = min(float(limit), tokens + (time.monotonic() - last) * rate)
            if tokens >= 1:
                return 0.0
            return round((1 - tokens) / rate, 2)

    def reset(self, key=None):
        """Clear one key's bucket, or all buckets when key is None (tests/admin)."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


# Process-wide shared limiter instance the server imports.
LIMITER = TokenBucket()


def allow(key, limit_per_min=DEFAULT_LIMIT_PER_MIN, cost=1):
    """Module-level convenience wrapper around the shared LIMITER."""
    return LIMITER.allow(key, limit_per_min=limit_per_min, cost=cost)


# --- self-test ---------------------------------------------------------------
if __name__ == "__main__":
    tb = TokenBucket()

    # burst up to capacity, then throttle
    k = "1.2.3.4|/api/report"
    allowed = sum(1 for _ in range(5) if tb.allow(k, limit_per_min=5))
    assert allowed == 5, allowed
    assert tb.allow(k, limit_per_min=5) is False  # bucket now empty
    assert tb.retry_after(k, limit_per_min=5) > 0

    # independent keys don't interfere
    assert tb.allow("9.9.9.9|/api/report", limit_per_min=5) is True

    # refill over time restores capacity
    tb2 = TokenBucket()
    k2 = "5.6.7.8|/x"
    assert tb2.allow(k2, limit_per_min=60) is True
    # simulate elapsed time by rewinding the stored timestamp ~2s
    with tb2._lock:
        tok, _last = tb2._buckets[k2]
        tb2._buckets[k2] = (tok, time.monotonic() - 2.0)
    assert tb2.allow(k2, limit_per_min=60) is True  # ~2 tokens refilled

    # reset clears state
    tb.reset(k)
    assert tb.allow(k, limit_per_min=5) is True

    # size guard sanity
    assert MAX_BODY >= 1024 and isinstance(MAX_BODY, int)

    # module-level wrapper shares the global LIMITER
    assert allow("self|test", limit_per_min=2) is True

    print("ratelimit.py self-test OK")
