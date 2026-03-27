"""In-memory token-bucket rate limiter -- zero external dependencies.

Extracted from services/edge-proxy/app/rate_limiter.py (production gateway).
Provides multi-tier rate limiting (per-user, per-session, global) for
applications that embed ForceField directly.

Thread-safe via ``threading.Lock``.  For distributed/multi-process rate
limiting, use the full Force Field gateway with Redis-backed limiters.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Tuple

from .types import RateLimitResult


class _Bucket:
    __slots__ = ("capacity", "refill_rate", "tokens", "last_refill")

    def __init__(self, capacity: int, refill_rate: float) -> None:
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self) -> int:
        if self.tokens >= 1.0:
            return 0
        return int((1.0 - self.tokens) / self.refill_rate) + 1

    def remaining(self) -> int:
        return int(self.tokens)


class RateLimiter:
    """Multi-tier in-memory token-bucket rate limiter.

    Args:
        tiers: Mapping of tier name to ``(capacity, refill_rate_per_second)``.
            Defaults to ``{"per_user": (100, 1.67), "global": (1000, 1000.0)}``.
        cleanup_seconds: Seconds of inactivity before a bucket is evicted.
    """

    DEFAULT_TIERS: Dict[str, Tuple[int, float]] = {
        "per_user": (100, 1.67),     # 100 req/min
        "per_session": (50, 0.83),   # 50 req/min
        "global": (1000, 1000.0),    # 1000 req/s
    }

    def __init__(
        self,
        tiers: Optional[Dict[str, Tuple[int, float]]] = None,
        cleanup_seconds: float = 600.0,
    ) -> None:
        self._tiers = tiers or dict(self.DEFAULT_TIERS)
        self._cleanup_seconds = cleanup_seconds
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def check(self, key: str, tier: str = "per_user") -> RateLimitResult:
        """Check whether *key* is within the rate limit for *tier*.

        Returns a ``RateLimitResult`` with ``allowed``, ``retry_after``, etc.
        """
        if tier not in self._tiers:
            return RateLimitResult(allowed=True, tier=tier)

        capacity, refill = self._tiers[tier]
        bucket_key = f"{tier}:{key}"

        with self._lock:
            self._maybe_cleanup()
            bucket = self._buckets.get(bucket_key)
            if bucket is None:
                bucket = _Bucket(capacity, refill)
                self._buckets[bucket_key] = bucket

            allowed = bucket.consume()

        return RateLimitResult(
            allowed=allowed,
            tier=tier,
            retry_after=0 if allowed else bucket.retry_after(),
            remaining=bucket.remaining(),
            limit=capacity,
        )

    def _maybe_cleanup(self) -> None:
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_seconds:
            return
        self._last_cleanup = now
        cutoff = now - self._cleanup_seconds
        stale = [k for k, b in self._buckets.items() if b.last_refill < cutoff]
        for k in stale:
            del self._buckets[k]
