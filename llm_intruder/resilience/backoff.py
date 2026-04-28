"""Exponential backoff with jitter and Retry-After header support.

Implements the "full jitter" strategy from the AWS Architecture Blog:
https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/

Full jitter: sleep = random_between(0, min(cap, base * 2^attempt))
This avoids thundering-herd problems when many workers retry simultaneously.
"""
from __future__ import annotations

import random
from datetime import datetime


def compute_backoff(
    attempt: int,
    factor: float = 2.0,
    jitter: bool = True,
    max_seconds: float = 60.0,
    seed: int | None = None,
) -> float:
    """Compute exponential backoff with optional full jitter.

    Parameters
    ----------
    attempt:
        Zero-based retry attempt number (0 = first retry).
    factor:
        Exponential base. ``factor^attempt`` gives the uncapped delay.
    jitter:
        If True, apply full jitter: return ``random(0, base_delay)``.
        If False, return the deterministic ``min(factor^attempt, max_seconds)``.
    max_seconds:
        Hard cap on the returned value.
    seed:
        Optional RNG seed for deterministic tests.

    Returns
    -------
    float
        Seconds to wait before the next attempt.
    """
    base = min(factor ** attempt, max_seconds)
    if jitter:
        rng = random.Random(seed) if seed is not None else random
        return round(rng.uniform(0.0, base), 3)
    return round(base, 3)


def parse_retry_after(headers: dict[str, str]) -> float | None:
    """Extract the ``Retry-After`` value from HTTP response headers.

    Supports:
    - Integer seconds: ``Retry-After: 30``
    - HTTP-date:       ``Retry-After: Thu, 01 Jan 2026 00:00:00 GMT``

    Returns ``None`` if the header is absent or unparseable.
    """
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    raw = raw.strip()

    # Integer / float seconds
    try:
        return float(raw)
    except ValueError:
        pass

    # HTTP-date format
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(raw)
        delta = (dt - datetime.now(dt.tzinfo)).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


class RetryAfterBackoff:
    """Smart backoff that honours the ``Retry-After`` header when present.

    If the server sends ``Retry-After: N``, waits exactly *N* seconds
    (capped at ``max_seconds``). Otherwise falls back to exponential
    backoff with full jitter.

    Parameters
    ----------
    factor:
        Exponential base for fallback backoff.
    jitter:
        Apply full jitter to fallback backoff.
    max_seconds:
        Hard cap applied to both Retry-After and computed backoff.
    """

    def __init__(
        self,
        factor: float = 2.0,
        jitter: bool = True,
        max_seconds: float = 60.0,
    ) -> None:
        self.factor = factor
        self.jitter = jitter
        self.max_seconds = max_seconds

    def wait_time(
        self,
        attempt: int,
        response_headers: dict[str, str] | None = None,
    ) -> float:
        """Return seconds to wait before the next retry.

        Parameters
        ----------
        attempt:
            Zero-based retry attempt number.
        response_headers:
            HTTP response headers from the failed request. If they contain
            ``Retry-After``, that value takes priority.

        Returns
        -------
        float
            Seconds to sleep before retrying.
        """
        if response_headers:
            ra = parse_retry_after(response_headers)
            if ra is not None:
                return min(ra, self.max_seconds)
        return compute_backoff(
            attempt=attempt,
            factor=self.factor,
            jitter=self.jitter,
            max_seconds=self.max_seconds,
        )
