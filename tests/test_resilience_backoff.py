"""Tests for llm_intruder.resilience.backoff."""
from __future__ import annotations

import pytest

from llm_intruder.resilience.backoff import (
    RetryAfterBackoff,
    compute_backoff,
    parse_retry_after,
)


# ── compute_backoff ────────────────────────────────────────────────────────────

class TestComputeBackoff:
    def test_attempt_0_no_jitter(self):
        # 2.0^0 = 1.0, capped at 60.0
        result = compute_backoff(0, factor=2.0, jitter=False)
        assert result == 1.0

    def test_attempt_1_no_jitter(self):
        # 2.0^1 = 2.0
        result = compute_backoff(1, factor=2.0, jitter=False)
        assert result == 2.0

    def test_attempt_10_capped_no_jitter(self):
        # 2.0^10 = 1024 → capped at 60.0
        result = compute_backoff(10, factor=2.0, jitter=False, max_seconds=60.0)
        assert result == 60.0

    def test_jitter_within_bounds(self):
        for attempt in range(5):
            result = compute_backoff(attempt, factor=2.0, jitter=True)
            base = min(2.0 ** attempt, 60.0)
            assert 0.0 <= result <= base + 0.001  # float tolerance

    def test_jitter_deterministic_with_seed(self):
        r1 = compute_backoff(3, factor=2.0, jitter=True, seed=42)
        r2 = compute_backoff(3, factor=2.0, jitter=True, seed=42)
        assert r1 == r2

    def test_jitter_different_seeds_differ(self):
        r1 = compute_backoff(3, factor=2.0, jitter=True, seed=1)
        r2 = compute_backoff(3, factor=2.0, jitter=True, seed=2)
        # Very unlikely to be equal
        assert r1 != r2

    def test_no_jitter_zero_attempt_factor_one(self):
        # 1.0^0 = 1.0
        result = compute_backoff(0, factor=1.0, jitter=False)
        assert result == 1.0

    def test_cap_respected_with_jitter(self):
        for _ in range(20):
            result = compute_backoff(20, factor=3.0, jitter=True, max_seconds=5.0)
            assert result <= 5.0

    def test_returns_float(self):
        assert isinstance(compute_backoff(1, jitter=False), float)

    def test_custom_factor(self):
        # 3.0^2 = 9.0
        result = compute_backoff(2, factor=3.0, jitter=False)
        assert result == 9.0


# ── parse_retry_after ──────────────────────────────────────────────────────────

class TestParseRetryAfter:
    def test_integer_seconds(self):
        result = parse_retry_after({"Retry-After": "30"})
        assert result == 30.0

    def test_float_seconds(self):
        result = parse_retry_after({"Retry-After": "1.5"})
        assert result == 1.5

    def test_missing_header_returns_none(self):
        result = parse_retry_after({})
        assert result is None

    def test_unrelated_headers_ignored(self):
        result = parse_retry_after({"Content-Type": "application/json"})
        assert result is None

    def test_lowercase_header_key(self):
        result = parse_retry_after({"retry-after": "10"})
        assert result == 10.0

    def test_unparseable_value_returns_none(self):
        result = parse_retry_after({"Retry-After": "not-a-number"})
        assert result is None

    def test_zero_seconds(self):
        result = parse_retry_after({"Retry-After": "0"})
        assert result == 0.0

    def test_large_value(self):
        result = parse_retry_after({"Retry-After": "3600"})
        assert result == 3600.0


# ── RetryAfterBackoff ──────────────────────────────────────────────────────────

class TestRetryAfterBackoff:
    def test_uses_retry_after_header(self):
        backoff = RetryAfterBackoff(factor=2.0, jitter=False)
        wait = backoff.wait_time(0, response_headers={"Retry-After": "45"})
        assert wait == 45.0

    def test_retry_after_capped_at_max(self):
        backoff = RetryAfterBackoff(max_seconds=10.0)
        wait = backoff.wait_time(0, response_headers={"Retry-After": "999"})
        assert wait == 10.0

    def test_fallback_no_header(self):
        backoff = RetryAfterBackoff(factor=2.0, jitter=False, max_seconds=60.0)
        wait = backoff.wait_time(2, response_headers=None)
        # 2.0^2 = 4.0
        assert wait == 4.0

    def test_fallback_empty_headers(self):
        backoff = RetryAfterBackoff(factor=2.0, jitter=False)
        wait = backoff.wait_time(1, response_headers={})
        # 2.0^1 = 2.0
        assert wait == 2.0

    def test_fallback_with_jitter_within_bounds(self):
        backoff = RetryAfterBackoff(factor=2.0, jitter=True, max_seconds=60.0)
        for _ in range(10):
            wait = backoff.wait_time(2)
            base = min(2.0 ** 2, 60.0)
            assert 0.0 <= wait <= base + 0.001

    def test_retry_after_priority_over_backoff(self):
        """Retry-After of 5 should win over computed 2^3=8."""
        backoff = RetryAfterBackoff(factor=2.0, jitter=False, max_seconds=60.0)
        wait = backoff.wait_time(3, response_headers={"Retry-After": "5"})
        assert wait == 5.0

    def test_no_headers_uses_attempt_zero(self):
        backoff = RetryAfterBackoff(factor=2.0, jitter=False)
        wait = backoff.wait_time(0)
        assert wait == 1.0  # 2.0^0 = 1.0

    def test_default_construction(self):
        backoff = RetryAfterBackoff()
        assert backoff.factor == 2.0
        assert backoff.jitter is True
        assert backoff.max_seconds == 60.0
