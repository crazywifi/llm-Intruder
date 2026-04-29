"""Tests for llm_intruder.resilience.models — Pydantic v2 model validation."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from llm_intruder.resilience.models import (
    EvidenceRecord,
    PoolSummary,
    RetryConfig,
    SessionPoolConfig,
    SessionSlot,
    WorkerResult,
)


# ── RetryConfig ────────────────────────────────────────────────────────────────

class TestRetryConfig:
    def test_defaults(self):
        cfg = RetryConfig()
        assert cfg.max_retries == 3
        assert cfg.backoff_factor == 2.0
        assert cfg.jitter is True
        assert cfg.max_backoff_seconds == 60.0
        assert 429 in cfg.retry_on_status
        assert 503 in cfg.retry_on_status
        assert cfg.respect_retry_after is True

    def test_custom_values(self):
        cfg = RetryConfig(
            max_retries=5,
            backoff_factor=1.5,
            jitter=False,
            max_backoff_seconds=30.0,
            retry_on_status=[429],
        )
        assert cfg.max_retries == 5
        assert cfg.backoff_factor == 1.5
        assert cfg.jitter is False
        assert cfg.retry_on_status == [429]

    def test_zero_retries_valid(self):
        cfg = RetryConfig(max_retries=0)
        assert cfg.max_retries == 0

    def test_empty_retry_on_status(self):
        cfg = RetryConfig(retry_on_status=[])
        assert cfg.retry_on_status == []


# ── SessionPoolConfig ──────────────────────────────────────────────────────────

class TestSessionPoolConfig:
    def test_defaults(self):
        cfg = SessionPoolConfig()
        assert cfg.pool_size == 4
        assert cfg.max_queue_size == 256
        assert cfg.worker_timeout_seconds == 30.0
        assert isinstance(cfg.retry, RetryConfig)

    def test_nested_retry(self):
        cfg = SessionPoolConfig(
            pool_size=8,
            retry=RetryConfig(max_retries=1, jitter=False),
        )
        assert cfg.pool_size == 8
        assert cfg.retry.max_retries == 1
        assert cfg.retry.jitter is False


# ── SessionSlot ────────────────────────────────────────────────────────────────

class TestSessionSlot:
    def test_defaults(self):
        slot = SessionSlot(slot_id=0)
        assert slot.status == "idle"
        assert slot.last_used is None
        assert slot.requests_sent == 0
        assert slot.errors == 0

    @pytest.mark.parametrize("status", ["idle", "busy", "error", "closed"])
    def test_valid_statuses(self, status):
        slot = SessionSlot(slot_id=1, status=status)
        assert slot.status == status

    def test_invalid_status_raises(self):
        with pytest.raises(ValidationError):
            SessionSlot(slot_id=0, status="sleeping")


# ── EvidenceRecord ─────────────────────────────────────────────────────────────

class TestEvidenceRecord:
    def test_defaults(self):
        rec = EvidenceRecord(trial_id="t1", event="response")
        assert rec.content == ""
        assert rec.file_path is None
        assert rec.latency_ms is None
        assert rec.slot_id is None

    @pytest.mark.parametrize("event", ["response", "error", "retry", "screenshot"])
    def test_valid_events(self, event):
        rec = EvidenceRecord(trial_id="t1", event=event)
        assert rec.event == event

    def test_invalid_event_raises(self):
        with pytest.raises(ValidationError):
            EvidenceRecord(trial_id="t1", event="warning")

    def test_full_record(self):
        rec = EvidenceRecord(
            trial_id="abc-123",
            slot_id=2,
            event="response",
            content="some response text",
            file_path="/tmp/evidence/abc_response.json",
            latency_ms=42.5,
        )
        assert rec.slot_id == 2
        assert rec.latency_ms == 42.5
        assert rec.file_path is not None


# ── WorkerResult ───────────────────────────────────────────────────────────────

class TestWorkerResult:
    def test_defaults(self):
        r = WorkerResult(slot_id=0, trial_id="t1", payload="test")
        assert r.success is False
        assert r.retries == 0
        assert r.latency_ms == 0.0
        assert r.error_message == ""
        assert r.evidence == []

    def test_successful_result(self):
        r = WorkerResult(
            slot_id=1,
            trial_id="t2",
            payload="p",
            response_text="response",
            success=True,
            latency_ms=12.3,
        )
        assert r.success is True
        assert r.response_text == "response"

    def test_error_result(self):
        r = WorkerResult(
            slot_id=0,
            trial_id="t3",
            payload="p",
            success=False,
            error_message="Connection refused",
        )
        assert r.success is False
        assert "Connection refused" in r.error_message


# ── PoolSummary ────────────────────────────────────────────────────────────────

class TestPoolSummary:
    def test_defaults(self):
        s = PoolSummary(engagement_id="eng-001")
        assert s.total_sent == 0
        assert s.succeeded == 0
        assert s.failed == 0
        assert s.success_rate == 0.0

    def test_success_rate_calculation(self):
        s = PoolSummary(engagement_id="eng", total_sent=10, succeeded=8, failed=2)
        assert s.success_rate == 0.8

    def test_success_rate_all_success(self):
        s = PoolSummary(engagement_id="eng", total_sent=5, succeeded=5)
        assert s.success_rate == 1.0

    def test_success_rate_zero_sent(self):
        s = PoolSummary(engagement_id="eng", total_sent=0)
        assert s.success_rate == 0.0

    def test_with_worker_results(self):
        results = [
            WorkerResult(slot_id=0, trial_id="t1", payload="p", success=True),
            WorkerResult(slot_id=1, trial_id="t2", payload="p", success=False),
        ]
        s = PoolSummary(
            engagement_id="eng",
            total_sent=2,
            succeeded=1,
            failed=1,
            worker_results=results,
        )
        assert len(s.worker_results) == 2
        assert s.success_rate == 0.5
