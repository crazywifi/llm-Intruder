"""Pydantic v2 models for Phase 10 — Resilience + Async."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


# ── Retry configuration ────────────────────────────────────────────────────────

class RetryConfig(BaseModel):
    """Retry and backoff policy for async HTTP clients."""
    max_retries: int = 3
    backoff_factor: float = 2.0
    jitter: bool = True
    max_backoff_seconds: float = 60.0
    retry_on_status: list[int] = Field(
        default_factory=lambda: [429, 502, 503, 504]
    )
    respect_retry_after: bool = True  # honour Retry-After header on 429


# ── Session pool ──────────────────────────────────────────────────────────────

SlotStatus = Literal["idle", "busy", "error", "closed"]


class SessionSlot(BaseModel):
    """Represents one concurrent worker slot in a SessionPool."""
    slot_id: int
    status: SlotStatus = "idle"
    last_used: datetime | None = None
    requests_sent: int = 0
    errors: int = 0


class SessionPoolConfig(BaseModel):
    """Configuration for a SessionPool."""
    pool_size: int = 4
    max_queue_size: int = 256
    worker_timeout_seconds: float = 30.0
    retry: RetryConfig = Field(default_factory=RetryConfig)
    requests_per_second: float | None = None
    """Optional global rate limit across all workers (e.g. 5.0 = max 5 req/s).
    ``None`` disables rate limiting — workers run as fast as the target allows.
    Set this when the target enforces a rate limit to avoid flooding 429s."""


# ── Evidence ──────────────────────────────────────────────────────────────────

EvidenceEvent = Literal["response", "error", "retry", "screenshot"]


class EvidenceRecord(BaseModel):
    """One captured evidence artefact from a single probe execution."""
    trial_id: str
    slot_id: int | None = None
    event: EvidenceEvent
    content: str = ""
    file_path: str | None = None
    captured_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    latency_ms: float | None = None


# ── Worker result ─────────────────────────────────────────────────────────────

class WorkerResult(BaseModel):
    """Result produced by one pool worker for one payload."""
    slot_id: int
    trial_id: str
    payload: str
    response_text: str = ""
    success: bool = False
    retries: int = 0
    latency_ms: float = 0.0
    error_message: str = ""
    evidence: list[EvidenceRecord] = Field(default_factory=list)


# ── Pool summary ──────────────────────────────────────────────────────────────

class PoolSummary(BaseModel):
    """Aggregate statistics for a completed SessionPool run."""
    engagement_id: str
    total_sent: int = 0
    succeeded: int = 0
    failed: int = 0
    retried: int = 0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    pool_size: int = 0
    evidence_dir: str = ""
    worker_results: list[WorkerResult] = Field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_sent == 0:
            return 0.0
        return round(self.succeeded / self.total_sent, 3)
