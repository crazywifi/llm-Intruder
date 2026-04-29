"""llm_intruder.resilience — Phase 10: Resilience + Async.

Provides:
  - Exponential backoff with jitter and Retry-After header support
  - AsyncApiClient — async httpx equivalent of the sync ApiClient
  - DryRunAsyncClient — simulated client for testing and dry runs
  - EvidenceCapture — response/error artefact writer
  - SessionPool — N-worker async pool for concurrent payload delivery
"""
from __future__ import annotations

from llm_intruder.resilience.backoff import (
    RetryAfterBackoff,
    compute_backoff,
    parse_retry_after,
)
from llm_intruder.resilience.models import (
    EvidenceRecord,
    PoolSummary,
    RetryConfig,
    SessionPoolConfig,
    SessionSlot,
    WorkerResult,
)
from llm_intruder.resilience.session_pool import SessionPool
from llm_intruder.resilience.evidence import EvidenceCapture
from llm_intruder.resilience.async_client import AsyncApiClient, DryRunAsyncClient

__all__ = [
    "compute_backoff",
    "parse_retry_after",
    "RetryAfterBackoff",
    "EvidenceRecord",
    "PoolSummary",
    "RetryConfig",
    "SessionPoolConfig",
    "SessionSlot",
    "WorkerResult",
    "SessionPool",
    "EvidenceCapture",
    "AsyncApiClient",
    "DryRunAsyncClient",
]
