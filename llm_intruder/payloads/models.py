"""Pydantic v2 models for the Payload Library and Campaign Runner."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Payload library entry ─────────────────────────────────────────────────────

class PayloadTemplate(BaseModel):
    """One base payload stored in payloads.yaml."""
    id: str
    strategy: str                        # which mutation strategy seeded this
    text: str                            # the raw probe text
    tags: list[str] = Field(default_factory=list)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    description: str = ""


class PayloadLibrary(BaseModel):
    """Root wrapper — matches the top-level ``payloads:`` key in YAML."""
    payloads: list[PayloadTemplate] = Field(default_factory=list)


# ── Mutator output ────────────────────────────────────────────────────────────

class MutatedPayload(BaseModel):
    """Produced by a mutator: original text plus its transformed variant."""
    trial_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    strategy: str
    original_text: str
    mutated_text: str
    mutation_metadata: dict[str, Any] = Field(default_factory=dict)


# ── Trial result (one row in the trials table) ────────────────────────────────

class TrialResult(BaseModel):
    """Stored after every trial.  Verdict is 'pending' until Phase 6 judge runs."""
    trial_id: str
    engagement_id: str
    strategy: str
    payload_hash: str
    response_hash: str
    request_payload: str = ""            # full HTTP request body sent to the target
    target_url: str = ""                 # URL the request was sent to
    response_preview: str = ""           # first 2000 chars of response, for console/report
    verdict: str = "pending"
    confidence: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Campaign summary ──────────────────────────────────────────────────────────

class CampaignSummary(BaseModel):
    engagement_id: str
    total_trials: int
    strategies_used: dict[str, int]      # strategy -> count
    dry_run: bool = False
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
