"""Pydantic v2 models for Phase 12 report generation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

# ── Shared types ───────────────────────────────────────────────────────────────

Verdict = Literal["pass", "fail", "error", "pending"]
Severity = Literal["none", "low", "medium", "high", "critical"]


# ── Per-trial / per-finding summaries ─────────────────────────────────────────

class TrialSummary(BaseModel):
    trial_id: str
    strategy: str
    verdict: str
    confidence: float
    payload_hash: str
    response_hash: str
    request_payload: str | None = None   # full HTTP request body sent to the target
    target_url: str | None = None        # URL the request was sent to
    response_text: str | None = None     # response received from the target
    created_at: datetime


class FindingSummary(BaseModel):
    finding_id: int
    trial_id: str
    category: str
    severity: str
    owasp_category: str
    description: str
    evidence_path: str | None = None


# ── Engagement report ──────────────────────────────────────────────────────────

class VerdictBreakdown(BaseModel):
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    pending_count: int = 0
    total: int = 0

    @property
    def block_rate(self) -> float:
        """Fraction of trials where the guardrail held (pass verdict)."""
        if self.total == 0:
            return 0.0
        return round(self.pass_count / self.total, 4)

    @property
    def attack_success_rate(self) -> float:
        """Fraction of trials where the attack succeeded (fail verdict)."""
        if self.total == 0:
            return 0.0
        return round(self.fail_count / self.total, 4)


class EngagementReport(BaseModel):
    """Full report for one engagement — generated from the SQLite DB."""

    engagement_id: str
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    trial_count: int = 0
    finding_count: int = 0
    verdict_breakdown: VerdictBreakdown = Field(default_factory=VerdictBreakdown)
    strategies_used: list[str] = Field(default_factory=list)
    strategy_verdict_counts: dict[str, dict[str, int]] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    owasp_category_counts: dict[str, int] = Field(default_factory=dict)
    trials: list[TrialSummary] = Field(default_factory=list)
    findings: list[FindingSummary] = Field(default_factory=list)
    attack_narrative_md: str = ""
    """Auto-generated Markdown attack narrative (populated by ReportGenerator.build())."""

    # ── Model fingerprint (populated when available) ──────────────────────────
    model_fingerprint_provider: str | None = None
    model_fingerprint_family: str | None = None
    model_fingerprint_confidence: float | None = None
    model_fingerprint_display: str | None = None
    model_fingerprint_custom: bool = False

    @property
    def has_findings(self) -> bool:
        return self.finding_count > 0

    @property
    def high_critical_findings(self) -> list[FindingSummary]:
        return [f for f in self.findings if f.severity in ("high", "critical")]


# ── Benchmark metrics ──────────────────────────────────────────────────────────

class StrategyMetrics(BaseModel):
    strategy: str
    total: int = 0
    pass_count: int = 0
    fail_count: int = 0

    @property
    def block_rate(self) -> float:
        return round(self.pass_count / self.total, 4) if self.total else 0.0

    @property
    def attack_success_rate(self) -> float:
        return round(self.fail_count / self.total, 4) if self.total else 0.0


class BenchmarkMetrics(BaseModel):
    """Guardrail effectiveness metrics computed from trial data."""

    engagement_id: str
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    total_trials: int = 0
    block_rate: float = 0.0           # % of attacks blocked (pass verdict)
    attack_success_rate: float = 0.0  # % of attacks that succeeded (fail verdict)
    avg_confidence: float = 0.0
    strategies_tested: int = 0
    by_strategy: list[StrategyMetrics] = Field(default_factory=list)
    verdict_counts: dict[str, int] = Field(default_factory=dict)

    @property
    def guardrail_score(self) -> float:
        """Composite 0-100 score: higher = better guardrails."""
        return round(self.block_rate * 100, 1)


# ── Comparison report ──────────────────────────────────────────────────────────

class ComparisonReport(BaseModel):
    """Before/after comparison of two :class:`BenchmarkMetrics` runs."""

    baseline_engagement: str
    current_engagement: str
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    baseline_block_rate: float = 0.0
    current_block_rate: float = 0.0
    block_rate_delta: float = 0.0          # positive = improvement
    baseline_attack_success_rate: float = 0.0
    current_attack_success_rate: float = 0.0
    attack_success_delta: float = 0.0     # negative = improvement
    baseline_trials: int = 0
    current_trials: int = 0
    improved: bool = False
    strategy_deltas: dict[str, float] = Field(default_factory=dict)
