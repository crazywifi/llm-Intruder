"""Tests for llm_intruder.reports.models."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from llm_intruder.reports.models import (
    BenchmarkMetrics,
    ComparisonReport,
    EngagementReport,
    FindingSummary,
    StrategyMetrics,
    TrialSummary,
    VerdictBreakdown,
)
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc)


# ── VerdictBreakdown ───────────────────────────────────────────────────────────

class TestVerdictBreakdown:
    def test_defaults(self):
        vb = VerdictBreakdown()
        assert vb.total == 0
        assert vb.pass_count == 0

    def test_block_rate_zero_when_no_trials(self):
        vb = VerdictBreakdown()
        assert vb.block_rate == 0.0

    def test_block_rate_calculation(self):
        vb = VerdictBreakdown(total=10, pass_count=8, fail_count=2)
        assert vb.block_rate == pytest.approx(0.8)

    def test_attack_success_rate_calculation(self):
        vb = VerdictBreakdown(total=10, pass_count=8, fail_count=2)
        assert vb.attack_success_rate == pytest.approx(0.2)

    def test_attack_success_rate_zero_when_no_trials(self):
        vb = VerdictBreakdown()
        assert vb.attack_success_rate == 0.0

    def test_block_rate_full(self):
        vb = VerdictBreakdown(total=5, pass_count=5)
        assert vb.block_rate == 1.0

    def test_block_rate_zero(self):
        vb = VerdictBreakdown(total=5, fail_count=5)
        assert vb.block_rate == 0.0


# ── TrialSummary ───────────────────────────────────────────────────────────────

class TestTrialSummary:
    def test_construction(self):
        ts = TrialSummary(
            trial_id="t1", strategy="roleplay", verdict="pass",
            confidence=0.9, payload_hash="abc", response_hash="def",
            created_at=_now(),
        )
        assert ts.verdict == "pass"
        assert ts.confidence == 0.9


# ── FindingSummary ─────────────────────────────────────────────────────────────

class TestFindingSummary:
    def test_construction(self):
        f = FindingSummary(
            finding_id=1, trial_id="t1", category="pii_leakage",
            severity="high", owasp_category="LLM06",
            description="PII found",
        )
        assert f.evidence_path is None
        assert f.severity == "high"

    def test_with_evidence_path(self):
        f = FindingSummary(
            finding_id=2, trial_id="t2", category="injection",
            severity="medium", owasp_category="LLM02",
            description="SQL injection", evidence_path="/tmp/ev.json",
        )
        assert f.evidence_path == "/tmp/ev.json"


# ── EngagementReport ───────────────────────────────────────────────────────────

class TestEngagementReport:
    def _make(self, **kw) -> EngagementReport:
        return EngagementReport(engagement_id="ENG-001", **kw)

    def test_defaults(self):
        r = self._make()
        assert r.trial_count == 0
        assert r.finding_count == 0
        assert r.has_findings is False
        assert r.high_critical_findings == []

    def test_generated_at_set(self):
        r = self._make()
        assert r.generated_at is not None

    def test_has_findings_true(self):
        f = FindingSummary(
            finding_id=1, trial_id="t1", category="pii",
            severity="high", owasp_category="LLM06", description="PII",
        )
        r = self._make(finding_count=1, findings=[f])
        assert r.has_findings is True

    def test_high_critical_findings(self):
        findings = [
            FindingSummary(finding_id=1, trial_id="t1", category="a",
                           severity="high", owasp_category="LLM06", description="x"),
            FindingSummary(finding_id=2, trial_id="t2", category="b",
                           severity="low", owasp_category="LLM01", description="y"),
            FindingSummary(finding_id=3, trial_id="t3", category="c",
                           severity="critical", owasp_category="LLM06", description="z"),
        ]
        r = self._make(finding_count=3, findings=findings)
        hc = r.high_critical_findings
        assert len(hc) == 2
        assert all(f.severity in ("high", "critical") for f in hc)


# ── StrategyMetrics ────────────────────────────────────────────────────────────

class TestStrategyMetrics:
    def test_block_rate(self):
        sm = StrategyMetrics(strategy="roleplay", total=10, pass_count=7, fail_count=3)
        assert sm.block_rate == pytest.approx(0.7)

    def test_attack_success_rate(self):
        sm = StrategyMetrics(strategy="roleplay", total=10, pass_count=7, fail_count=3)
        assert sm.attack_success_rate == pytest.approx(0.3)

    def test_zero_total(self):
        sm = StrategyMetrics(strategy="x")
        assert sm.block_rate == 0.0
        assert sm.attack_success_rate == 0.0


# ── BenchmarkMetrics ───────────────────────────────────────────────────────────

class TestBenchmarkMetrics:
    def test_defaults(self):
        bm = BenchmarkMetrics(engagement_id="ENG-001")
        assert bm.total_trials == 0
        assert bm.block_rate == 0.0
        assert bm.guardrail_score == 0.0

    def test_guardrail_score(self):
        bm = BenchmarkMetrics(engagement_id="ENG-001", block_rate=0.85)
        assert bm.guardrail_score == pytest.approx(85.0)

    def test_computed_at_set(self):
        bm = BenchmarkMetrics(engagement_id="ENG-001")
        assert bm.computed_at is not None


# ── ComparisonReport ───────────────────────────────────────────────────────────

class TestComparisonReport:
    def test_improved_true_when_positive_delta(self):
        cr = ComparisonReport(
            baseline_engagement="A", current_engagement="B",
            block_rate_delta=0.1, improved=True,
        )
        assert cr.improved is True

    def test_improved_false_when_negative_delta(self):
        cr = ComparisonReport(
            baseline_engagement="A", current_engagement="B",
            block_rate_delta=-0.05, improved=False,
        )
        assert cr.improved is False

    def test_generated_at_set(self):
        cr = ComparisonReport(baseline_engagement="A", current_engagement="B")
        assert cr.generated_at is not None
