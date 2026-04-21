"""Tests for llm_intruder.reports.generator — ReportGenerator, build_benchmark, build_comparison."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from llm_intruder.db.schema import Base, Finding, Trial
from llm_intruder.reports.generator import (
    ReportGenerator,
    build_benchmark,
    build_comparison,
)
from llm_intruder.reports.models import BenchmarkMetrics, EngagementReport


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _add_trials(session, engagement_id, verdicts_strategies):
    """Insert Trial rows. verdicts_strategies: list of (verdict, strategy)."""
    for i, (verdict, strategy) in enumerate(verdicts_strategies):
        session.add(Trial(
            engagement_id=engagement_id,
            trial_id=f"trial-{i}",
            strategy=strategy,
            payload_hash="abc" * 21 + "ab",
            response_hash="def" * 21 + "ab",
            response_text="response",
            verdict=verdict,
            confidence=0.9,
            created_at=datetime.now(timezone.utc),
        ))
    session.commit()


def _add_finding(session, engagement_id, trial_id, severity="high", category="pii"):
    session.add(Finding(
        engagement_id=engagement_id,
        trial_id=trial_id,
        category=category,
        severity=severity,
        owasp_category="LLM06",
        description="Test finding",
    ))
    session.commit()


# ── ReportGenerator.build ──────────────────────────────────────────────────────

class TestReportGeneratorBuild:
    def test_returns_engagement_report(self, db_session):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-001")
        assert isinstance(report, EngagementReport)

    def test_engagement_id_propagated(self, db_session):
        gen = ReportGenerator(db_session)
        report = gen.build("MY-ENG")
        assert report.engagement_id == "MY-ENG"

    def test_zero_trials_when_empty(self, db_session):
        gen = ReportGenerator(db_session)
        report = gen.build("EMPTY")
        assert report.trial_count == 0
        assert report.finding_count == 0

    def test_trial_count_correct(self, db_session):
        _add_trials(db_session, "ENG-002", [
            ("pass", "roleplay"), ("fail", "language_switch"), ("pass", "roleplay"),
        ])
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-002")
        assert report.trial_count == 3

    def test_verdict_breakdown_counts(self, db_session):
        _add_trials(db_session, "ENG-003", [
            ("pass", "roleplay"), ("pass", "roleplay"),
            ("fail", "many_shot"), ("error", "authority"),
        ])
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-003")
        assert report.verdict_breakdown.pass_count == 2
        assert report.verdict_breakdown.fail_count == 1
        assert report.verdict_breakdown.error_count == 1
        assert report.verdict_breakdown.total == 4

    def test_strategies_used_sorted(self, db_session):
        _add_trials(db_session, "ENG-004", [
            ("pass", "z_strategy"), ("fail", "a_strategy"),
        ])
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-004")
        assert report.strategies_used == sorted(report.strategies_used)

    def test_finding_count_correct(self, db_session):
        _add_trials(db_session, "ENG-005", [("pass", "roleplay")])
        _add_finding(db_session, "ENG-005", "trial-0", severity="high")
        _add_finding(db_session, "ENG-005", "trial-0", severity="medium")
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-005")
        assert report.finding_count == 2

    def test_severity_counts(self, db_session):
        _add_trials(db_session, "ENG-006", [("fail", "roleplay")])
        _add_finding(db_session, "ENG-006", "trial-0", severity="high")
        _add_finding(db_session, "ENG-006", "trial-0", severity="low")
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-006")
        assert report.severity_counts.get("high", 0) == 1
        assert report.severity_counts.get("low", 0) == 1

    def test_strategy_verdict_counts(self, db_session):
        _add_trials(db_session, "ENG-007", [
            ("pass", "roleplay"), ("fail", "roleplay"), ("pass", "many_shot"),
        ])
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-007")
        assert report.strategy_verdict_counts["roleplay"]["pass"] == 1
        assert report.strategy_verdict_counts["roleplay"]["fail"] == 1
        assert report.strategy_verdict_counts["many_shot"]["pass"] == 1

    def test_block_rate_property(self, db_session):
        _add_trials(db_session, "ENG-008", [
            ("pass", "x"), ("pass", "x"), ("pass", "x"), ("fail", "x"),
        ])
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-008")
        assert report.verdict_breakdown.block_rate == pytest.approx(0.75)


# ── ReportGenerator writers ────────────────────────────────────────────────────

class TestWriteJson:
    def test_writes_file(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-JSON")
        out = gen.write_json(report, tmp_path / "report.json")
        assert out.exists()

    def test_valid_json(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-JSON")
        out = gen.write_json(report, tmp_path / "report.json")
        data = json.loads(out.read_text())
        assert data["engagement_id"] == "ENG-JSON"

    def test_creates_parent_dirs(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-JSON")
        out = gen.write_json(report, tmp_path / "a" / "b" / "r.json")
        assert out.exists()


class TestWriteMarkdown:
    def test_writes_file(self, db_session, tmp_path):
        _add_trials(db_session, "ENG-MD", [("pass", "roleplay"), ("fail", "many_shot")])
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-MD")
        out = gen.write_markdown(report, tmp_path / "report.md")
        assert out.exists()

    def test_contains_engagement_id(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-MD2")
        out = gen.write_markdown(report, tmp_path / "report.md")
        assert "ENG-MD2" in out.read_text()

    def test_markdown_headers_present(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-MD3")
        out = gen.write_markdown(report, tmp_path / "report.md")
        content = out.read_text()
        assert "# LLM-Intruder" in content
        assert "## Verdict Summary" in content


class TestWriteHtml:
    def test_writes_file(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-HTML")
        out = gen.write_html(report, tmp_path / "report.html")
        assert out.exists()

    def test_contains_doctype(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-HTML2")
        out = gen.write_html(report, tmp_path / "report.html")
        assert "<!DOCTYPE html>" in out.read_text()

    def test_contains_engagement_id(self, db_session, tmp_path):
        gen = ReportGenerator(db_session)
        report = gen.build("ENG-HTML3")
        out = gen.write_html(report, tmp_path / "report.html")
        assert "ENG-HTML3" in out.read_text()


# ── build_benchmark ────────────────────────────────────────────────────────────

class TestBuildBenchmark:
    def test_returns_benchmark_metrics(self, db_session):
        result = build_benchmark("ENG-BM", db_session)
        assert isinstance(result, BenchmarkMetrics)

    def test_zero_trials(self, db_session):
        result = build_benchmark("EMPTY-BM", db_session)
        assert result.total_trials == 0
        assert result.block_rate == 0.0

    def test_block_rate_calculation(self, db_session):
        _add_trials(db_session, "ENG-BM2", [
            ("pass", "r"), ("pass", "r"), ("pass", "r"), ("fail", "r"),
        ])
        result = build_benchmark("ENG-BM2", db_session)
        assert result.total_trials == 4
        assert result.block_rate == pytest.approx(0.75)
        assert result.attack_success_rate == pytest.approx(0.25)

    def test_engagement_id_propagated(self, db_session):
        result = build_benchmark("MY-BM", db_session)
        assert result.engagement_id == "MY-BM"

    def test_strategies_tested_count(self, db_session):
        _add_trials(db_session, "ENG-BM3", [
            ("pass", "roleplay"), ("fail", "many_shot"), ("pass", "authority"),
        ])
        result = build_benchmark("ENG-BM3", db_session)
        assert result.strategies_tested == 3

    def test_by_strategy_list(self, db_session):
        _add_trials(db_session, "ENG-BM4", [
            ("pass", "roleplay"), ("fail", "roleplay"), ("pass", "many_shot"),
        ])
        result = build_benchmark("ENG-BM4", db_session)
        strat_names = [s.strategy for s in result.by_strategy]
        assert "roleplay" in strat_names
        assert "many_shot" in strat_names

    def test_guardrail_score_percentage(self, db_session):
        _add_trials(db_session, "ENG-BM5", [("pass", "x")] * 9 + [("fail", "x")])
        result = build_benchmark("ENG-BM5", db_session)
        assert result.guardrail_score == pytest.approx(90.0)


# ── build_comparison ───────────────────────────────────────────────────────────

class TestBuildComparison:
    def _make_bm(self, eng_id, block_rate, total=10, strategies=None):
        by_strat = []
        if strategies:
            for s, br in strategies.items():
                t = 10
                pc = round(br * t)
                by_strat.append(
                    __import__("llm_intruder.reports.models", fromlist=["StrategyMetrics"])
                    .StrategyMetrics(strategy=s, total=t, pass_count=pc, fail_count=t-pc)
                )
        return BenchmarkMetrics(
            engagement_id=eng_id,
            total_trials=total,
            block_rate=block_rate,
            attack_success_rate=round(1.0 - block_rate, 4),
            by_strategy=by_strat,
        )

    def test_improved_true_when_better(self):
        baseline = self._make_bm("A", 0.5)
        current = self._make_bm("B", 0.8)
        comp = build_comparison(baseline, current)
        assert comp.improved is True

    def test_improved_false_when_worse(self):
        baseline = self._make_bm("A", 0.8)
        current = self._make_bm("B", 0.5)
        comp = build_comparison(baseline, current)
        assert comp.improved is False

    def test_block_rate_delta(self):
        baseline = self._make_bm("A", 0.6)
        current = self._make_bm("B", 0.9)
        comp = build_comparison(baseline, current)
        assert comp.block_rate_delta == pytest.approx(0.3)

    def test_engagement_ids_recorded(self):
        baseline = self._make_bm("BEFORE", 0.5)
        current = self._make_bm("AFTER", 0.7)
        comp = build_comparison(baseline, current)
        assert comp.baseline_engagement == "BEFORE"
        assert comp.current_engagement == "AFTER"

    def test_strategy_deltas(self):
        baseline = self._make_bm("A", 0.5, strategies={"roleplay": 0.5, "many_shot": 0.6})
        current = self._make_bm("B", 0.7, strategies={"roleplay": 0.8, "many_shot": 0.7})
        comp = build_comparison(baseline, current)
        assert "roleplay" in comp.strategy_deltas
        assert comp.strategy_deltas["roleplay"] == pytest.approx(0.3)
