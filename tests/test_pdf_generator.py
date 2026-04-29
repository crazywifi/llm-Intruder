"""Tests for llm_intruder.reports.pdf_generator (Phase 13)."""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from llm_intruder.reports.models import (
    EngagementReport,
    FindingSummary,
    VerdictBreakdown,
)
from llm_intruder.reports.pdf_generator import FPDF2_AVAILABLE, write_pdf


def _make_report(**kwargs) -> EngagementReport:
    vb = VerdictBreakdown(total=10, pass_count=7, fail_count=2, error_count=1)
    defaults = dict(
        engagement_id="test-pdf-001",
        trial_count=10,
        finding_count=0,
        verdict_breakdown=vb,
        generated_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(kwargs)
    return EngagementReport(**defaults)


@pytest.mark.skipif(not FPDF2_AVAILABLE, reason="fpdf2 not installed")
def test_write_pdf_creates_file():
    report = _make_report()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.pdf"
        result = write_pdf(report, out)
        assert result == out
        assert out.exists()
        assert out.stat().st_size > 1000  # meaningful PDF has content


@pytest.mark.skipif(not FPDF2_AVAILABLE, reason="fpdf2 not installed")
def test_write_pdf_with_findings():
    finding = FindingSummary(
        finding_id=1,
        trial_id="tid-001",
        category="prompt_injection",
        severity="high",
        owasp_category="LLM01",
        description="Model leaked system prompt fragment.",
    )
    report = _make_report(finding_count=1, findings=[finding])
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "findings.pdf"
        write_pdf(report, out)
        assert out.exists()
        assert out.stat().st_size > 1000


@pytest.mark.skipif(not FPDF2_AVAILABLE, reason="fpdf2 not installed")
def test_write_pdf_creates_parent_dir():
    report = _make_report()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "nested" / "deep" / "report.pdf"
        write_pdf(report, out)
        assert out.exists()


@pytest.mark.skipif(not FPDF2_AVAILABLE, reason="fpdf2 not installed")
def test_write_pdf_all_severities():
    findings = [
        FindingSummary(
            finding_id=i,
            trial_id=f"tid-{i:03d}",
            category="injection",
            severity=sev,
            owasp_category="LLM01",
            description=f"Test finding with {sev} severity.",
        )
        for i, sev in enumerate(["critical", "high", "medium", "low", "none"])
    ]
    report = _make_report(finding_count=5, findings=findings)
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "all_sev.pdf"
        write_pdf(report, out)
        assert out.exists()


def test_fpdf2_unavailable_raises():
    """write_pdf raises RuntimeError when fpdf2 is not installed."""
    import llm_intruder.reports.pdf_generator as mod
    orig = mod.FPDF2_AVAILABLE
    try:
        mod.FPDF2_AVAILABLE = False
        report = _make_report()
        with pytest.raises(RuntimeError, match="fpdf2"):
            write_pdf(report, Path("/tmp/test.pdf"))
    finally:
        mod.FPDF2_AVAILABLE = orig
