"""Tests for llm_intruder.analyzers.models."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from llm_intruder.analyzers.models import (
    AnalyzerFinding,
    ClassifierResult,
    ComplianceViolation,
    InjectionRisk,
    PiiMatch,
    PiiScanResult,
    ResponseAnalysis,
    SystemPromptLeakage,
)


# ── PiiMatch ───────────────────────────────────────────────────────────────────

class TestPiiMatch:
    def test_defaults(self):
        m = PiiMatch(entity_type="EMAIL", masked_value="test***", start=0, end=10)
        assert m.confidence == 1.0

    def test_all_entity_types(self):
        for etype in ("EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IP_ADDRESS", "AWS_KEY", "JWT", "GENERIC_SECRET"):
            m = PiiMatch(entity_type=etype, masked_value="****", start=0, end=4)
            assert m.entity_type == etype

    def test_invalid_entity_type(self):
        with pytest.raises(ValidationError):
            PiiMatch(entity_type="PASSPORT", masked_value="x", start=0, end=1)


# ── PiiScanResult ──────────────────────────────────────────────────────────────

class TestPiiScanResult:
    def test_defaults(self):
        r = PiiScanResult(response_hash="abc")
        assert r.matches == []
        assert r.risk_level == "none"
        assert r.entity_counts == {}

    def test_with_matches(self):
        m = PiiMatch(entity_type="EMAIL", masked_value="test***", start=0, end=10)
        r = PiiScanResult(response_hash="abc", matches=[m], risk_level="medium", entity_counts={"EMAIL": 1})
        assert len(r.matches) == 1
        assert r.entity_counts["EMAIL"] == 1

    def test_invalid_risk_level(self):
        with pytest.raises(ValidationError):
            PiiScanResult(response_hash="abc", risk_level="extreme")


# ── InjectionRisk ──────────────────────────────────────────────────────────────

class TestInjectionRisk:
    def test_defaults(self):
        ir = InjectionRisk(category="sql", pattern="SQL SELECT", context_snippet="SELECT * FROM users")
        assert ir.risk_level == "high"

    def test_all_categories(self):
        for cat in ("javascript", "sql", "html", "command"):
            ir = InjectionRisk(category=cat, pattern="p", context_snippet="s")
            assert ir.category == cat

    def test_invalid_category(self):
        with pytest.raises(ValidationError):
            InjectionRisk(category="xss", pattern="p", context_snippet="s")


# ── SystemPromptLeakage ────────────────────────────────────────────────────────

class TestSystemPromptLeakage:
    def test_defaults(self):
        spl = SystemPromptLeakage()
        assert spl.fragments == []
        assert spl.detected is False
        assert spl.confidence == 0.0

    def test_detected_with_fragments(self):
        spl = SystemPromptLeakage(fragments=["You are a helpful AI"], detected=True, confidence=0.4)
        assert spl.detected is True
        assert len(spl.fragments) == 1


# ── AnalyzerFinding ────────────────────────────────────────────────────────────

class TestAnalyzerFinding:
    def test_defaults(self):
        f = AnalyzerFinding(category="pii_leakage", severity="medium", description="PII found")
        assert f.evidence == ""

    def test_all_severity_levels(self):
        for sev in ("none", "low", "medium", "high", "critical"):
            f = AnalyzerFinding(category="c", severity=sev, description="d")
            assert f.severity == sev

    def test_invalid_severity(self):
        with pytest.raises(ValidationError):
            AnalyzerFinding(category="c", severity="extreme", description="d")


# ── ResponseAnalysis ───────────────────────────────────────────────────────────

class TestResponseAnalysis:
    def _make_pii(self) -> PiiScanResult:
        return PiiScanResult(response_hash="abc")

    def test_defaults(self):
        ra = ResponseAnalysis(
            trial_id="t1",
            pii_scan=self._make_pii(),
        )
        assert ra.overall_risk == "none"
        assert ra.findings_count == 0
        assert ra.has_findings is False

    def test_has_findings_true(self):
        ra = ResponseAnalysis(
            trial_id="t1",
            pii_scan=self._make_pii(),
            findings_count=3,
            overall_risk="high",
        )
        assert ra.has_findings is True

    def test_analyzed_at_set(self):
        ra = ResponseAnalysis(trial_id="t1", pii_scan=self._make_pii())
        assert ra.analyzed_at is not None

    def test_response_length_default(self):
        ra = ResponseAnalysis(trial_id="t1", pii_scan=self._make_pii())
        assert ra.response_length == 0


# ── ComplianceViolation ────────────────────────────────────────────────────────

class TestComplianceViolation:
    def test_defaults(self):
        v = ComplianceViolation(
            framework="OWASP_LLM",
            control_id="LLM06",
            control_name="Sensitive Information Disclosure",
            description="PII in output",
        )
        assert v.severity == "medium"

    def test_all_frameworks(self):
        for fw in ("OWASP_LLM", "MITRE_ATLAS", "NIST_AI_RMF", "EU_AI_ACT"):
            v = ComplianceViolation(
                framework=fw, control_id="X", control_name="Y", description="Z"
            )
            assert v.framework == fw

    def test_invalid_framework(self):
        with pytest.raises(ValidationError):
            ComplianceViolation(
                framework="ISO27001", control_id="X", control_name="Y", description="Z"
            )


# ── ClassifierResult ───────────────────────────────────────────────────────────

class TestClassifierResult:
    def test_defaults(self):
        cr = ClassifierResult(trial_id="t1")
        assert cr.violations == []
        assert cr.violation_count == 0
        assert cr.highest_severity == "none"
        assert cr.has_violations is False

    def test_has_violations_true(self):
        v = ComplianceViolation(
            framework="OWASP_LLM", control_id="LLM06",
            control_name="Sensitive Information Disclosure",
            description="PII", severity="high",
        )
        cr = ClassifierResult(trial_id="t1", violations=[v], violation_count=1, highest_severity="high")
        assert cr.has_violations is True

    def test_classified_at_set(self):
        cr = ClassifierResult(trial_id="t1")
        assert cr.classified_at is not None
