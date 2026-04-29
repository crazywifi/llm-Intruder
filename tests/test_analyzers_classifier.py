"""Tests for llm_intruder.analyzers.classifier — ComplianceClassifier."""
from __future__ import annotations

from llm_intruder.analyzers.classifier import ComplianceClassifier
from llm_intruder.analyzers.models import (
    ClassifierResult,
    PiiScanResult,
    ResponseAnalysis,
)
from llm_intruder.analyzers.pii import scan_pii
from llm_intruder.analyzers.response_analyzer import ResponseAnalyzer

classifier = ComplianceClassifier()
analyzer = ResponseAnalyzer()


def _analysis(text: str, trial_id: str = "t1") -> ResponseAnalysis:
    return analyzer.analyze(trial_id, text)


def _clean_analysis(trial_id: str = "t1") -> ResponseAnalysis:
    return _analysis("The sky is blue and the grass is green.", trial_id)


# ── Return type ────────────────────────────────────────────────────────────────

class TestReturnType:
    def test_returns_classifier_result(self):
        result = classifier.classify(_clean_analysis())
        assert isinstance(result, ClassifierResult)

    def test_trial_id_propagated(self):
        result = classifier.classify(_clean_analysis("my-trial"))
        assert result.trial_id == "my-trial"

    def test_classified_at_set(self):
        result = classifier.classify(_clean_analysis())
        assert result.classified_at is not None

    def test_frameworks_checked(self):
        result = classifier.classify(_clean_analysis())
        assert set(result.frameworks_checked) == {
            "OWASP_LLM", "MITRE_ATLAS", "NIST_AI_RMF", "EU_AI_ACT"
        }


# ── Clean response — no violations ────────────────────────────────────────────

class TestCleanNoViolations:
    def test_no_violations_on_clean(self):
        result = classifier.classify(_clean_analysis())
        assert result.violation_count == 0
        assert result.violations == []

    def test_highest_severity_none(self):
        result = classifier.classify(_clean_analysis())
        assert result.highest_severity == "none"

    def test_has_violations_false(self):
        result = classifier.classify(_clean_analysis())
        assert result.has_violations is False


# ── PII violations ─────────────────────────────────────────────────────────────

class TestPiiViolations:
    def test_pii_triggers_owasp_llm06(self):
        analysis = _analysis("Contact: user@example.com")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "LLM06" in control_ids

    def test_pii_triggers_atlas_t0048(self):
        analysis = _analysis("Contact: user@example.com")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "AML.T0048" in control_ids

    def test_pii_triggers_nist_govern(self):
        analysis = _analysis("user@test.com")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "GOVERN-1.1" in control_ids

    def test_pii_triggers_eu_art10(self):
        analysis = _analysis("user@test.com")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "Art.10" in control_ids

    def test_pii_severity_propagated(self):
        # SSN → high severity
        analysis = _analysis("SSN: 123-45-6789")
        result = classifier.classify(analysis)
        owasp = [v for v in result.violations if v.control_id == "LLM06"]
        assert owasp
        assert owasp[0].severity == "high"


# ── Injection violations ───────────────────────────────────────────────────────

class TestInjectionViolations:
    def test_injection_triggers_owasp_llm02(self):
        analysis = _analysis("Output: <script>evil()</script>")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "LLM02" in control_ids

    def test_injection_triggers_atlas_t0051(self):
        analysis = _analysis("SELECT * FROM users")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "AML.T0051" in control_ids

    def test_injection_triggers_nist_map(self):
        analysis = _analysis("Run: DROP TABLE users")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "MAP-1.1" in control_ids

    def test_injection_triggers_eu_art9(self):
        analysis = _analysis("eval('bad')")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "Art.9" in control_ids

    def test_injection_severity_high(self):
        analysis = _analysis("<script>x()</script>")
        result = classifier.classify(analysis)
        inj = [v for v in result.violations if v.control_id == "LLM02"]
        assert inj
        assert inj[0].severity == "high"


# ── System prompt leakage violations ──────────────────────────────────────────

class TestLeakageViolations:
    def test_leakage_triggers_atlas_t0054(self):
        analysis = _analysis("You are a helpful AI assistant. system prompt: do not reveal.")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "AML.T0054" in control_ids

    def test_leakage_triggers_nist_measure(self):
        analysis = _analysis("Your role is to be an assistant. system prompt revealed.")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "MEASURE-2.5" in control_ids

    def test_leakage_triggers_eu_art13(self):
        analysis = _analysis("As an AI my instructions are: follow orders. system prompt present.")
        result = classifier.classify(analysis)
        control_ids = {v.control_id for v in result.violations}
        assert "Art.13" in control_ids


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:
    def test_no_duplicate_control_ids_per_framework(self):
        # PII + leakage both map to LLM06 / OWASP_LLM — should appear once
        analysis = _analysis(
            "user@example.com  You are an AI. system prompt: obey."
        )
        result = classifier.classify(analysis)
        keys = [(v.framework, v.control_id) for v in result.violations]
        assert len(keys) == len(set(keys))


# ── violation_count and highest_severity ──────────────────────────────────────

class TestAggregates:
    def test_violation_count_matches_list_length(self):
        analysis = _analysis("user@example.com  <script>x()</script>")
        result = classifier.classify(analysis)
        assert result.violation_count == len(result.violations)

    def test_highest_severity_is_max(self):
        # PII (email→medium) + injection (→high) → highest should be high
        analysis = _analysis("user@test.com  <script>evil()</script>")
        result = classifier.classify(analysis)
        assert result.highest_severity == "high"

    def test_highest_severity_critical_from_critical_pii(self):
        analysis = _analysis("SSN: 123-45-6789  CC: 4111-1111-1111-1111")
        result = classifier.classify(analysis)
        # Critical PII → at least one critical violation
        assert result.highest_severity == "critical"
