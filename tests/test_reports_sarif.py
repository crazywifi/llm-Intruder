"""Tests for llm_intruder.reports.sarif — SarifExporter."""
from __future__ import annotations

import json
from pathlib import Path

from llm_intruder.reports.models import EngagementReport, FindingSummary, VerdictBreakdown
from llm_intruder.reports.sarif import SarifExporter


def _make_report(findings=None) -> EngagementReport:
    findings = findings or []
    return EngagementReport(
        engagement_id="ENG-SARIF",
        trial_count=5,
        finding_count=len(findings),
        verdict_breakdown=VerdictBreakdown(total=5, pass_count=4, fail_count=1),
        findings=findings,
    )


def _make_finding(severity="high", category="pii_leakage", fid=1) -> FindingSummary:
    return FindingSummary(
        finding_id=fid, trial_id=f"t{fid}",
        category=category, severity=severity,
        owasp_category="LLM06", description="Test finding",
    )


exporter = SarifExporter()


class TestSarifExport:
    def test_returns_dict(self):
        doc = exporter.export(_make_report())
        assert isinstance(doc, dict)

    def test_schema_field_present(self):
        doc = exporter.export(_make_report())
        assert "$schema" in doc
        assert "sarif" in doc["$schema"]

    def test_version_2_1_0(self):
        doc = exporter.export(_make_report())
        assert doc["version"] == "2.1.0"

    def test_runs_list(self):
        doc = exporter.export(_make_report())
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_tool_name(self):
        doc = exporter.export(_make_report())
        assert doc["runs"][0]["tool"]["driver"]["name"] == "LLM-Intruder"

    def test_engagement_id_in_properties(self):
        doc = exporter.export(_make_report())
        assert doc["runs"][0]["properties"]["engagementId"] == "ENG-SARIF"

    def test_no_findings_empty_results(self):
        doc = exporter.export(_make_report())
        assert doc["runs"][0]["results"] == []

    def test_finding_creates_result(self):
        f = _make_finding()
        doc = exporter.export(_make_report([f]))
        assert len(doc["runs"][0]["results"]) == 1

    def test_result_rule_id(self):
        f = _make_finding(category="pii_leakage")
        doc = exporter.export(_make_report([f]))
        result = doc["runs"][0]["results"][0]
        assert "SENTINEL-PII_LEAKAGE" in result["ruleId"]

    def test_result_level_critical_is_error(self):
        f = _make_finding(severity="critical")
        doc = exporter.export(_make_report([f]))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_result_level_medium_is_warning(self):
        f = _make_finding(severity="medium")
        doc = exporter.export(_make_report([f]))
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_result_level_low_is_note(self):
        f = _make_finding(severity="low")
        doc = exporter.export(_make_report([f]))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_rule_deduplication(self):
        # Two findings with same category → one rule
        f1 = _make_finding(category="pii_leakage", fid=1)
        f2 = _make_finding(category="pii_leakage", fid=2)
        doc = exporter.export(_make_report([f1, f2]))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_two_different_categories_two_rules(self):
        f1 = _make_finding(category="pii_leakage", fid=1)
        f2 = _make_finding(category="injection_sql", fid=2)
        doc = exporter.export(_make_report([f1, f2]))
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_evidence_path_creates_location(self):
        f = FindingSummary(
            finding_id=1, trial_id="t1", category="pii",
            severity="high", owasp_category="LLM06",
            description="desc", evidence_path="/tmp/evidence.json",
        )
        doc = exporter.export(_make_report([f]))
        result = doc["runs"][0]["results"][0]
        assert "locations" in result


class TestSarifWrite:
    def test_writes_json_file(self, tmp_path):
        out = tmp_path / "report.sarif"
        exporter.write(_make_report(), out)
        assert out.exists()

    def test_written_file_is_valid_json(self, tmp_path):
        out = tmp_path / "report.sarif"
        exporter.write(_make_report(), out)
        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "a" / "b" / "report.sarif"
        exporter.write(_make_report(), out)
        assert out.exists()
