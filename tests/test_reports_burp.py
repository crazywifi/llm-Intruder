"""Tests for llm_intruder.reports.burp — BurpExporter."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from llm_intruder.reports.models import EngagementReport, FindingSummary, VerdictBreakdown
from llm_intruder.reports.burp import BurpExporter


def _make_report(findings=None) -> EngagementReport:
    findings = findings or []
    return EngagementReport(
        engagement_id="ENG-BURP",
        trial_count=4,
        finding_count=len(findings),
        verdict_breakdown=VerdictBreakdown(total=4, pass_count=3, fail_count=1),
        findings=findings,
    )


def _make_finding(severity="high", category="pii_leakage", fid=1) -> FindingSummary:
    return FindingSummary(
        finding_id=fid, trial_id=f"t{fid}",
        category=category, severity=severity,
        owasp_category="LLM06", description="Test finding",
    )


exporter = BurpExporter()


class TestBurpExport:
    def test_returns_string(self):
        xml_str = exporter.export(_make_report())
        assert isinstance(xml_str, str)

    def test_starts_with_xml_declaration(self):
        xml_str = exporter.export(_make_report())
        assert xml_str.startswith("<?xml")

    def test_root_element_is_issues(self):
        xml_str = exporter.export(_make_report())
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        assert root.tag == "issues"

    def test_no_findings_empty_issues(self):
        xml_str = exporter.export(_make_report())
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        assert len(list(root)) == 0

    def test_one_finding_one_issue(self):
        f = _make_finding()
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        issues = list(root)
        assert len(issues) == 1
        assert issues[0].tag == "issue"

    def test_two_findings_two_issues(self):
        f1 = _make_finding(fid=1)
        f2 = _make_finding(fid=2)
        xml_str = exporter.export(_make_report([f1, f2]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        assert len(list(root)) == 2

    def test_severity_critical_maps_to_high(self):
        f = _make_finding(severity="critical")
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        issue = list(root)[0]
        sev_el = issue.find("severity")
        assert sev_el is not None and sev_el.text == "High"

    def test_severity_medium_maps_to_medium(self):
        f = _make_finding(severity="medium")
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        sev_el = list(root)[0].find("severity")
        assert sev_el is not None and sev_el.text == "Medium"

    def test_severity_low_maps_to_low(self):
        f = _make_finding(severity="low")
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        sev_el = list(root)[0].find("severity")
        assert sev_el is not None and sev_el.text == "Low"

    def test_serial_number_is_finding_id(self):
        f = FindingSummary(
            finding_id=42, trial_id="t42", category="c",
            severity="high", owasp_category="LLM06", description="d",
        )
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        serial = list(root)[0].find("serialNumber")
        assert serial is not None and serial.text == "42"

    def test_host_is_engagement_id(self):
        f = _make_finding()
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        host = list(root)[0].find("host")
        assert host is not None and host.text == "ENG-BURP"

    def test_export_time_attribute_present(self):
        xml_str = exporter.export(_make_report())
        assert "exportTime" in xml_str

    def test_confidence_high_severity_certain_or_firm(self):
        f = _make_finding(severity="high")
        xml_str = exporter.export(_make_report([f]))
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        conf = list(root)[0].find("confidence")
        assert conf is not None and conf.text in ("Certain", "Firm")

    def test_valid_xml_output(self):
        f1 = _make_finding(severity="critical", fid=1)
        f2 = _make_finding(severity="low", fid=2)
        xml_str = exporter.export(_make_report([f1, f2]))
        # Should parse without error
        root = ET.fromstring(xml_str.split("\n", 1)[1])
        assert root is not None


class TestBurpWrite:
    def test_writes_xml_file(self, tmp_path):
        out = tmp_path / "burp.xml"
        exporter.write(_make_report(), out)
        assert out.exists()

    def test_written_file_is_valid_xml(self, tmp_path):
        f = _make_finding()
        out = tmp_path / "burp.xml"
        exporter.write(_make_report([f]), out)
        content = out.read_text()
        root = ET.fromstring(content.split("\n", 1)[1])
        assert root.tag == "issues"

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "x" / "y" / "burp.xml"
        exporter.write(_make_report(), out)
        assert out.exists()
