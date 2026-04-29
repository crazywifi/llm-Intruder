"""Burp Suite XML exporter — Phase 12."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from llm_intruder.reports.models import EngagementReport, FindingSummary

# Burp severity → confidence mapping (Burp uses Certain/Firm/Tentative)
_BURP_SEVERITY = {
    "critical": "High",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "none":     "Information",
}

_BURP_CONFIDENCE = {
    "critical": "Certain",
    "high":     "Firm",
    "medium":   "Firm",
    "low":      "Tentative",
    "none":     "Tentative",
}


class BurpExporter:
    """Export an :class:`EngagementReport` as a Burp Suite-compatible XML file.

    The output conforms to the Burp Suite issues XML schema so findings can be
    imported into a Burp project for manual triage.
    """

    def export(self, report: EngagementReport) -> str:
        """Return the Burp XML as a string."""
        root = ET.Element("issues")
        root.set("burpVersion", "LLM-Intruder-export")
        root.set("exportTime", report.generated_at.isoformat())

        for finding in report.findings:
            root.append(self._finding_to_issue(finding, report.engagement_id))

        return self._to_string(root)

    def write(self, report: EngagementReport, output_path: Path) -> Path:
        """Write the Burp XML to *output_path*."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.export(report), encoding="utf-8")
        return output_path

    # ── Private ────────────────────────────────────────────────────────────────

    def _finding_to_issue(
        self, finding: FindingSummary, engagement_id: str
    ) -> ET.Element:
        issue = ET.Element("issue")

        def _sub(tag: str, text: str) -> None:
            el = ET.SubElement(issue, tag)
            el.text = text

        _sub("serialNumber", str(finding.finding_id))
        _sub("type", finding.category)
        _sub("name", f"{finding.owasp_category}: {finding.category}")
        _sub("host", engagement_id)
        _sub("path", finding.trial_id)
        _sub("location", f"Trial {finding.trial_id}")
        _sub("severity", _BURP_SEVERITY.get(finding.severity, "Medium"))
        _sub("confidence", _BURP_CONFIDENCE.get(finding.severity, "Firm"))
        _sub("issueBackground", finding.description)
        _sub("issueDetail", finding.description)

        if finding.evidence_path:
            _sub("remediationBackground", f"Evidence: {finding.evidence_path}")

        return issue

    @staticmethod
    def _to_string(root: ET.Element) -> str:
        ET.indent(root, space="  ")
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            + ET.tostring(root, encoding="unicode")
        )
