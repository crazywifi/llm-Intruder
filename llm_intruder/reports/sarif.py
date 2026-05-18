"""SARIF 2.1.0 exporter — Phase 12."""
from __future__ import annotations

import json
from pathlib import Path

from llm_intruder import __version__
from llm_intruder.reports.models import EngagementReport, FindingSummary

# SARIF severity mapping
_SEVERITY_MAP = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "none":     "none",
}


class SarifExporter:
    """Export an :class:`EngagementReport` as a SARIF 2.1.0 JSON document.

    SARIF (Static Analysis Results Interchange Format) is the standard
    interchange format for security tool output, supported by GitHub Advanced
    Security, VS Code, and most SAST platforms.
    """

    SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    VERSION = "2.1.0"
    TOOL_NAME = "LLM-Intruder"

    def export(self, report: EngagementReport) -> dict:
        """Return the SARIF document as a plain Python dict."""
        rules = self._build_rules(report.findings)
        results = self._build_results(report.findings)

        return {
            "$schema": self.SCHEMA,
            "version": self.VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": __version__,
                            "informationUri": "https://github.com/llm-intruder",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "engagementId": report.engagement_id,
                        "generatedAt": report.generated_at.isoformat(),
                        "trialCount": report.trial_count,
                        "blockRate": report.verdict_breakdown.block_rate,
                    },
                }
            ],
        }

    def write(self, report: EngagementReport, output_path: Path) -> Path:
        """Write the SARIF document to *output_path* (JSON)."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = self.export(report)
        output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        return output_path

    # ── Private ────────────────────────────────────────────────────────────────

    def _build_rules(self, findings: list[FindingSummary]) -> list[dict]:
        """One SARIF rule per unique (category, owasp_category) pair."""
        seen: set[str] = set()
        rules: list[dict] = []
        for f in findings:
            rule_id = self._rule_id(f)
            if rule_id in seen:
                continue
            seen.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": f"{f.category} — {f.owasp_category}"},
                    "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    "properties": {
                        "tags": [f.owasp_category],
                        "severity": f.severity,
                    },
                }
            )
        return rules

    def _build_results(self, findings: list[FindingSummary]) -> list[dict]:
        results: list[dict] = []
        for f in findings:
            result: dict = {
                "ruleId": self._rule_id(f),
                "level": _SEVERITY_MAP.get(f.severity, "warning"),
                "message": {"text": f.description},
                "properties": {
                    "trialId": f.trial_id,
                    "severity": f.severity,
                    "owaspCategory": f.owasp_category,
                },
            }
            if f.evidence_path:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.evidence_path}
                        }
                    }
                ]
            results.append(result)
        return results

    @staticmethod
    def _rule_id(f: FindingSummary) -> str:
        return f"SENTINEL-{f.category.upper().replace(' ', '_')}"
