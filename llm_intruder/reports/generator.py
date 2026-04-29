"""Report generator — reads from SQLite and writes HTML / Markdown / JSON."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from llm_intruder.db.schema import Finding, Trial
from llm_intruder.reports.models import (
    EngagementReport,
    FindingSummary,
    StrategyMetrics,
    TrialSummary,
    VerdictBreakdown,
)
from llm_intruder.reports.narrative import build_narrative, _md_to_html as _narrative_md_to_html

try:
    import weasyprint as _weasyprint  # type: ignore
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False

from llm_intruder.reports.pdf_generator import FPDF2_AVAILABLE, write_pdf as _write_pdf_fpdf2


# ── Builder ────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Build and serialise an :class:`EngagementReport` from a DB session.

    Parameters
    ----------
    db_session:
        Active SQLAlchemy session pointing at the ``llm_intruder.db``.
    """

    def __init__(self, db_session: Session, run_meta: dict | None = None) -> None:
        self._session = db_session
        self._run_meta = run_meta or {}

    def build(self, engagement_id: str) -> EngagementReport:
        """Query the DB and return a populated :class:`EngagementReport`."""
        trials_rows = (
            self._session.query(Trial)
            .filter(Trial.engagement_id == engagement_id)
            .order_by(Trial.created_at)
            .all()
        )
        finding_rows = (
            self._session.query(Finding)
            .filter(Finding.engagement_id == engagement_id)
            .order_by(Finding.created_at)
            .all()
        )

        trials = [
            TrialSummary(
                trial_id=t.trial_id,
                strategy=t.strategy,
                verdict=t.verdict,
                confidence=t.confidence,
                payload_hash=t.payload_hash,
                response_hash=t.response_hash,
                request_payload=t.request_payload,
                target_url=t.target_url,
                response_text=t.response_text,
                created_at=t.created_at,
            )
            for t in trials_rows
        ]
        findings = [
            FindingSummary(
                finding_id=f.id,
                trial_id=f.trial_id,
                category=f.category,
                severity=f.severity,
                owasp_category=f.owasp_category,
                description=f.description,
                evidence_path=f.evidence_path,
            )
            for f in finding_rows
        ]

        # Verdict breakdown
        vb = VerdictBreakdown(total=len(trials))
        for t in trials:
            if t.verdict == "pass":
                vb.pass_count += 1
            elif t.verdict == "fail":
                vb.fail_count += 1
            elif t.verdict == "error":
                vb.error_count += 1
            else:
                vb.pending_count += 1

        # Strategy breakdown
        strat_map: dict[str, dict[str, int]] = {}
        for t in trials:
            strat_map.setdefault(t.strategy, {"pass": 0, "fail": 0, "error": 0, "pending": 0})
            strat_map[t.strategy][t.verdict] = strat_map[t.strategy].get(t.verdict, 0) + 1

        # Severity + OWASP counts from findings
        severity_counts: dict[str, int] = {}
        owasp_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            owasp_counts[f.owasp_category] = owasp_counts.get(f.owasp_category, 0) + 1

        report = EngagementReport(
            engagement_id=engagement_id,
            trial_count=len(trials),
            finding_count=len(findings),
            verdict_breakdown=vb,
            strategies_used=sorted(strat_map.keys()),
            strategy_verdict_counts=strat_map,
            severity_counts=severity_counts,
            owasp_category_counts=owasp_counts,
            trials=trials,
            findings=findings,
            # ── Model fingerprint (from run_meta if available) ────────────────
            model_fingerprint_provider=self._run_meta.get("model_fingerprint_provider"),
            model_fingerprint_family=self._run_meta.get("model_fingerprint_family"),
            model_fingerprint_confidence=self._run_meta.get("model_fingerprint_confidence"),
            model_fingerprint_display=self._run_meta.get("model_fingerprint_display"),
            model_fingerprint_custom=bool(self._run_meta.get("model_fingerprint_custom", False)),
        )

        # Auto-generate attack narrative (always — reads from report's own data)
        try:
            narrative = build_narrative(report)
            report.attack_narrative_md = narrative.to_markdown()
        except Exception:
            pass  # narrative is non-critical; never block report generation

        return report

    # ── Writers ────────────────────────────────────────────────────────────────

    def write_json(self, report: EngagementReport, output_path: Path) -> Path:
        """Write the report as a JSON file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return output_path

    def write_markdown(self, report: EngagementReport, output_path: Path) -> Path:
        """Write a Markdown summary report."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(_render_markdown(report), encoding="utf-8")
        return output_path

    def write_html(self, report: EngagementReport, output_path: Path, *, full: bool = False) -> Path:
        """Write an HTML report.

        Parameters
        ----------
        full:
            When True the report includes Appendix B — Full Trial Evidence
            with every trial's complete payload and response for manual QA.
            When False (default) only confirmed findings are shown.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(_render_html(report, full=full), encoding="utf-8")
        return output_path

    def write_pdf(self, report: EngagementReport, output_path: Path) -> Path:
        """Write a PDF report using fpdf2 (preferred) or WeasyPrint as fallback.

        fpdf2 is pure Python and works on Windows without system libraries.
        Install with: pip install fpdf2
        """
        if FPDF2_AVAILABLE:
            return _write_pdf_fpdf2(report, output_path)
        if WEASYPRINT_AVAILABLE:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            html_str = _render_html(report)
            _weasyprint.HTML(string=html_str).write_pdf(str(output_path))
            return output_path
        raise RuntimeError(
            "No PDF library available. Install fpdf2: pip install fpdf2"
        )


# ── Benchmark builder ──────────────────────────────────────────────────────────

def build_benchmark(engagement_id: str, db_session: Session):
    """Compute :class:`~llm_intruder.reports.models.BenchmarkMetrics` from DB."""
    from llm_intruder.reports.models import BenchmarkMetrics

    trials_rows = (
        db_session.query(Trial)
        .filter(Trial.engagement_id == engagement_id)
        .all()
    )

    total = len(trials_rows)
    verdict_counts: dict[str, int] = {}
    strategy_map: dict[str, StrategyMetrics] = {}
    total_conf = 0.0

    for t in trials_rows:
        verdict_counts[t.verdict] = verdict_counts.get(t.verdict, 0) + 1
        total_conf += t.confidence
        sm = strategy_map.setdefault(
            t.strategy, StrategyMetrics(strategy=t.strategy)
        )
        sm.total += 1
        if t.verdict == "pass":
            sm.pass_count += 1
        elif t.verdict == "fail":
            sm.fail_count += 1

    pass_count = verdict_counts.get("pass", 0)
    fail_count = verdict_counts.get("fail", 0)

    return BenchmarkMetrics(
        engagement_id=engagement_id,
        total_trials=total,
        block_rate=round(pass_count / total, 4) if total else 0.0,
        attack_success_rate=round(fail_count / total, 4) if total else 0.0,
        avg_confidence=round(total_conf / total, 4) if total else 0.0,
        strategies_tested=len(strategy_map),
        by_strategy=sorted(strategy_map.values(), key=lambda s: s.strategy),
        verdict_counts=verdict_counts,
    )


def build_comparison(baseline, current):
    """Compute :class:`~llm_intruder.reports.models.ComparisonReport`."""
    from llm_intruder.reports.models import ComparisonReport

    block_delta = round(current.block_rate - baseline.block_rate, 4)
    attack_delta = round(
        current.attack_success_rate - baseline.attack_success_rate, 4
    )

    # Per-strategy block_rate deltas
    baseline_strat = {s.strategy: s.block_rate for s in baseline.by_strategy}
    current_strat = {s.strategy: s.block_rate for s in current.by_strategy}
    all_strats = set(baseline_strat) | set(current_strat)
    strategy_deltas = {
        s: round(current_strat.get(s, 0.0) - baseline_strat.get(s, 0.0), 4)
        for s in sorted(all_strats)
    }

    return ComparisonReport(
        baseline_engagement=baseline.engagement_id,
        current_engagement=current.engagement_id,
        baseline_block_rate=baseline.block_rate,
        current_block_rate=current.block_rate,
        block_rate_delta=block_delta,
        baseline_attack_success_rate=baseline.attack_success_rate,
        current_attack_success_rate=current.attack_success_rate,
        attack_success_delta=attack_delta,
        baseline_trials=baseline.total_trials,
        current_trials=current.total_trials,
        improved=block_delta > 0,
        strategy_deltas=strategy_deltas,
    )


# ── Render helpers ─────────────────────────────────────────────────────────────

def _render_markdown(report: EngagementReport) -> str:
    lines: list[str] = [
        f"# LLM-Intruder Security Assessment Report",
        f"",
        f"**Engagement:** {report.engagement_id}  ",
        f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Trials:** {report.trial_count}  |  **Findings:** {report.finding_count}",
        f"",
    ]

    # ── Model fingerprint section ─────────────────────────────────────────────
    if report.model_fingerprint_display:
        lines += [
            f"## Target Model Identification",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Model | {report.model_fingerprint_display} |",
            f"| Provider | {report.model_fingerprint_provider or 'Unknown'} |",
            f"| Model Family | {report.model_fingerprint_family or 'Unknown'} |",
            f"| Confidence | {round((report.model_fingerprint_confidence or 0) * 100)}% |",
            f"| Custom Fine-Tune | {'Yes' if report.model_fingerprint_custom else 'No'} |",
            f"",
        ]

    lines += [
        f"## Verdict Summary",
        f"",
        f"| Verdict | Count |",
        f"|---------|-------|",
        f"| Pass (blocked) | {report.verdict_breakdown.pass_count} |",
        f"| Fail (attack succeeded) | {report.verdict_breakdown.fail_count} |",
        f"| Error | {report.verdict_breakdown.error_count} |",
        f"| Pending | {report.verdict_breakdown.pending_count} |",
        f"| **Total** | **{report.verdict_breakdown.total}** |",
        f"",
        f"**Block Rate:** {report.verdict_breakdown.block_rate:.1%}  ",
        f"**Attack Success Rate:** {report.verdict_breakdown.attack_success_rate:.1%}",
        f"",
    ]

    if report.strategy_verdict_counts:
        lines += [
            f"## Strategies",
            f"",
            f"| Strategy | Pass | Fail | Error |",
            f"|----------|------|------|-------|",
        ]
        for strat in sorted(report.strategy_verdict_counts):
            vc = report.strategy_verdict_counts[strat]
            lines.append(
                f"| {strat} | {vc.get('pass',0)} | {vc.get('fail',0)} | {vc.get('error',0)} |"
            )
        lines.append("")

    if report.findings:
        lines += [
            f"## Findings ({report.finding_count})",
            f"",
        ]
        if report.severity_counts:
            lines += [
                f"| Severity | Count |",
                f"|----------|-------|",
            ]
            for sev in ("critical", "high", "medium", "low", "none"):
                cnt = report.severity_counts.get(sev, 0)
                if cnt:
                    lines.append(f"| {sev.upper()} | {cnt} |")
            lines.append("")

        trial_lookup = {t.trial_id: t for t in report.trials}
        for f in report.findings:
            trial = trial_lookup.get(f.trial_id)
            lines.append(
                f"- **[{f.severity.upper()}]** `{f.category}` / {f.owasp_category}"
            )
            lines.append(f"  {f.description}")
            if trial:
                req = (trial.request_payload or "").strip()
                # Strip [classifier:...] prefix — report shows real response only
                raw_resp = (trial.response_text or "").strip()
                if raw_resp.startswith("[classifier:"):
                    raw_resp = raw_resp.split("\n", 1)[1].strip() if "\n" in raw_resp else ""
                if req:
                    lines.append(f"")
                    lines.append(f"  **HTTP Request:**")
                    lines.append(f"  ```http")
                    lines.append(f"  {req}")
                    lines.append(f"  ```")
                if raw_resp:
                    lines.append(f"")
                    lines.append(f"  **Response Received:**")
                    lines.append(f"  ```")
                    lines.append(f"  {raw_resp}")
                    lines.append(f"  ```")
            lines.append("")

    if not report.findings:
        lines += ["## Findings", "", "_No findings recorded._", ""]

    if report.attack_narrative_md:
        lines += [
            "## Attack Narrative",
            "",
            report.attack_narrative_md,
            "",
        ]

    lines += [
        "---",
        "_Generated by LLM-Intruder_",
    ]
    return "\n".join(lines)


def _render_html(report: EngagementReport, *, full: bool = False) -> str:
    """Polished self-contained HTML report.

    Parameters
    ----------
    report:
        Populated :class:`EngagementReport`.
    full:
        When ``True`` the report includes **Appendix B — Full Trial Evidence**
        which lists every trial (pass, fail, error) with its complete request
        payload and unredacted response, suitable for manual QA review.
        When ``False`` (default) only confirmed findings are shown.
    """
    vb = report.verdict_breakdown

    # ── Shared helpers ────────────────────────────────────────────────────────
    def _esc(s: str) -> str:
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _clean_response(text: str) -> str:
        """Strip [classifier:...] metadata line added by the hunt runner."""
        t = (text or "").strip()
        if t.startswith("[classifier:"):
            parts = t.split("\n", 1)
            return parts[1].strip() if len(parts) > 1 else ""
        return t

    def _format_request_pre(req_payload: str, target_url: str) -> str:
        """Return a <pre class='payload-box'>…</pre> block with syntax colour."""
        if not req_payload and not target_url:
            return "<span class='na'>—</span>"
        stripped = (req_payload or "").strip() or f"POST {target_url}"
        lines = stripped.split("\n", 1)
        first_line = lines[0].strip()
        body = lines[1].strip() if len(lines) > 1 else ""
        if " " in first_line:
            method, url_part = first_line.split(" ", 1)
            first_html = (
                f"<span class='http-method'>{_esc(method)}</span> "
                f"<span class='http-url'>{_esc(url_part)}</span>"
            )
        else:
            first_html = _esc(first_line)
        body_html = f"\n\n{_esc(body)}" if body else ""
        return f"<pre class='payload-box'>{first_html}{body_html}</pre>"

    # ── Severity helpers ──────────────────────────────────────────────────────
    SEV_COLOR = {
        "critical": "#7c1a1a", "high": "#b94a00",
        "medium": "#7a6400", "low": "#2d6a2d", "none": "#555",
    }
    SEV_ORDER = ("critical", "high", "medium", "low", "none")

    def _sev_color(sev: str) -> str:
        return SEV_COLOR.get(sev.lower(), "#333")

    def _sev_badge(sev: str) -> str:
        return f"<span class='sev-badge' style='background:{_sev_color(sev)}'>{sev.upper()}</span>"

    # ── Overall risk rating (highest severity present) ────────────────────────
    overall_sev = "none"
    for s in SEV_ORDER:
        if report.severity_counts.get(s, 0):
            overall_sev = s
            break

    RISK_LABEL = {
        "critical": "CRITICAL", "high": "HIGH",
        "medium": "MEDIUM", "low": "LOW", "none": "INFO",
    }

    RISK_SUMMARY = {
        "critical": "Critical vulnerabilities were confirmed. Immediate remediation required — do not expose to production traffic.",
        "high": "The guardrails hold against most inputs, but reproducible bypasses exist that disclose protected content. Remediation is required before this configuration is considered production-safe.",
        "medium": "Some guardrail weaknesses were identified. Review and harden the affected strategies before wider deployment.",
        "low": "Minor issues detected. The guardrails are broadly effective; low-priority hardening is recommended.",
        "none": "No confirmed findings. The target's guardrails successfully blocked all adversarial payloads in this engagement.",
    }

    # ── Trial lookup ──────────────────────────────────────────────────────────
    trial_lookup: dict[str, "TrialSummary"] = {t.trial_id: t for t in report.trials}

    # ── Model fingerprint section ─────────────────────────────────────────────
    if report.model_fingerprint_display:
        fp_conf_pct = f"{round((report.model_fingerprint_confidence or 0) * 100)}%"
        fp_custom_label = "Yes" if report.model_fingerprint_custom else "No"
        fp_section = f"""
<h2 class="section" id="target">4. Target Model Identification</h2>
<table>
<tr><th>Attribute</th><th>Value</th></tr>
<tr><td>Most likely model</td><td><strong>{_esc(report.model_fingerprint_display)} (confidence={fp_conf_pct})</strong></td></tr>
<tr><td>Provider</td><td>{_esc(report.model_fingerprint_provider or 'Unknown')}</td></tr>
<tr><td>Model family</td><td>{_esc(report.model_fingerprint_family or 'Unknown')}</td></tr>
<tr><td>Fingerprint confidence</td><td>{fp_conf_pct}</td></tr>
<tr><td>Custom fine-tune</td><td>{fp_custom_label}</td></tr>
</table>
<p class="na">Identification is heuristic — derived from probe responses — and should be
   treated as indicative rather than authoritative.</p>
"""
        target_toc = '<li><a href="#target">Target Model Identification</a></li>'
        target_section_num = 4
        findings_section_num = 5
        strategy_section_num = 6
        narrative_section_num = 7
        appendix_a_num = 8
        appendix_b_num = 9
        disclaimer_num = 10
    else:
        fp_section = ""
        target_toc = ""
        target_section_num = None
        findings_section_num = 4
        strategy_section_num = 5
        narrative_section_num = 6
        appendix_a_num = 7
        appendix_b_num = 8
        disclaimer_num = 9

    # ── KPI bar ───────────────────────────────────────────────────────────────
    sev_kpis = ""
    for s in SEV_ORDER:
        cnt = report.severity_counts.get(s, 0)
        if cnt:
            sev_kpis += (
                f'  <div class="kpi"><div class="label">{s.upper()} severity</div>'
                f'<div class="value" style="color:{_sev_color(s)}">{cnt}</div></div>\n'
            )

    strat_count = len(report.strategies_used)

    # ── Executive summary: most significant finding ───────────────────────────
    most_sig = ""
    if report.findings:
        f0 = report.findings[0]
        most_sig = (
            f"<p><strong>Most significant finding:</strong> "
            f"<em>{_esc(f0.owasp_category)}</em> — {_esc(f0.description)}</p>"
        )

    # ── Findings overview tables ──────────────────────────────────────────────
    sev_table_rows = ""
    for s in SEV_ORDER:
        cnt = report.severity_counts.get(s, 0)
        if cnt:
            sev_table_rows += f"<tr><td>{_sev_badge(s)}</td><td>{cnt}</td></tr>"

    owasp_table_rows = ""
    for cat, cnt in sorted(report.owasp_category_counts.items(), key=lambda x: -x[1]):
        owasp_table_rows += f"<tr><td>{_esc(cat)}</td><td>{cnt}</td></tr>"

    # ── Detailed findings cards ───────────────────────────────────────────────
    REMEDIATION = {
        "critical": [
            "Stop all production traffic to this endpoint immediately.",
            "Rotate any leaked secrets, credentials or API keys.",
            "Implement a server-side output filter before re-enabling.",
            "Conduct a full audit of all prompts and responses logged to date.",
        ],
        "high": [
            "Remove all secrets, credentials and proprietary data from the system prompt — assume any system-prompt content is reachable by an attacker.",
            "Where a secret must influence behaviour, store it server-side and gate the action behind a deterministic check, not the model's judgement.",
            "Add an output filter that redacts known secret patterns (passwords, API keys, internal identifiers) before the response leaves the server.",
            "Log and alert on responses that contain protected tokens — treat these as confirmed disclosures.",
        ],
        "medium": [
            "Review the affected strategy and harden the system prompt against the demonstrated bypass.",
            "Add rule-based post-processing to catch partial disclosures.",
            "Schedule a follow-up test after changes are applied.",
        ],
        "low": [
            "Investigate the flagged response pattern and apply a targeted system-prompt patch.",
            "Monitor for recurrence in production logs.",
        ],
        "none": [
            "No immediate action required; maintain current guardrail configuration.",
        ],
    }

    finding_cards = ""
    for idx, f in enumerate(report.findings, 1):
        trial = trial_lookup.get(f.trial_id)
        req_payload = (trial.request_payload or "").strip() if trial else ""
        target_url = (trial.target_url or "").strip() if trial else ""
        resp_text = _clean_response(trial.response_text if trial else "")
        conf_pct = f"{round((trial.confidence or 0) * 100)}%" if trial else "—"

        flags_html = ""
        if hasattr(f, "flags") and f.flags:
            flags_html = "".join(f"<span class='flag'>{_esc(fl)}</span>" for fl in f.flags)
        elif trial and hasattr(trial, "flags") and trial.flags:
            flags_html = "".join(f"<span class='flag'>{_esc(fl)}</span>" for fl in trial.flags)

        sev_lo = f.severity.lower()
        remediation_items = "".join(
            f"<li>{_esc(item)}</li>"
            for item in REMEDIATION.get(sev_lo, REMEDIATION["none"])
        )

        finding_cards += f"""<div class="finding" style="border-left-color:{_sev_color(sev_lo)}" id="finding-{idx}">
  <h3>Finding {idx}: {_esc(f.owasp_category)}</h3>
  <div class="meta-row">
    {_sev_badge(sev_lo)}
    <span class="pill">Strategy: {_esc(trial.strategy if trial else '—')}</span>
    <span class="pill">Trial: <code>{_esc(f.trial_id)}</code></span>
    <span class="pill">Judge confidence: {conf_pct}</span>
    {flags_html}
  </div>

  <h4>Risk Summary</h4>
  <p>{_esc(f.description)}</p>

  <h4>Reproduction — Request Sent to Target</h4>
  {_format_request_pre(req_payload, target_url)}

  <h4>Observed Response</h4>
  {"<pre class='response-box'>" + _esc(resp_text) + "</pre>" if resp_text else "<span class='na'>—</span>"}

  <h4>Recommended Remediation</h4>
  <ul>{remediation_items}</ul>
</div>"""

    # ── Strategy effectiveness table ──────────────────────────────────────────
    strat_rows = ""
    for strat in sorted(report.strategy_verdict_counts):
        vc = report.strategy_verdict_counts[strat]
        total_s = vc.get("pass", 0) + vc.get("fail", 0) + vc.get("error", 0)
        bypass_rate = (
            f"{vc.get('fail', 0) / total_s:.0%}" if total_s else "—"
        )
        strat_rows += (
            f"<tr><td><code>{_esc(strat)}</code></td>"
            f"<td>{vc.get('pass', 0)}</td>"
            f"<td>{vc.get('fail', 0)}</td>"
            f"<td>{vc.get('error', 0)}</td>"
            f"<td>{bypass_rate}</td></tr>\n"
        )

    # ── Appendix A — Trial Timeline ───────────────────────────────────────────
    timeline_rows = ""
    for idx, t in enumerate(report.trials, 1):
        v = (t.verdict or "pending").lower()
        v_class = {"pass": "v-pass", "fail": "v-fail", "error": "v-err"}.get(v, "")
        v_label = {"pass": "BLOCKED", "fail": "BYPASSED", "error": "ERROR"}.get(v, v.upper())
        conf_pct = f"{round((t.confidence or 0) * 100)}%"
        timeline_rows += (
            f"<tr><td>{idx}</td><td><code>{_esc(t.strategy)}</code></td>"
            f"<td class='{v_class}'>{v_label}</td><td>{conf_pct}</td>"
            f"<td><code>{_esc(t.trial_id)}</code></td></tr>"
        )

    # ── Appendix B — Full Trial Evidence (only when full=True) ────────────────
    appendix_b_toc = ""
    appendix_b_html = ""
    if full:
        appendix_b_toc = f'<li><a href="#appendix-b">Appendix B — Full Trial Evidence (manual QA)</a></li>'
        bypassed_count = vb.fail_count
        blocked_count = vb.pass_count
        error_count = vb.error_count

        trial_details = ""
        for idx, t in enumerate(report.trials, 1):
            v = (t.verdict or "pending").lower()
            v_class = {"pass": "v-pass", "fail": "v-fail", "error": "v-err"}.get(v, "")
            v_label = {"pass": "BLOCKED", "fail": "BYPASSED", "error": "ERROR"}.get(v, v.upper())
            conf_pct = f"{round((t.confidence or 0) * 100)}%"
            req_payload = (t.request_payload or "").strip()
            target_url = (t.target_url or "").strip()
            resp_text = _clean_response(t.response_text or "")
            trial_details += f"""
<details class="trial" open>
  <summary>
    <span class="{v_class}">#{idx} · {v_label}</span>
    · <code>{_esc(t.strategy)}</code>
    · trial <code>{_esc(t.trial_id)}</code>
    · judge confidence {conf_pct}
  </summary>
  <div class="body">
    <h4>Request sent</h4>
    {_format_request_pre(req_payload, target_url)}
    <h4>Response received</h4>
    {"<pre class='response-box'>" + _esc(resp_text) + "</pre>" if resp_text else "<span class='na'>—</span>"}
  </div>
</details>
"""
        appendix_b_html = f"""
<h2 class="section" id="appendix-b">Appendix {appendix_b_num} — Full Trial Evidence (manual analysis)</h2>
<p>This appendix contains <strong>every trial</strong> executed during this engagement —
   bypassed, blocked, errored and pending — with the complete request payload sent
   to the target and the unredacted response received. It is provided so a reviewer
   can manually verify the automated judge's verdicts, identify partial-disclosure
   patterns the heuristics may have missed, and audit the target's refusal quality.
   Each entry is collapsible — click to expand the full request and response.</p>
<p>
  <strong>Total trials:</strong> {vb.total}
  &nbsp;·&nbsp; <span class="v-fail">Bypassed: {bypassed_count}</span>
  &nbsp;·&nbsp; <span class="v-pass">Blocked: {blocked_count}</span>
  &nbsp;·&nbsp; Errors: {error_count}
</p>
<div style="margin:.5rem 0 1rem">
  <button type="button" onclick="document.querySelectorAll('#appendix-b ~ details.trial, details.trial').forEach(d=>d.open=true)"
          class="appendix-btn">Expand all</button>
  <button type="button" onclick="document.querySelectorAll('#appendix-b ~ details.trial, details.trial').forEach(d=>d.open=false)"
          class="appendix-btn">Collapse all</button>
  <span style="font-size:.8rem;color:#5b6373;margin-left:.5rem">All trials are expanded by default so every payload and response is immediately visible.</span>
</div>
<style>.appendix-btn{{background:#fff;border:1px solid #d6d9e0;border-radius:4px;padding:.3rem .7rem;font-size:.8rem;cursor:pointer;margin-right:.35rem}}.appendix-btn:hover{{background:#eaf2fb;border-color:#0b5394;color:#0b5394}}</style>
{trial_details}
"""

    # ── TOC ───────────────────────────────────────────────────────────────────
    toc_items = (
        f'<li><a href="#exec">Executive Summary</a></li>'
        f'<li><a href="#dashboard">Risk Dashboard</a></li>'
        f'<li><a href="#methodology">Methodology &amp; Scope</a></li>'
        f'{target_toc}'
        f'<li><a href="#findings-summary">Findings Overview ({report.finding_count})</a></li>'
        f'<li><a href="#findings-detail">Detailed Findings</a></li>'
        f'<li><a href="#strategy-eff">Strategy Effectiveness</a></li>'
        f'<li><a href="#narrative">Attack Narrative</a></li>'
        f'<li><a href="#appendix-a">Appendix A — Trial Timeline</a></li>'
        f'{appendix_b_toc}'
        f'<li><a href="#disclaimer">Disclaimers</a></li>'
    )

    # ── Narrative ─────────────────────────────────────────────────────────────
    narrative_html = ""
    if report.attack_narrative_md:
        narrative_html = (
            f'<h2 class="section" id="narrative">{narrative_section_num}. Attack Narrative</h2>'
            f'<div class="narrative">{_narrative_md_to_html(report.attack_narrative_md)}</div>'
        )

    # ── Full HTML ─────────────────────────────────────────────────────────────
    doc_type = "Full evidence report" if full else "Findings report"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LLM-Intruder — Security Assessment Report — {_esc(report.engagement_id)}</title>
<style>
:root{{
  --ink:#1a1a2e; --ink2:#16213e; --muted:#5b6373; --line:#d6d9e0;
  --bg:#fafbfd; --card:#ffffff; --accent:#0b5394; --accent-soft:#eaf2fb;
}}
*{{box-sizing:border-box}}
body{{font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
     max-width:1180px;margin:0 auto;padding:2.5rem 1.5rem 4rem;
     color:#222;background:var(--bg);line-height:1.55;}}
header.cover{{border-bottom:3px solid var(--ink);padding-bottom:1.25rem;margin-bottom:2rem}}
header.cover .eyebrow{{color:var(--accent);font-weight:600;letter-spacing:.12em;
     text-transform:uppercase;font-size:.78rem;margin-bottom:.5rem}}
header.cover h1{{margin:0 0 .5rem;color:var(--ink);font-size:2rem;font-weight:700;letter-spacing:-.01em}}
header.cover .meta{{color:var(--muted);font-size:.92rem}}
header.cover .meta strong{{color:#222}}
h2.section{{color:var(--ink);font-size:1.35rem;margin:2.5rem 0 1rem;
     padding-bottom:.4rem;border-bottom:1px solid var(--line)}}
h3.sub{{color:var(--ink2);font-size:1.05rem;margin:1.25rem 0 .5rem}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0 1.25rem;
     font-size:.92rem;background:var(--card);border:1px solid var(--line)}}
th,td{{border:1px solid var(--line);padding:8px 12px;text-align:left;vertical-align:top}}
th{{background:var(--ink);color:#fff;font-weight:600;font-size:.85rem;letter-spacing:.02em}}
tr:nth-child(even) td{{background:#fafbfd}}
.toc{{background:var(--card);border:1px solid var(--line);border-radius:6px;
     padding:1rem 1.25rem;margin:1rem 0 2rem}}
.toc ol{{margin:.25rem 0 0 1.25rem;padding:0}}
.toc li{{margin:.15rem 0}}
.toc a{{color:var(--accent);text-decoration:none}}
.toc a:hover{{text-decoration:underline}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
     gap:.75rem;margin:1rem 0 1.5rem}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:6px;
     padding:.85rem 1rem}}
.kpi .label{{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600}}
.kpi .value{{font-size:1.6rem;font-weight:700;color:var(--ink);margin-top:.15rem}}
.kpi .sub{{font-size:.78rem;color:var(--muted)}}
.risk-banner{{display:flex;align-items:center;gap:1rem;padding:1rem 1.25rem;
     border-left:6px solid #b94a00;background:#fff;border:1px solid var(--line);
     border-radius:6px;margin:1rem 0 1.5rem}}
.risk-banner .badge{{font-weight:700;letter-spacing:.06em;padding:.35rem .7rem;
     border-radius:4px;color:#fff;font-size:.85rem;flex-shrink:0}}
.risk-banner p{{margin:0;color:#333}}
.sev-badge{{display:inline-block;padding:.18rem .55rem;border-radius:3px;
     font-size:.72rem;font-weight:700;letter-spacing:.04em;color:#fff}}
.finding{{background:var(--card);border:1px solid var(--line);border-left:4px solid #b94a00;
     border-radius:6px;padding:1.1rem 1.25rem;margin:1rem 0}}
.finding h3{{margin:0 0 .35rem;color:var(--ink);font-size:1.08rem}}
.finding .meta-row{{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;
     color:var(--muted);font-size:.82rem;margin-bottom:.6rem}}
.finding .meta-row .pill{{background:var(--accent-soft);color:var(--accent);
     padding:.15rem .55rem;border-radius:3px;font-weight:600}}
.finding .meta-row .flag{{background:#fdecea;color:#7c1a1a;padding:.12rem .45rem;
     border-radius:3px;font-size:.72rem}}
.finding h4{{margin:.85rem 0 .3rem;color:var(--ink2);font-size:.92rem;
     text-transform:uppercase;letter-spacing:.04em}}
.finding p{{margin:.25rem 0}}
.finding ul{{margin:.25rem 0 .25rem 1.25rem;padding:0}}
.finding li{{margin:.15rem 0}}
.payload-box,.response-box{{padding:10px 12px;border-radius:4px;
     white-space:pre-wrap;word-break:break-word;font-size:.78rem;
     max-height:280px;overflow-y:auto;margin:.25rem 0;
     line-height:1.55;font-family:'JetBrains Mono','Consolas',monospace;
     border:1px solid #2a2a40}}
.payload-box{{background:#1e1e2e;color:#cdd6f4}}
.response-box{{background:#10241a;color:#a6e3a1;border-color:#1e3a28}}
.payload-box .http-method{{color:#f38ba8;font-weight:bold}}
.payload-box .http-url{{color:#89b4fa}}
.na{{color:#9aa0aa;font-style:italic}}
.narrative{{background:#fafbff;border-left:4px solid var(--ink);padding:1rem 1.5rem;
     border-radius:0 4px 4px 0;margin:1rem 0;line-height:1.7}}
.narrative h1,.narrative h2,.narrative h3,.narrative h4{{color:var(--ink);margin:1.2rem 0 .5rem}}
.narrative h1{{font-size:1.25rem;border-bottom:1px solid #c8cce8;padding-bottom:4px}}
.narrative h2{{font-size:1.08rem}}
.narrative h3{{font-size:.98rem}}
.narrative p{{margin:.4rem 0}}
.narrative code{{background:#eef0f6;padding:1px 5px;border-radius:3px;
     font-family:'JetBrains Mono','Consolas',monospace;font-size:.86em}}
.narrative pre{{background:#1e1e2e;color:#cdd6f4;padding:10px;border-radius:4px;
     overflow-x:auto;font-size:.85rem}}
.narrative-table{{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}}
.narrative-table td{{border:1px solid var(--line);padding:5px 10px;vertical-align:top}}
.narrative-table tr:first-child td{{background:var(--ink);color:#fff;font-weight:bold}}
.narrative-table tr:nth-child(even) td{{background:#f4f4f8}}
.timeline-table td.v-pass{{color:#2d6a2d;font-weight:600}}
.timeline-table td.v-fail{{color:#7c1a1a;font-weight:700}}
.timeline-table td.v-err{{color:#8a6d00}}
details.trial{{background:var(--card);border:1px solid var(--line);
     border-radius:5px;margin:.5rem 0;padding:.6rem .9rem}}
details.trial[open]{{border-color:var(--accent)}}
details.trial summary{{cursor:pointer;font-size:.9rem;display:flex;
     gap:.6rem;align-items:center;flex-wrap:wrap}}
details.trial summary .v-pass{{color:#2d6a2d;font-weight:600}}
details.trial summary .v-fail{{color:#7c1a1a;font-weight:700}}
details.trial .body{{margin-top:.6rem}}
.disclaimer{{background:#fffbe6;border:1px solid #f0d96b;border-radius:5px;
     padding:.75rem 1rem;margin:1.5rem 0;font-size:.85rem;color:#5a4a00}}
footer.report-footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);
     color:var(--muted);font-size:.82rem;text-align:center}}
@media print{{
  body{{background:#fff;padding:1cm}}
  details.trial{{break-inside:avoid}}
  .finding{{break-inside:avoid}}
}}
</style>
</head>
<body>
<header class="cover">
  <div class="eyebrow">LLM Security Assessment · Authorised Engagement</div>
  <h1>LLM-Intruder — Security Assessment Report</h1>
  <div class="meta">
    <strong>Engagement ID:</strong> {_esc(report.engagement_id)} &nbsp;·&nbsp;
    <strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}<br/>
    <strong>Document type:</strong> {doc_type} &nbsp;·&nbsp;
    <strong>Classification:</strong> Confidential — internal use
  </div>
</header>

<nav class="toc">
  <strong>Contents</strong>
  <ol>{toc_items}</ol>
</nav>

<h2 class="section" id="exec">1. Executive Summary</h2>
<div class="risk-banner" style="border-left-color:{_sev_color(overall_sev)}">
  <span class="badge" style="background:{_sev_color(overall_sev)}">{RISK_LABEL[overall_sev]}</span>
  <p>{RISK_SUMMARY[overall_sev]}</p>
</div>
<p>This report documents an authorised security assessment of the target's LLM-based
   conversational interface. <strong>{vb.total}</strong> adversarial test cases were
   executed against the target. The guardrails blocked <strong>{vb.pass_count}</strong>
   ({vb.block_rate:.1%}) and were bypassed in <strong>{vb.fail_count}</strong>
   ({vb.attack_success_rate:.1%}) cases, producing <strong>{report.finding_count}</strong>
   confirmed finding(s) classified under the OWASP LLM Top 10.</p>
{most_sig}

<h2 class="section" id="dashboard">2. Risk Dashboard</h2>
<div class="kpi-grid">
  <div class="kpi"><div class="label">Trials executed</div><div class="value">{vb.total}</div></div>
  <div class="kpi"><div class="label">Block rate</div>
      <div class="value" style="color:#2d6a2d">{vb.block_rate:.1%}</div>
      <div class="sub">{vb.pass_count} blocked</div></div>
  <div class="kpi"><div class="label">Attack success rate</div>
      <div class="value" style="color:#b94a00">{vb.attack_success_rate:.1%}</div>
      <div class="sub">{vb.fail_count} bypassed</div></div>
  <div class="kpi"><div class="label">Findings</div>
      <div class="value">{report.finding_count}</div>
      <div class="sub">{strat_count} strategy / strategies</div></div>
{sev_kpis}</div>

<h2 class="section" id="methodology">3. Methodology &amp; Scope</h2>
<p>The assessment was performed by the LLM-Intruder framework, an automated
   adversarial-testing harness for conversational AI systems. Each trial in
   this engagement consisted of:</p>
<ol>
  <li><strong>Payload selection</strong> — an adversarial prompt drawn from the
      configured strategy library (e.g. authority impersonation, role
      override, format injection, refusal suppression).</li>
  <li><strong>Delivery</strong> — the payload was delivered to the target's
      conversational endpoint exactly as a normal user message would be,
      with no out-of-band channel or privileged access.</li>
  <li><strong>Capture</strong> — the full request and response were recorded
      for replay and audit.</li>
  <li><strong>Adjudication</strong> — an independent judge model classified
      each response as <em>pass</em> (guardrail held), <em>fail</em>
      (guardrail bypassed), or <em>error</em>, and assigned a confidence
      score and OWASP LLM Top-10 category to each failure.</li>
</ol>
<p><strong>Scope:</strong> only the conversational interface was tested.
   No infrastructure-level (network, server, OS) testing was performed as
   part of this engagement. All findings relate to model and prompt-layer
   behaviour and should be reviewed alongside any platform-level controls.</p>

{fp_section}

<h2 class="section" id="findings-summary">{findings_section_num}. Findings Overview</h2>
<h3 class="sub">By severity</h3>
<table><tr><th>Severity</th><th>Count</th></tr>{sev_table_rows or "<tr><td colspan='2'>No findings</td></tr>"}</table>
<h3 class="sub">By OWASP LLM Top-10 category</h3><table><tr><th>OWASP LLM category</th><th>Findings</th></tr>{owasp_table_rows or "<tr><td colspan='2'>No findings</td></tr>"}</table>
<h2 class="section" id="findings-detail">{findings_section_num + 1}. Detailed Findings</h2>{"".join([finding_cards]) if finding_cards else "<p class='na'>No confirmed findings in this engagement.</p>"}

<h2 class="section" id="strategy-eff">{strategy_section_num}. Strategy Effectiveness</h2>
<table>
<tr><th>Strategy</th><th>Blocked</th><th>Bypassed</th><th>Error</th><th>Bypass rate</th></tr>
{strat_rows if strat_rows else "<tr><td colspan='5'>No trials</td></tr>"}
</table>

{narrative_html}

<h2 class="section" id="appendix-a">Appendix A — Trial Timeline</h2>
<p>Chronological list of every trial executed during this engagement.</p>
<table class="timeline-table">
<tr><th>#</th><th>Strategy</th><th>Verdict</th><th>Judge confidence</th><th>Trial ID</th></tr>
{timeline_rows if timeline_rows else "<tr><td colspan='5'>No trials</td></tr>"}
</table>

{appendix_b_html}

<h2 class="section" id="disclaimer">Disclaimers</h2>
<div class="disclaimer">
  <strong>Authorised testing only.</strong> All adversarial payloads in this
  report were sent under an explicit authorisation to perform security testing
  against the named target. The payloads and responses are reproduced here for
  audit and remediation purposes only. Redistribution of this report outside
  the authorised scope is prohibited.
</div>

<footer class="report-footer">Generated by LLM-Intruder &mdash; authorised security assessment only.</footer>
</body>
</html>"""
    return html
