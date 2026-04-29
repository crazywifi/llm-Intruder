"""PDF report generator using fpdf2 (pure Python, no system dependencies)."""
from __future__ import annotations

from pathlib import Path

from llm_intruder.reports.models import EngagementReport

try:
    from fpdf import FPDF, XPos, YPos  # type: ignore
    FPDF2_AVAILABLE = True
except ImportError:
    FPDF2_AVAILABLE = False


# ── Colour palette ─────────────────────────────────────────────────────────────
_DARK    = (26,  26,  46)
_MID     = (22,  33,  62)
_WHITE   = (255, 255, 255)
_LIGHT   = (240, 240, 245)
_RED     = (180,  30,  30)
_ORANGE  = (185,  74,   0)
_YELLOW  = (140, 110,   0)
_GREEN   = ( 30, 120,  30)
_GREY    = (120, 120, 120)

_SEV_COLOUR = {
    "critical": _RED,
    "high":     _ORANGE,
    "medium":   _YELLOW,
    "low":      _GREEN,
    "none":     _GREY,
}


def _safe(s: str, max_len: int = 200) -> str:
    """Sanitise a string for Helvetica (Latin-1 only).

    Characters outside Latin-1 (codepoint > 255) are replaced with '?' so
    fpdf2 does not raise a font-encoding error on Unicode payloads (e.g.
    Korean, Chinese, emoji, or multi-language injection payloads).
    """
    cleaned = "".join(c if ord(c) < 256 else "?" for c in (s or ""))
    return cleaned[:max_len]


class ReportPDF(FPDF):
    """Custom FPDF subclass with header/footer and helper methods."""

    def __init__(self, engagement_id: str):
        super().__init__()
        self.engagement_id = engagement_id
        self.set_auto_page_break(auto=True, margin=18)

    def header(self):
        self.set_fill_color(*_DARK)
        self.rect(0, 0, 210, 14, "F")
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 9)
        self.set_xy(8, 3)
        self.cell(130, 8, "LLM-Intruder  |  Security Assessment Report", new_x=XPos.RIGHT)
        self.set_font("Helvetica", "", 8)
        self.set_xy(140, 3)
        self.cell(60, 8, f"Engagement: {self.engagement_id}", align="R")
        self.set_text_color(0, 0, 0)
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*_GREY)
        self.cell(0, 8, f"Page {self.page_no()} | CONFIDENTIAL - Authorised Security Assessment Only",
                  align="C")
        self.set_text_color(0, 0, 0)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def section_title(self, title: str) -> None:
        self.set_fill_color(*_MID)
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def metric_box(self, label: str, value: str, colour: tuple = _MID) -> None:
        self.set_fill_color(*colour)
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 10)
        self.cell(44, 12, f"{label}", fill=True, align="C")
        self.set_fill_color(*_LIGHT)
        self.set_text_color(*_DARK)
        self.set_font("Helvetica", "", 10)
        self.cell(44, 12, f"{value}", fill=True, align="C", new_x=XPos.RIGHT)
        self.set_text_color(0, 0, 0)

    def table_header(self, cols: list[tuple[str, int]]) -> None:
        self.set_fill_color(*_DARK)
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 8)
        for label, width in cols:
            self.cell(width, 7, label, border=1, fill=True, align="C")
        self.ln()
        self.set_text_color(0, 0, 0)

    def table_row(self, cells: list[tuple[str, int]], fill: bool = False) -> None:
        self.set_fill_color(*_LIGHT)
        self.set_font("Helvetica", "", 8)
        for text, width in cells:
            self.cell(width, 6, _safe(str(text), 60), border=1, fill=fill)
        self.ln()

    def severity_badge(self, severity: str) -> None:
        col = _SEV_COLOUR.get(severity.lower(), _GREY)
        self.set_fill_color(*col)
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 7)
        self.cell(22, 5, severity.upper(), fill=True, align="C")
        self.set_text_color(0, 0, 0)


def write_pdf(report: EngagementReport, output_path: Path) -> Path:
    """Generate a PDF report from *report* and write it to *output_path*.

    Requires ``fpdf2``:  pip install fpdf2
    """
    if not FPDF2_AVAILABLE:
        raise RuntimeError(
            "fpdf2 is not installed. Install it with: pip install fpdf2"
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    vb = report.verdict_breakdown
    pdf = ReportPDF(report.engagement_id)
    pdf.add_page()

    # ── Cover metrics ──────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*_DARK)
    pdf.cell(0, 10, "LLM Security Assessment", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_GREY)
    pdf.cell(0, 6, f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Metric boxes
    pdf.metric_box("Total Trials", str(vb.total))
    pdf.metric_box("Findings", str(report.finding_count))
    pdf.ln(14)
    pdf.metric_box("Block Rate", f"{vb.block_rate:.1%}")
    pdf.metric_box("Attack Success", f"{vb.attack_success_rate:.1%}")
    pdf.ln(16)

    # ── Verdict breakdown ──────────────────────────────────────────────────────
    pdf.section_title("Verdict Breakdown")
    cols = [("Verdict", 55), ("Count", 30), ("Percentage", 40)]
    pdf.table_header(cols)
    rows = [
        ("Pass (attack blocked)", vb.pass_count, f"{vb.block_rate:.1%}"),
        ("Fail (attack succeeded)", vb.fail_count, f"{vb.attack_success_rate:.1%}"),
        ("Error", vb.error_count, ""),
        ("Pending", vb.pending_count, ""),
    ]
    for i, (label, count, pct) in enumerate(rows):
        pdf.table_row([(label, 55), (str(count), 30), (pct, 40)], fill=(i % 2 == 0))

    # ── Strategies ─────────────────────────────────────────────────────────────
    if report.strategy_verdict_counts:
        pdf.ln(6)
        pdf.section_title("Strategies Used")
        cols = [("Strategy", 80), ("Pass", 25), ("Fail", 25), ("Error", 25)]
        pdf.table_header(cols)
        for i, strat in enumerate(sorted(report.strategy_verdict_counts)):
            vc = report.strategy_verdict_counts[strat]
            pdf.table_row([
                (strat, 80),
                (str(vc.get("pass", 0)), 25),
                (str(vc.get("fail", 0)), 25),
                (str(vc.get("error", 0)), 25),
            ], fill=(i % 2 == 0))

    # ── Findings ───────────────────────────────────────────────────────────────
    if report.findings:
        pdf.ln(6)
        pdf.section_title(f"Findings ({report.finding_count})")

        trial_lookup = {t.trial_id: t for t in report.trials}

        for i, f in enumerate(report.findings):
            trial = trial_lookup.get(f.trial_id)

            pdf.set_font("Helvetica", "B", 8)
            pdf.set_x(10)
            pdf.severity_badge(f.severity)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_x(34)
            pdf.cell(0, 5,
                     "[" + _safe(f.owasp_category, 30) + "]  " + _safe(f.category, 40) + "  -  Trial: " + f.trial_id[:16],
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            # Description
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(*_GREY)
            pdf.multi_cell(0, 4, "  " + _safe(f.description, 300))
            pdf.set_text_color(0, 0, 0)

            # Request payload block
            if trial and trial.request_payload:
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_text_color(*_MID)
                pdf.cell(0, 5, "  Request Payload:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_fill_color(30, 30, 50)
                pdf.set_text_color(*_WHITE)
                pdf.set_font("Helvetica", "", 7)
                pdf.multi_cell(0, 4, "  " + _safe(trial.request_payload, 500), fill=True)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(1)

            # Response block
            if trial and trial.response_text:
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_text_color(*_MID)
                pdf.cell(0, 5, "  Response Received:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_fill_color(20, 50, 30)
                pdf.set_text_color(*_WHITE)
                pdf.set_font("Helvetica", "", 7)
                pdf.multi_cell(0, 4, "  " + _safe(trial.response_text, 500), fill=True)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(1)

            if i < len(report.findings) - 1:
                pdf.set_draw_color(*_LIGHT)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(2)
    else:
        pdf.ln(4)
        pdf.section_title("Findings")
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 8, "  No findings recorded for this engagement.")
        pdf.ln()

    # ── Footer note ────────────────────────────────────────────────────────────
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(*_GREY)
    pdf.multi_cell(0, 4,
        "This report was generated by LLM-Intruder for authorised security assessment "
        "purposes only. All findings relate to a target system for which written "
        "authorisation was obtained prior to testing.")

    pdf.output(str(output_path))
    return output_path
