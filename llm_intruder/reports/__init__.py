"""llm_intruder.reports — Phase 12/13: Report generation + integrations."""
from llm_intruder.reports.burp import BurpExporter
from llm_intruder.reports.generator import (
    FPDF2_AVAILABLE,
    WEASYPRINT_AVAILABLE,
    ReportGenerator,
    build_benchmark,
    build_comparison,
)
from llm_intruder.reports.models import (
    BenchmarkMetrics,
    ComparisonReport,
    EngagementReport,
    FindingSummary,
    StrategyMetrics,
    TrialSummary,
    VerdictBreakdown,
)
from llm_intruder.reports.pdf_generator import write_pdf
from llm_intruder.reports.sarif import SarifExporter

__all__ = [
    # Classes
    "ReportGenerator",
    "SarifExporter",
    "BurpExporter",
    # Functions
    "build_benchmark",
    "build_comparison",
    "write_pdf",
    # Models
    "BenchmarkMetrics",
    "ComparisonReport",
    "EngagementReport",
    "FindingSummary",
    "StrategyMetrics",
    "TrialSummary",
    "VerdictBreakdown",
    # Flags
    "FPDF2_AVAILABLE",
    "WEASYPRINT_AVAILABLE",
]
