"""llm_intruder.rag — Phase 9: Multi-Modal + RAG Boundary testing.

Provides:
  - Adversarial document payload generation (TXT / CSV / Markdown)
  - Adversarial image payload generation (PNG via Pillow, or base64 fallback)
  - RAG boundary probe catalogue and response analyser
  - Citation integrity checker
  - Cross-tenant access probe catalogue and response analyser
  - RagRunner orchestrator
"""
from __future__ import annotations

# One-time Pillow availability check — imported by image_payload.py and runner.py
try:
    import PIL  # noqa: F401
    PILLOW_AVAILABLE: bool = True
except ImportError:
    PILLOW_AVAILABLE = False

from llm_intruder.rag.models import (
    BoundaryProbeResult,
    CitationCheckResult,
    CrossTenantProbeResult,
    DocumentPayloadSpec,
    ImagePayloadSpec,
    ParsedCitation,
    RagTestSummary,
)
from llm_intruder.rag.runner import RagRunner

__all__ = [
    "PILLOW_AVAILABLE",
    "BoundaryProbeResult",
    "CitationCheckResult",
    "CrossTenantProbeResult",
    "DocumentPayloadSpec",
    "ImagePayloadSpec",
    "ParsedCitation",
    "RagTestSummary",
    "RagRunner",
]
