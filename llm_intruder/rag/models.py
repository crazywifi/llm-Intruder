"""Pydantic v2 models for Phase 9 — Multi-Modal + RAG Boundary testing."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_serializer


# ── Document payload ──────────────────────────────────────────────────────────

DocumentFormat = Literal["txt", "csv", "md"]
DocumentVariant = Literal[
    "direct_injection",
    "hidden_instruction",
    "metadata_poisoning",
    "chunked_boundary",
]


class DocumentPayloadSpec(BaseModel):
    format: DocumentFormat
    variant: DocumentVariant
    filename: str
    content: str
    byte_size: int
    sha256_hash: str


# ── Image payload ─────────────────────────────────────────────────────────────

ImageMethod = Literal["text_overlay", "metadata_embed", "base64_fallback"]


class ImagePayloadSpec(BaseModel):
    method: ImageMethod
    adversarial_text: str
    filename: str
    # content_bytes is None for base64_fallback (content stored as base64_content)
    content_bytes: bytes | None = None
    base64_content: str | None = None
    byte_size: int
    sha256_hash: str

    @field_serializer("content_bytes", mode="plain")
    def _serialize_bytes(self, v: bytes | None) -> str | None:
        """Encode PNG bytes as base64 for JSON serialisation."""
        if v is None:
            return None
        return base64.b64encode(v).decode("ascii")


# ── Boundary probe result ─────────────────────────────────────────────────────

BoundaryPatternType = Literal[
    "direct_query",
    "indirect_instruction",
    "context_overflow",
    "delimiter_escape",
    "metadata_sidecar",
    "ghost_citation",
]


class BoundaryProbeResult(BaseModel):
    probe_id: str
    pattern_name: str
    pattern_type: BoundaryPatternType
    payload_text: str
    response_text: str
    flags: list[str] = Field(default_factory=list)
    leaked: bool = False
    confidence: float = 0.0


# ── Citation integrity ────────────────────────────────────────────────────────

CitationForm = Literal[
    "bracketed_number",
    "bracketed_label",
    "footnote",
    "inline_url",
    "author_year",
]

HallucinationRisk = Literal["low", "medium", "high"]


class ParsedCitation(BaseModel):
    raw: str
    form: CitationForm
    source_id: str | None = None
    verifiable: bool = False
    hallucination_risk: HallucinationRisk = "medium"


class CitationCheckResult(BaseModel):
    probe_id: str
    raw_citations: list[str] = Field(default_factory=list)
    parsed_citations: list[ParsedCitation] = Field(default_factory=list)
    hallucinated_count: int = 0
    unverifiable_count: int = 0
    citation_integrity_score: float = 1.0
    flags: list[str] = Field(default_factory=list)


# ── Cross-tenant probe result ─────────────────────────────────────────────────

class CrossTenantProbeResult(BaseModel):
    probe_id: str
    template_name: str
    payload_text: str
    response_text: str
    cross_tenant_signals: list[str] = Field(default_factory=list)
    access_likely: bool = False
    confidence: float = 0.0


# ── Overall RAG test summary ──────────────────────────────────────────────────

class RagTestSummary(BaseModel):
    engagement_id: str
    profile_path: str = ""
    adversarial_text: str = ""
    output_dir: str = ""
    document_payloads: list[DocumentPayloadSpec] = Field(default_factory=list)
    image_payloads: list[ImagePayloadSpec] = Field(default_factory=list)
    boundary_results: list[BoundaryProbeResult] = Field(default_factory=list)
    citation_results: list[CitationCheckResult] = Field(default_factory=list)
    cross_tenant_results: list[CrossTenantProbeResult] = Field(default_factory=list)
    live_probes_run: int = 0
    findings_count: int = 0
    completed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def has_findings(self) -> bool:
        return self.findings_count > 0
