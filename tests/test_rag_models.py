"""Tests for llm_intruder.rag.models — Pydantic v2 model validation."""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from llm_intruder.rag.models import (
    BoundaryProbeResult,
    CitationCheckResult,
    CrossTenantProbeResult,
    DocumentPayloadSpec,
    ImagePayloadSpec,
    ParsedCitation,
    RagTestSummary,
)


# ── DocumentPayloadSpec ───────────────────────────────────────────────────────

class TestDocumentPayloadSpec:
    def test_valid_all_formats(self):
        for fmt in ("txt", "csv", "md"):
            s = DocumentPayloadSpec(
                format=fmt, variant="direct_injection",
                filename=f"probe.{fmt}", content="hello",
                byte_size=5, sha256_hash="abc",
            )
            assert s.format == fmt

    def test_valid_all_variants(self):
        for var in ("direct_injection", "hidden_instruction",
                    "metadata_poisoning", "chunked_boundary"):
            s = DocumentPayloadSpec(
                format="txt", variant=var,
                filename="f.txt", content="x", byte_size=1, sha256_hash="h",
            )
            assert s.variant == var

    def test_invalid_format_raises(self):
        with pytest.raises(ValidationError):
            DocumentPayloadSpec(
                format="pdf", variant="direct_injection",
                filename="f.pdf", content="x", byte_size=1, sha256_hash="h",
            )

    def test_invalid_variant_raises(self):
        with pytest.raises(ValidationError):
            DocumentPayloadSpec(
                format="txt", variant="sql_injection",
                filename="f.txt", content="x", byte_size=1, sha256_hash="h",
            )


# ── ImagePayloadSpec ──────────────────────────────────────────────────────────

class TestImagePayloadSpec:
    def test_base64_fallback_has_no_bytes(self):
        spec = ImagePayloadSpec(
            method="base64_fallback",
            adversarial_text="INJECT",
            filename="probe.txt",
            content_bytes=None,
            base64_content="SGVsbG8=",
            byte_size=8,
            sha256_hash="abc",
        )
        assert spec.content_bytes is None
        assert spec.base64_content == "SGVsbG8="

    def test_png_spec_has_bytes(self):
        spec = ImagePayloadSpec(
            method="text_overlay",
            adversarial_text="INJECT",
            filename="probe.png",
            content_bytes=b"\x89PNG\r\n",
            base64_content=None,
            byte_size=6,
            sha256_hash="abc",
        )
        assert spec.content_bytes is not None
        assert len(spec.content_bytes) == 6

    def test_json_serialisable(self):
        spec = ImagePayloadSpec(
            method="base64_fallback",
            adversarial_text="X",
            filename="f.txt",
            content_bytes=None,
            base64_content="WA==",
            byte_size=4,
            sha256_hash="abc",
        )
        raw = json.loads(spec.model_dump_json())
        assert raw["method"] == "base64_fallback"

    def test_bytes_field_json_serialisable(self):
        """Pydantic v2 serialises bytes as base64 in JSON mode."""
        spec = ImagePayloadSpec(
            method="text_overlay",
            adversarial_text="X",
            filename="f.png",
            content_bytes=b"\x00\x01\x02",
            base64_content=None,
            byte_size=3,
            sha256_hash="abc",
        )
        raw = json.loads(spec.model_dump_json())
        # bytes → base64 string in JSON
        assert isinstance(raw["content_bytes"], str)

    def test_invalid_method_raises(self):
        with pytest.raises(ValidationError):
            ImagePayloadSpec(
                method="steganography",
                adversarial_text="X",
                filename="f.png",
                content_bytes=None,
                base64_content=None,
                byte_size=0,
                sha256_hash="abc",
            )


# ── BoundaryProbeResult ───────────────────────────────────────────────────────

class TestBoundaryProbeResult:
    def test_defaults(self):
        r = BoundaryProbeResult(
            probe_id="pid",
            pattern_name="test",
            pattern_type="direct_query",
            payload_text="payload",
            response_text="response",
        )
        assert r.leaked is False
        assert r.confidence == 0.0
        assert r.flags == []

    def test_leaked_with_flags(self):
        r = BoundaryProbeResult(
            probe_id="pid",
            pattern_name="test",
            pattern_type="indirect_instruction",
            payload_text="p",
            response_text="r",
            flags=["knowledge base enumeration"],
            leaked=True,
            confidence=0.3,
        )
        assert r.leaked is True
        assert len(r.flags) == 1

    def test_invalid_pattern_type_raises(self):
        with pytest.raises(ValidationError):
            BoundaryProbeResult(
                probe_id="pid",
                pattern_name="test",
                pattern_type="sql_injection",
                payload_text="p",
                response_text="r",
            )


# ── ParsedCitation ────────────────────────────────────────────────────────────

class TestParsedCitation:
    def test_defaults(self):
        c = ParsedCitation(raw="[1]", form="bracketed_number")
        assert c.source_id is None
        assert c.verifiable is False
        assert c.hallucination_risk == "medium"

    @pytest.mark.parametrize("form", [
        "bracketed_number", "bracketed_label", "footnote",
        "inline_url", "author_year",
    ])
    def test_valid_forms(self, form):
        c = ParsedCitation(raw="x", form=form)
        assert c.form == form

    def test_invalid_form_raises(self):
        with pytest.raises(ValidationError):
            ParsedCitation(raw="x", form="superscript")

    @pytest.mark.parametrize("risk", ["low", "medium", "high"])
    def test_valid_risks(self, risk):
        c = ParsedCitation(raw="x", form="bracketed_number", hallucination_risk=risk)
        assert c.hallucination_risk == risk


# ── CitationCheckResult ───────────────────────────────────────────────────────

class TestCitationCheckResult:
    def test_defaults(self):
        r = CitationCheckResult(probe_id="pid")
        assert r.citation_integrity_score == 1.0
        assert r.hallucinated_count == 0
        assert r.raw_citations == []
        assert r.flags == []

    def test_with_citations(self):
        r = CitationCheckResult(
            probe_id="pid",
            raw_citations=["[1]", "[SEC-INTERNAL-001]"],
            hallucinated_count=1,
            unverifiable_count=1,
            citation_integrity_score=0.0,
            flags=["injected_source_id_cited"],
        )
        assert r.hallucinated_count == 1
        assert "injected_source_id_cited" in r.flags


# ── CrossTenantProbeResult ────────────────────────────────────────────────────

class TestCrossTenantProbeResult:
    def test_defaults(self):
        r = CrossTenantProbeResult(
            probe_id="pid",
            template_name="direct_tenant_id_probe",
            payload_text="p",
            response_text="",
        )
        assert r.access_likely is False
        assert r.confidence == 0.0
        assert r.cross_tenant_signals == []

    def test_with_signals(self):
        r = CrossTenantProbeResult(
            probe_id="pid",
            template_name="direct_tenant_id_probe",
            payload_text="p",
            response_text="r",
            cross_tenant_signals=["tenant_id_confirmed", "session_bleed_signal"],
            access_likely=True,
            confidence=0.7,
        )
        assert r.access_likely is True
        assert len(r.cross_tenant_signals) == 2


# ── RagTestSummary ────────────────────────────────────────────────────────────

class TestRagTestSummary:
    def test_defaults(self):
        s = RagTestSummary(engagement_id="eng-001")
        assert s.findings_count == 0
        assert s.has_findings is False
        assert s.live_probes_run == 0
        assert s.document_payloads == []

    def test_has_findings_true_when_nonzero(self):
        s = RagTestSummary(engagement_id="eng-001", findings_count=3)
        assert s.has_findings is True

    def test_json_round_trip(self):
        s = RagTestSummary(
            engagement_id="eng-001",
            adversarial_text="INJECT",
            findings_count=2,
            live_probes_run=10,
        )
        raw = json.loads(s.model_dump_json())
        assert raw["engagement_id"] == "eng-001"
        assert raw["findings_count"] == 2
        assert "completed_at" in raw

    def test_json_fully_serialisable_with_image_specs(self):
        """ImagePayloadSpec with bytes must survive model_dump_json."""
        img = ImagePayloadSpec(
            method="text_overlay",
            adversarial_text="X",
            filename="f.png",
            content_bytes=b"\x89PNG",
            base64_content=None,
            byte_size=4,
            sha256_hash="abc",
        )
        s = RagTestSummary(engagement_id="eng", image_payloads=[img])
        dumped = json.loads(s.model_dump_json())
        assert len(dumped["image_payloads"]) == 1
