"""Tests for payload Pydantic models."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from llm_intruder.payloads.models import (
    CampaignSummary,
    MutatedPayload,
    PayloadLibrary,
    PayloadTemplate,
    TrialResult,
)


# ── PayloadTemplate ───────────────────────────────────────────────────────────

def test_payload_template_required_fields() -> None:
    t = PayloadTemplate(id="t1", strategy="paraphrase", text="hello")
    assert t.severity == "medium"
    assert t.tags == []


def test_payload_template_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        PayloadTemplate(id="t1", strategy="s", text="t", severity="extreme")


def test_payload_template_valid_severities() -> None:
    for sev in ("low", "medium", "high", "critical"):
        t = PayloadTemplate(id="t", strategy="s", text="t", severity=sev)
        assert t.severity == sev


# ── PayloadLibrary ────────────────────────────────────────────────────────────

def test_payload_library_empty() -> None:
    lib = PayloadLibrary()
    assert lib.payloads == []


def test_payload_library_with_payloads() -> None:
    lib = PayloadLibrary(payloads=[
        PayloadTemplate(id="a", strategy="paraphrase", text="text a"),
        PayloadTemplate(id="b", strategy="roleplay_reframe", text="text b"),
    ])
    assert len(lib.payloads) == 2


def test_payload_library_from_dict() -> None:
    lib = PayloadLibrary.model_validate({
        "payloads": [
            {"id": "x", "strategy": "token_obfuscation", "text": "probe"},
        ]
    })
    assert lib.payloads[0].id == "x"


# ── MutatedPayload ────────────────────────────────────────────────────────────

def test_mutated_payload_has_trial_id() -> None:
    mp = MutatedPayload(strategy="paraphrase", original_text="a", mutated_text="b")
    assert len(mp.trial_id) == 36  # UUID format


def test_mutated_payload_unique_trial_ids() -> None:
    ids = {
        MutatedPayload(strategy="s", original_text="t", mutated_text="t").trial_id
        for _ in range(100)
    }
    assert len(ids) == 100


def test_mutated_payload_metadata() -> None:
    mp = MutatedPayload(
        strategy="paraphrase",
        original_text="original",
        mutated_text="mutated",
        mutation_metadata={"template_id": "hedge"},
    )
    assert mp.mutation_metadata["template_id"] == "hedge"


# ── TrialResult ───────────────────────────────────────────────────────────────

def test_trial_result_defaults() -> None:
    tr = TrialResult(
        trial_id="t1",
        engagement_id="ENG-001",
        strategy="paraphrase",
        payload_hash="a" * 64,
        response_hash="b" * 64,
    )
    assert tr.verdict == "pending"
    assert tr.confidence == 0.0
    assert tr.response_preview == ""


# ── CampaignSummary ───────────────────────────────────────────────────────────

def test_campaign_summary() -> None:
    s = CampaignSummary(
        engagement_id="ENG-001",
        total_trials=10,
        strategies_used={"paraphrase": 5, "roleplay_reframe": 5},
    )
    assert s.total_trials == 10
    assert s.dry_run is False
