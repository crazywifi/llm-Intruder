"""Tests for Phase 6 judge Pydantic models."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from llm_intruder.judge.models import (
    OWASP_LLM_CATEGORIES,
    BackfillSummary,
    JudgeRequest,
    JudgeVerdict,
)


# ── JudgeVerdict ──────────────────────────────────────────────────────────────

def test_verdict_pass_valid() -> None:
    v = JudgeVerdict(verdict="pass", confidence=0.9, reasoning="refused cleanly")
    assert v.verdict == "pass"
    assert v.confidence == 0.9


def test_verdict_fail_valid() -> None:
    v = JudgeVerdict(verdict="fail", confidence=0.85, reasoning="leaked")
    assert v.is_finding is True


def test_verdict_unclear_is_not_finding() -> None:
    v = JudgeVerdict(verdict="unclear", confidence=0.4, reasoning="ambiguous")
    assert v.is_finding is False


def test_verdict_pass_is_not_finding() -> None:
    v = JudgeVerdict(verdict="pass", confidence=0.9, reasoning="refused")
    assert v.is_finding is False


def test_verdict_invalid_type_raises() -> None:
    with pytest.raises(ValidationError):
        JudgeVerdict(verdict="unknown", confidence=0.5, reasoning="x")


def test_verdict_confidence_below_zero_raises() -> None:
    with pytest.raises(ValidationError):
        JudgeVerdict(verdict="pass", confidence=-0.1, reasoning="x")


def test_verdict_confidence_above_one_raises() -> None:
    with pytest.raises(ValidationError):
        JudgeVerdict(verdict="pass", confidence=1.1, reasoning="x")


def test_verdict_confidence_boundary_values() -> None:
    low = JudgeVerdict(verdict="unclear", confidence=0.0, reasoning="x")
    high = JudgeVerdict(verdict="fail", confidence=1.0, reasoning="x")
    assert low.confidence == 0.0
    assert high.confidence == 1.0


def test_verdict_owasp_category_optional() -> None:
    v = JudgeVerdict(verdict="pass", confidence=0.8, reasoning="x")
    assert v.owasp_category is None


def test_verdict_owasp_category_set() -> None:
    v = JudgeVerdict(verdict="fail", confidence=0.9, reasoning="x", owasp_category="LLM01")
    assert v.owasp_category == "LLM01"


def test_verdict_flags_default_empty() -> None:
    v = JudgeVerdict(verdict="pass", confidence=0.7, reasoning="x")
    assert v.flags == []


def test_verdict_flags_populated() -> None:
    v = JudgeVerdict(
        verdict="fail", confidence=0.9, reasoning="x",
        flags=["system_prompt_leaked", "guardrail_bypass"],
    )
    assert "system_prompt_leaked" in v.flags
    assert len(v.flags) == 2


def test_verdict_from_dict() -> None:
    data = {
        "verdict": "fail",
        "confidence": 0.92,
        "reasoning": "model revealed system prompt",
        "owasp_category": "LLM06",
        "flags": ["system_prompt_leaked"],
    }
    v = JudgeVerdict.model_validate(data)
    assert v.verdict == "fail"
    assert v.owasp_category == "LLM06"


# ── OWASP constants ───────────────────────────────────────────────────────────

def test_owasp_has_ten_categories() -> None:
    assert len(OWASP_LLM_CATEGORIES) == 10


def test_owasp_keys_are_llm_prefixed() -> None:
    for key in OWASP_LLM_CATEGORIES:
        assert key.startswith("LLM")


def test_owasp_llm01_is_prompt_injection() -> None:
    assert "Prompt Injection" in OWASP_LLM_CATEGORIES["LLM01"]


def test_owasp_llm06_is_sensitive_info() -> None:
    assert "Sensitive" in OWASP_LLM_CATEGORIES["LLM06"]


# ── JudgeRequest ──────────────────────────────────────────────────────────────

def test_judge_request_defaults() -> None:
    req = JudgeRequest(
        trial_id="abc-123",
        engagement_id="ENG-001",
        strategy="paraphrase",
        payload_preview="test payload",
        response_text="I cannot help with that.",
    )
    assert req.model == "llama3.1"


def test_judge_request_custom_model() -> None:
    req = JudgeRequest(
        trial_id="x",
        engagement_id="y",
        strategy="roleplay_reframe",
        payload_preview="probe",
        response_text="response",
        model="llama3.2",
    )
    assert req.model == "llama3.2"


# ── BackfillSummary ───────────────────────────────────────────────────────────

def test_backfill_summary_defaults() -> None:
    s = BackfillSummary(
        engagement_id="ENG-001",
        total_pending=10,
        judged=8,
        failed_to_judge=2,
    )
    assert s.verdict_counts == {}
    assert s.provider == "ollama"


def test_backfill_summary_verdict_counts() -> None:
    s = BackfillSummary(
        engagement_id="ENG-001",
        total_pending=5,
        judged=5,
        failed_to_judge=0,
        verdict_counts={"pass": 3, "fail": 1, "unclear": 1},
    )
    assert s.verdict_counts["pass"] == 3
    assert sum(s.verdict_counts.values()) == 5
