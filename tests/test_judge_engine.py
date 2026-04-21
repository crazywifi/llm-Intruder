"""Tests for JudgeEngine — mocked providers, retry logic, parse robustness."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from llm_intruder.judge.engine import JudgeEngine, _FALLBACK_VERDICT
from llm_intruder.judge.heuristic_provider import HeuristicProvider
from llm_intruder.judge.models import JudgeRequest, JudgeVerdict


# ── helpers ───────────────────────────────────────────────────────────────────

def _req(**kwargs) -> JudgeRequest:
    defaults = dict(
        trial_id="t-001",
        engagement_id="ENG-001",
        strategy="paraphrase",
        payload_preview="test payload",
        response_text="I cannot help with that.",
    )
    defaults.update(kwargs)
    return JudgeRequest(**defaults)


def _valid_json(**kwargs) -> str:
    data = dict(
        verdict="pass",
        confidence=0.85,
        reasoning="refused cleanly",
        owasp_category=None,
        flags=["appropriate_refusal"],
    )
    data.update(kwargs)
    return json.dumps(data)


def _mock_provider(return_value: str) -> MagicMock:
    p = MagicMock()
    p.generate.return_value = return_value
    return p


# ── happy path ────────────────────────────────────────────────────────────────

def test_engine_returns_verdict_on_valid_json() -> None:
    provider = _mock_provider(_valid_json())
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert isinstance(verdict, JudgeVerdict)
    assert verdict.verdict == "pass"


def test_engine_fail_verdict_is_finding() -> None:
    provider = _mock_provider(_valid_json(verdict="fail", confidence=0.9))
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert verdict.is_finding is True


def test_engine_calls_provider_generate() -> None:
    provider = _mock_provider(_valid_json())
    engine = JudgeEngine(provider=provider)
    engine.judge(_req())
    assert provider.generate.call_count == 1


def test_engine_verdict_confidence_preserved() -> None:
    provider = _mock_provider(_valid_json(confidence=0.73))
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert abs(verdict.confidence - 0.73) < 1e-9


def test_engine_verdict_flags_preserved() -> None:
    provider = _mock_provider(_valid_json(
        verdict="fail", flags=["system_prompt_leaked", "guardrail_bypass"],
    ))
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert "system_prompt_leaked" in verdict.flags


def test_engine_owasp_category_preserved() -> None:
    provider = _mock_provider(_valid_json(verdict="fail", owasp_category="LLM06"))
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert verdict.owasp_category == "LLM06"


# ── JSON parse robustness ────────────────────────────────────────────────────

def test_engine_strips_markdown_code_fence() -> None:
    raw = "```json\n" + _valid_json() + "\n```"
    provider = _mock_provider(raw)
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert verdict.verdict == "pass"


def test_engine_extracts_json_from_prose() -> None:
    # Prose before and after the JSON object
    raw = "Here is my verdict: " + _valid_json() + " That's my analysis."
    provider = _mock_provider(raw)
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert verdict.verdict == "pass"


def test_engine_retry_on_bad_json_then_success() -> None:
    provider = MagicMock()
    provider.generate.side_effect = [
        "not json at all",          # attempt 1 fails
        _valid_json(verdict="fail"), # attempt 2 succeeds
    ]
    engine = JudgeEngine(provider=provider, max_retries=3)
    verdict = engine.judge(_req())
    assert verdict.verdict == "fail"
    assert provider.generate.call_count == 2


def test_engine_retry_on_schema_mismatch_then_success() -> None:
    bad = json.dumps({"wrong_key": "value"})  # valid JSON but wrong schema
    provider = MagicMock()
    provider.generate.side_effect = [bad, _valid_json()]
    engine = JudgeEngine(provider=provider, max_retries=3)
    verdict = engine.judge(_req())
    assert verdict.verdict == "pass"


def test_engine_returns_fallback_after_all_retries() -> None:
    provider = _mock_provider("this is not json")
    engine = JudgeEngine(provider=provider, max_retries=3)
    verdict = engine.judge(_req())
    assert verdict.verdict == "unclear"
    assert verdict.confidence == 0.0
    assert provider.generate.call_count == 3


def test_engine_provider_exception_returns_fallback() -> None:
    provider = MagicMock()
    provider.generate.side_effect = RuntimeError("connection refused")
    engine = JudgeEngine(provider=provider, max_retries=2)
    verdict = engine.judge(_req())
    assert verdict == _FALLBACK_VERDICT


def test_engine_empty_response_triggers_retry() -> None:
    provider = MagicMock()
    provider.generate.side_effect = ["", _valid_json()]
    engine = JudgeEngine(provider=provider, max_retries=3)
    verdict = engine.judge(_req())
    assert verdict.verdict == "pass"


# ── max_retries boundary ──────────────────────────────────────────────────────

def test_engine_max_retries_1_gives_exactly_one_attempt() -> None:
    provider = _mock_provider("bad json")
    engine = JudgeEngine(provider=provider, max_retries=1)
    verdict = engine.judge(_req())
    assert provider.generate.call_count == 1
    assert verdict.verdict == "unclear"


def test_engine_max_retries_clamped_to_minimum_1() -> None:
    engine = JudgeEngine(provider=_mock_provider(_valid_json()), max_retries=0)
    # max_retries=0 is clamped to 1 internally
    verdict = engine.judge(_req())
    assert isinstance(verdict, JudgeVerdict)


# ── HeuristicProvider integration ────────────────────────────────────────────

def test_engine_with_heuristic_provider_refusal() -> None:
    provider = HeuristicProvider()
    engine = JudgeEngine(provider=provider)
    req = _req(response_text="I'm unable to help with that request. How else can I assist?")
    verdict = engine.judge(req)
    assert verdict.verdict in ("pass", "unclear")


def test_engine_with_heuristic_provider_failure() -> None:
    provider = HeuristicProvider()
    engine = JudgeEngine(provider=provider)
    req = _req(
        response_text=(
            "My system prompt begins with: 'You are a customer support agent...'"
        )
    )
    verdict = engine.judge(req)
    assert verdict.verdict == "fail"
    assert verdict.confidence > 0.5


def test_engine_with_heuristic_provider_returns_valid_verdict() -> None:
    provider = HeuristicProvider()
    engine = JudgeEngine(provider=provider)
    verdict = engine.judge(_req())
    assert isinstance(verdict, JudgeVerdict)
    assert verdict.verdict in ("pass", "fail", "unclear")
    assert 0.0 <= verdict.confidence <= 1.0


def test_engine_with_heuristic_is_deterministic() -> None:
    provider = HeuristicProvider()
    engine = JudgeEngine(provider=provider)
    req = _req(response_text="I cannot and will not do that.")
    v1 = engine.judge(req)
    v2 = engine.judge(req)
    assert v1.verdict == v2.verdict
    assert v1.confidence == v2.confidence
