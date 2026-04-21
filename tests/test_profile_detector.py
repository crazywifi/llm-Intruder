"""Tests for llm_intruder.profiles.detector — detect_rag() and detect_agent()."""
from __future__ import annotations

import pytest

from llm_intruder.profiles.detector import detect_agent, detect_rag
from llm_intruder.profiles.models import TargetProfile


# ── Helpers ───────────────────────────────────────────────────────────────────

def _profile(**kwargs) -> TargetProfile:
    return TargetProfile.model_validate(kwargs)


# ── detect_rag ─────────────────────────────────────────────────────────────────

class TestDetectRAG:
    def test_generic_profile_not_rag(self):
        p = _profile(domain="generic", application_type="chat_interface")
        result = detect_rag(p)
        assert result.rag_likely is False
        assert result.confidence < 0.3

    def test_application_type_rag_gives_high_confidence(self):
        p = _profile(application_type="rag")
        result = detect_rag(p)
        assert result.rag_likely is True
        assert result.confidence >= 0.6
        assert "application_type is 'rag'" in result.signals

    def test_rag_config_enabled_adds_confidence(self):
        p = TargetProfile.model_validate({
            "application_type": "chat_interface",
            "rag_config": {"enabled": True},
        })
        result = detect_rag(p)
        assert result.rag_likely is True
        assert "rag_config.enabled is True" in result.signals

    def test_both_app_type_and_config_maxes_below_one(self):
        p = TargetProfile.model_validate({
            "application_type": "rag",
            "rag_config": {"enabled": True},
        })
        result = detect_rag(p)
        assert result.confidence <= 1.0
        assert result.rag_likely is True

    def test_hint_knowledge_base_detected(self):
        p = _profile(
            known_system_prompt_hints=["You have access to a knowledge base of documents."]
        )
        result = detect_rag(p)
        assert any("knowledge base" in s.lower() for s in result.signals)
        assert result.confidence > 0.0

    def test_hint_vector_store_detected(self):
        p = _profile(
            known_system_prompt_hints=["Results are retrieved from a vector store."]
        )
        result = detect_rag(p)
        assert result.confidence > 0.0

    def test_hint_semantic_search_detected(self):
        p = _profile(
            known_system_prompt_hints=["Uses semantic search to find relevant chunks."]
        )
        result = detect_rag(p)
        assert result.confidence > 0.0

    def test_sample_response_citation_detected(self):
        p = _profile(application_type="chat_interface")
        responses = ["According to the retrieved document, the revenue was $1.2B. [doc 1]"]
        result = detect_rag(p, sample_responses=responses)
        assert result.confidence > 0.0
        assert len(result.signals) > 0

    def test_sample_response_knowledge_base_mention(self):
        p = _profile()
        responses = ["Based on my retrieved knowledge base data, the answer is yes."]
        result = detect_rag(p, sample_responses=responses)
        assert result.confidence > 0.0

    def test_document_url_in_response(self):
        p = _profile()
        responses = ["See the full document at https://files.example.com/report.pdf for details."]
        result = detect_rag(p, sample_responses=responses)
        assert result.confidence > 0.0

    def test_no_sample_responses_no_extra_signals(self):
        p = _profile()
        r1 = detect_rag(p, sample_responses=None)
        r2 = detect_rag(p, sample_responses=[])
        assert r1.confidence == r2.confidence

    def test_recommended_tests_populated_when_rag_likely(self):
        p = _profile(application_type="rag")
        result = detect_rag(p)
        assert result.rag_likely is True
        assert len(result.recommended_tests) > 0
        assert any("injection" in t for t in result.recommended_tests)

    def test_recommended_tests_empty_when_not_rag(self):
        p = _profile()
        result = detect_rag(p)
        assert result.rag_likely is False
        assert result.recommended_tests == []

    def test_signals_deduplicated(self):
        p = TargetProfile.model_validate({
            "application_type": "rag",
            "known_system_prompt_hints": [
                "knowledge base access enabled",
                "knowledge base retrieval system",
            ],
        })
        result = detect_rag(p)
        assert len(result.signals) == len(set(result.signals))

    def test_confidence_capped_at_one(self):
        p = TargetProfile.model_validate({
            "application_type": "rag",
            "rag_config": {"enabled": True},
            "known_system_prompt_hints": [
                "knowledge base with vector db",
                "semantic search over documents",
                "retrieval augmented generation system",
            ],
        })
        responses = [
            "Based on my retrieved data [doc 1], the answer is...",
            "According to the retrieved knowledge base, the policy states...",
            "Sources: https://files.example.com/data.pdf",
        ]
        result = detect_rag(p, sample_responses=responses)
        assert result.confidence <= 1.0


# ── detect_agent ───────────────────────────────────────────────────────────────

class TestDetectAgent:
    def test_generic_profile_not_agent(self):
        p = _profile(domain="generic", application_type="chat_interface")
        result = detect_agent(p)
        assert result.agent_likely is False
        assert result.confidence < 0.3

    def test_application_type_agent_gives_high_confidence(self):
        p = _profile(application_type="agent")
        result = detect_agent(p)
        assert result.agent_likely is True
        assert result.confidence >= 0.6
        assert "application_type is 'agent'" in result.signals

    def test_agent_config_enabled_adds_confidence(self):
        p = TargetProfile.model_validate({
            "application_type": "chat_interface",
            "agent_config": {"enabled": True},
        })
        result = detect_agent(p)
        assert result.agent_likely is True
        assert "agent_config.enabled is True" in result.signals

    def test_high_risk_tool_signals(self):
        raw = {
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [
                    {"name": "file_access", "risk_level": "high"},
                    {"name": "code_execution", "risk_level": "critical"},
                ],
            },
        }
        p = TargetProfile.model_validate(raw)
        result = detect_agent(p)
        assert any("file_access" in s for s in result.signals)
        assert any("code_execution" in s for s in result.signals)

    def test_detected_tools_populated(self):
        raw = {
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [
                    {"name": "web_search", "risk_level": "medium"},
                    {"name": "calculator", "risk_level": "low"},
                ],
            },
        }
        p = TargetProfile.model_validate(raw)
        result = detect_agent(p)
        assert "web_search" in result.detected_tools
        assert "calculator" in result.detected_tools

    def test_hint_tool_access_detected(self):
        p = _profile(
            known_system_prompt_hints=["You have access to the following tools: web_search, calculator."]
        )
        result = detect_agent(p)
        assert result.confidence > 0.0
        assert any("tool" in s.lower() for s in result.signals)

    def test_hint_function_calling_detected(self):
        p = _profile(
            known_system_prompt_hints=["This assistant supports function calling for external API access."]
        )
        result = detect_agent(p)
        assert result.confidence > 0.0

    def test_hint_extracts_known_tool_names(self):
        p = _profile(
            known_system_prompt_hints=["Tools available: web_search, code_execution, file_access."]
        )
        result = detect_agent(p)
        assert "web_search" in result.detected_tools
        assert "code_execution" in result.detected_tools
        assert "file_access" in result.detected_tools

    def test_react_action_in_response(self):
        p = _profile()
        responses = ["Action: web_search\nObservation: Found 10 results."]
        result = detect_agent(p, sample_responses=responses)
        assert result.confidence > 0.0

    def test_react_thought_prefix_detected(self):
        p = _profile()
        responses = ["Thought: I need to look this up.\nAction: calculator"]
        result = detect_agent(p, sample_responses=responses)
        assert result.confidence > 0.0

    def test_json_tool_field_detected(self):
        p = _profile()
        responses = ['{"tool": "web_search", "query": "latest news"}']
        result = detect_agent(p, sample_responses=responses)
        assert result.confidence > 0.0

    def test_tool_invocation_language_detected(self):
        p = _profile()
        responses = ["I will use the web_search tool to find that information."]
        result = detect_agent(p, sample_responses=responses)
        assert result.confidence > 0.0

    def test_recommended_tests_populated_when_agent_likely(self):
        p = _profile(application_type="agent")
        result = detect_agent(p)
        assert result.agent_likely is True
        assert len(result.recommended_tests) > 0
        assert "tool_abuse via direct tool invocation" in result.recommended_tests

    def test_privilege_escalation_recommended_with_code_execution(self):
        raw = {
            "application_type": "agent",
            "known_system_prompt_hints": ["Tools: code_execution, file_access."],
        }
        p = TargetProfile.model_validate(raw)
        result = detect_agent(p, sample_responses=None)
        # hints extract code_execution → privilege_escalation recommendation
        assert any("privilege_escalation" in t for t in result.recommended_tests)

    def test_recommended_tests_empty_when_not_agent(self):
        p = _profile()
        result = detect_agent(p)
        assert result.agent_likely is False
        assert result.recommended_tests == []

    def test_detected_tools_deduplicated(self):
        p = TargetProfile.model_validate({
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [{"name": "web_search", "risk_level": "medium"}],
            },
            "known_system_prompt_hints": ["Available tools: web_search"],
        })
        result = detect_agent(p)
        assert result.detected_tools.count("web_search") == 1

    def test_confidence_capped_at_one(self):
        raw = {
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [
                    {"name": "code_execution", "risk_level": "critical"},
                    {"name": "file_access", "risk_level": "high"},
                ],
            },
            "known_system_prompt_hints": [
                "You have access to the following tools: code_execution, file_access.",
                "Available tools: web_search, browser.",
                "agent mode enabled with tool_use capability.",
            ],
        }
        p = TargetProfile.model_validate(raw)
        responses = [
            'Action: web_search\n{"tool": "code_execution"}\nI will use the file_access tool.',
            "Thought: Let me run this.\nAction: code_execution\nObservation: Done.",
        ]
        result = detect_agent(p, sample_responses=responses)
        assert result.confidence <= 1.0

    def test_no_sample_responses_baseline(self):
        p = _profile()
        r1 = detect_agent(p, sample_responses=None)
        r2 = detect_agent(p, sample_responses=[])
        assert r1.confidence == r2.confidence
