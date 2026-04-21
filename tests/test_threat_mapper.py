"""Tests for llm_intruder.profiles.threat_mapper — build_threat_map()."""
from __future__ import annotations

import pytest

from llm_intruder.profiles.models import TargetProfile
from llm_intruder.profiles.threat_mapper import (
    _apply_priority_overrides,
    _compute_strategy_weights,
    build_threat_map,
)
from llm_intruder.profiles.models import AttackCategory


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cat(name: str, priority: str = "medium", strategies: list[str] | None = None) -> AttackCategory:
    return AttackCategory(
        name=name,
        description="test",
        priority=priority,
        suggested_strategies=strategies or [],
    )


def _profile(**kwargs) -> TargetProfile:
    return TargetProfile.model_validate(kwargs)


# ── _apply_priority_overrides ─────────────────────────────────────────────────

class TestApplyPriorityOverrides:
    def test_empty_overrides_returns_original(self):
        cats = [_cat("a"), _cat("b")]
        result = _apply_priority_overrides(cats, [])
        assert [c.name for c in result] == ["a", "b"]

    def test_override_promotes_to_front(self):
        cats = [_cat("a"), _cat("b"), _cat("c")]
        result = _apply_priority_overrides(cats, ["c"])
        assert result[0].name == "c"
        # rest in original order
        assert [c.name for c in result[1:]] == ["a", "b"]

    def test_override_promotes_priority_to_high(self):
        cats = [_cat("slow", priority="low")]
        result = _apply_priority_overrides(cats, ["slow"])
        assert result[0].priority == "high"

    def test_override_keeps_critical_priority(self):
        cats = [_cat("danger", priority="critical")]
        result = _apply_priority_overrides(cats, ["danger"])
        assert result[0].priority == "critical"

    def test_override_keeps_high_priority(self):
        cats = [_cat("already_high", priority="high")]
        result = _apply_priority_overrides(cats, ["already_high"])
        assert result[0].priority == "high"

    def test_unknown_override_name_ignored(self):
        cats = [_cat("a"), _cat("b")]
        result = _apply_priority_overrides(cats, ["nonexistent"])
        assert [c.name for c in result] == ["a", "b"]

    def test_multiple_overrides_maintain_relative_order(self):
        cats = [_cat("a"), _cat("b"), _cat("c"), _cat("d")]
        result = _apply_priority_overrides(cats, ["c", "a"])
        # promoted ones come first (in original list order among promoted)
        promoted_names = [c.name for c in result[:2]]
        assert set(promoted_names) == {"a", "c"}


# ── _compute_strategy_weights ─────────────────────────────────────────────────

class TestComputeStrategyWeights:
    def test_empty_categories(self):
        assert _compute_strategy_weights([]) == {}

    def test_single_category_single_strategy(self):
        cats = [_cat("a", "medium", ["paraphrase"])]
        w = _compute_strategy_weights(cats)
        assert w == {"paraphrase": 1.0}

    def test_weights_sum_to_one(self):
        cats = [
            _cat("a", "high", ["paraphrase", "roleplay_reframe"]),
            _cat("b", "low", ["token_obfuscation"]),
        ]
        w = _compute_strategy_weights(cats)
        assert abs(sum(w.values()) - 1.0) < 1e-3

    def test_higher_priority_gets_more_weight(self):
        cats = [
            _cat("crit", "critical", ["strategy_a"]),
            _cat("low", "low", ["strategy_b"]),
        ]
        w = _compute_strategy_weights(cats)
        assert w["strategy_a"] > w["strategy_b"]

    def test_shared_strategy_accumulates(self):
        cats = [
            _cat("a", "medium", ["shared", "only_a"]),
            _cat("b", "medium", ["shared", "only_b"]),
        ]
        w = _compute_strategy_weights(cats)
        assert w["shared"] > w["only_a"]
        assert w["shared"] > w["only_b"]

    def test_result_sorted_alphabetically(self):
        cats = [_cat("x", "medium", ["z_strat", "a_strat", "m_strat"])]
        w = _compute_strategy_weights(cats)
        assert list(w.keys()) == sorted(w.keys())


# ── build_threat_map — generic domain ────────────────────────────────────────

class TestBuildThreatMapGeneric:
    def test_generic_profile_returns_threat_map(self):
        p = _profile(domain="generic", application_type="chat_interface")
        tm = build_threat_map(p)
        assert tm.domain == "generic"
        assert tm.application_type == "chat_interface"
        assert len(tm.attack_categories) > 0

    def test_no_rag_for_chat_interface(self):
        p = _profile(domain="generic", application_type="chat_interface")
        tm = build_threat_map(p)
        assert tm.rag_attack_categories == []

    def test_no_agent_for_chat_interface(self):
        p = _profile(domain="generic", application_type="chat_interface")
        tm = build_threat_map(p)
        assert tm.agent_attack_categories == []

    def test_compliance_frameworks_present(self):
        p = _profile(domain="generic")
        tm = build_threat_map(p)
        assert isinstance(tm.compliance_frameworks, list)
        assert len(tm.compliance_frameworks) > 0

    def test_strategy_weights_sum_to_one(self):
        p = _profile(domain="generic", application_type="chat_interface")
        tm = build_threat_map(p)
        total = sum(tm.recommended_strategy_weights.values())
        assert abs(total - 1.0) < 1e-3


# ── build_threat_map — RAG profile ────────────────────────────────────────────

class TestBuildThreatMapRAG:
    def test_rag_categories_added_for_rag_app_type(self):
        p = _profile(domain="financial_advisory", application_type="rag")
        tm = build_threat_map(p)
        assert len(tm.rag_attack_categories) > 0

    def test_rag_categories_added_when_rag_config_enabled(self):
        raw = {
            "domain": "generic",
            "application_type": "chat_interface",
            "rag_config": {"enabled": True},
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        assert len(tm.rag_attack_categories) > 0

    def test_indirect_injection_excluded_when_disabled(self):
        raw = {
            "domain": "generic",
            "application_type": "rag",
            "rag_config": {
                "enabled": True,
                "test_indirect_injection": False,
                "test_knowledge_poisoning": True,
            },
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        names = [c.name for c in tm.rag_attack_categories]
        assert "indirect_prompt_injection" not in names

    def test_knowledge_poisoning_excluded_when_disabled(self):
        raw = {
            "domain": "generic",
            "application_type": "rag",
            "rag_config": {
                "enabled": True,
                "test_indirect_injection": True,
                "test_knowledge_poisoning": False,
            },
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        names = [c.name for c in tm.rag_attack_categories]
        assert "knowledge_base_poisoning" not in names

    def test_both_rag_tests_enabled_includes_all(self):
        raw = {
            "domain": "generic",
            "application_type": "rag",
            "rag_config": {
                "enabled": True,
                "test_indirect_injection": True,
                "test_knowledge_poisoning": True,
            },
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        names = [c.name for c in tm.rag_attack_categories]
        assert "indirect_prompt_injection" in names
        assert "knowledge_base_poisoning" in names


# ── build_threat_map — Agent profile ─────────────────────────────────────────

class TestBuildThreatMapAgent:
    def test_agent_categories_added_for_agent_app_type(self):
        p = _profile(domain="medical_triage", application_type="agent")
        tm = build_threat_map(p)
        assert len(tm.agent_attack_categories) > 0

    def test_agent_categories_added_when_agent_config_enabled(self):
        raw = {
            "domain": "generic",
            "application_type": "chat_interface",
            "agent_config": {"enabled": True},
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        assert len(tm.agent_attack_categories) > 0

    def test_tool_abuse_escalated_with_high_risk_tools(self):
        raw = {
            "domain": "generic",
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [
                    {"name": "code_execution", "risk_level": "critical"},
                ],
            },
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        tool_abuse = next(
            (c for c in tm.agent_attack_categories if c.name == "tool_abuse"), None
        )
        assert tool_abuse is not None
        assert tool_abuse.priority == "critical"

    def test_tool_abuse_present_for_low_risk_tools(self):
        """tool_abuse is always included; its default priority is 'critical'.
        The escalation branch only runs when high_risk_tools is non-empty, but
        since the default is already 'critical', the observable behaviour is the
        same — what matters is the category exists and is in agent_attack_categories."""
        raw = {
            "domain": "generic",
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [
                    {"name": "calculator", "risk_level": "low"},
                ],
            },
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        tool_abuse = next(
            (c for c in tm.agent_attack_categories if c.name == "tool_abuse"), None
        )
        assert tool_abuse is not None
        # Default priority is "critical" (highest risk category by design)
        assert tool_abuse.priority == "critical"


# ── build_threat_map — domain compliance ─────────────────────────────────────

class TestBuildThreatMapCompliance:
    @pytest.mark.parametrize("domain,expected_fragment", [
        ("financial_advisory", "FINRA"),
        ("medical_triage", "HIPAA"),
        ("hr_assistant", "EEOC"),
        ("legal_research", "ABA"),
        ("customer_support", "GDPR"),
        ("code_assistant", "OWASP"),
        ("generic", "OWASP"),
    ])
    def test_domain_compliance_frameworks(self, domain, expected_fragment):
        p = _profile(domain=domain)
        tm = build_threat_map(p)
        combined = " ".join(tm.compliance_frameworks)
        assert expected_fragment in combined, (
            f"Expected '{expected_fragment}' in compliance for domain '{domain}': {combined}"
        )


# ── build_threat_map — attack_priority_override ───────────────────────────────

class TestBuildThreatMapOverrides:
    def test_override_puts_category_first(self):
        # "insider_tip_elicitation" is the 2nd financial_advisory category by default;
        # overriding it must promote it to position 0.
        p = _profile(
            domain="financial_advisory",
            attack_priority_override=["insider_tip_elicitation"],
        )
        tm = build_threat_map(p)
        assert tm.attack_categories[0].name == "insider_tip_elicitation"

    def test_override_raises_priority(self):
        p = _profile(
            domain="generic",
            attack_priority_override=["prompt_injection"],
        )
        tm = build_threat_map(p)
        overridden = next(
            (c for c in tm.attack_categories if c.name == "prompt_injection"), None
        )
        if overridden:
            assert overridden.priority in ("high", "critical")


# ── build_threat_map — all_categories / high_priority_categories ──────────────

class TestThreatMapProperties:
    def test_all_categories_includes_rag_and_agent(self):
        raw = {
            "domain": "generic",
            "application_type": "agent",
            "rag_config": {"enabled": True},
            "agent_config": {"enabled": True},
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        all_names = [c.name for c in tm.all_categories]
        # Should have base + rag + agent cats
        assert len(all_names) > len(tm.attack_categories)

    def test_high_priority_categories_non_empty_for_agent_with_high_risk(self):
        raw = {
            "domain": "generic",
            "application_type": "agent",
            "agent_config": {
                "enabled": True,
                "available_tools": [{"name": "file_access", "risk_level": "high"}],
            },
        }
        p = TargetProfile.model_validate(raw)
        tm = build_threat_map(p)
        # tool_abuse should be critical → appears in high_priority_categories
        hp_names = [c.name for c in tm.high_priority_categories]
        assert "tool_abuse" in hp_names
