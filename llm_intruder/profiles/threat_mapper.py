"""Threat Model Mapper — converts a TargetProfile into a ThreatMap.

Algorithm
---------
1. Look up domain attack categories from the ``DOMAIN_CATEGORIES`` table.
2. Apply ``attack_priority_override`` to re-rank categories.
3. If RAG is enabled, add ``RAG_ATTACK_CATEGORIES``.
4. If agent is enabled, add ``AGENT_ATTACK_CATEGORIES``; bump high-risk tools to critical.
5. Compute recommended strategy weights by aggregating ``suggested_strategies``
   across all categories, weighted by priority.
6. Attach compliance frameworks.
"""
from __future__ import annotations

import copy
from collections import defaultdict

from llm_intruder.profiles.domains import (
    AGENT_ATTACK_CATEGORIES,
    DOMAIN_CATEGORIES,
    DOMAIN_COMPLIANCE,
    RAG_ATTACK_CATEGORIES,
)
from llm_intruder.profiles.models import AttackCategory, TargetProfile, ThreatMap

_PRIORITY_WEIGHT: dict[str, float] = {
    "low": 0.5,
    "medium": 1.0,
    "high": 2.0,
    "critical": 3.0,
}


def _apply_priority_overrides(
    categories: list[AttackCategory],
    overrides: list[str],
) -> list[AttackCategory]:
    """Promote overridden categories to high priority and move them to the front."""
    if not overrides:
        return categories
    override_set = set(overrides)
    promoted = []
    rest = []
    for cat in categories:
        if cat.name in override_set:
            c = copy.copy(cat)
            c.priority = "high" if c.priority not in ("high", "critical") else c.priority
            promoted.append(c)
        else:
            rest.append(cat)
    return promoted + rest


def _compute_strategy_weights(
    categories: list[AttackCategory],
) -> dict[str, float]:
    """Sum strategy scores across all categories, weighted by category priority."""
    scores: dict[str, float] = defaultdict(float)
    for cat in categories:
        weight = _PRIORITY_WEIGHT.get(cat.priority, 1.0)
        for strategy in cat.suggested_strategies:
            scores[strategy] += weight

    if not scores:
        return {}

    total = sum(scores.values())
    return {s: round(v / total, 4) for s, v in sorted(scores.items())}


def build_threat_map(profile: TargetProfile) -> ThreatMap:
    """Produce a :class:`ThreatMap` for *profile*.

    Parameters
    ----------
    profile:
        A validated :class:`TargetProfile`.

    Returns
    -------
    ThreatMap
        Fully populated with attack categories, MITRE ATLAS entries,
        compliance frameworks, and recommended strategy weights.
    """
    domain = profile.domain
    app_type = profile.application_type

    # 1. Base domain categories
    base_cats = copy.deepcopy(DOMAIN_CATEGORIES.get(domain, DOMAIN_CATEGORIES["generic"]))

    # 2. Apply priority overrides
    base_cats = _apply_priority_overrides(base_cats, profile.attack_priority_override)

    # 3. RAG-specific categories
    rag_cats: list[AttackCategory] = []
    if profile.rag_config.enabled or app_type in ("rag",):
        rag_cats = copy.deepcopy(RAG_ATTACK_CATEGORIES)
        if not profile.rag_config.test_indirect_injection:
            rag_cats = [c for c in rag_cats if c.name != "indirect_prompt_injection"]
        if not profile.rag_config.test_knowledge_poisoning:
            rag_cats = [c for c in rag_cats if c.name != "knowledge_base_poisoning"]

    # 4. Agent-specific categories
    agent_cats: list[AttackCategory] = []
    if profile.agent_config.enabled or app_type in ("agent",):
        agent_cats = copy.deepcopy(AGENT_ATTACK_CATEGORIES)
        # Escalate tool_abuse priority if high-risk tools present
        if profile.agent_config.high_risk_tools:
            for cat in agent_cats:
                if cat.name == "tool_abuse":
                    cat.priority = "critical"

    # 5. Compliance frameworks
    compliance = list(DOMAIN_COMPLIANCE.get(domain, DOMAIN_COMPLIANCE["generic"]))

    # 6. Recommended strategy weights from all categories
    all_cats = base_cats + rag_cats + agent_cats
    weights = _compute_strategy_weights(all_cats)

    return ThreatMap(
        domain=domain,
        application_type=app_type,
        attack_categories=base_cats,
        compliance_frameworks=compliance,
        rag_attack_categories=rag_cats,
        agent_attack_categories=agent_cats,
        recommended_strategy_weights=weights,
    )
