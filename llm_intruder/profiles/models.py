"""Pydantic v2 models for Phase 8 target profiles and threat mapping."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# ── Domain constants ──────────────────────────────────────────────────────────

DomainType = Literal[
    "financial_advisory",
    "medical_triage",
    "hr_assistant",
    "legal_research",
    "customer_support",
    "code_assistant",
    "generic",
]

ApplicationType = Literal[
    "chat_interface",
    "api",
    "rag",
    "agent",
]

RiskLevel = Literal["low", "medium", "high", "critical"]


# ── Sub-configs (match target_profile.yaml) ───────────────────────────────────

class RAGConfig(BaseModel):
    enabled: bool = False
    document_upload_enabled: bool = False
    upload_endpoint: str = ""
    supported_formats: list[str] = Field(default_factory=list)
    knowledge_base_type: Literal["vector_db", "graph", "hybrid", "unknown"] = "unknown"
    test_indirect_injection: bool = True
    test_knowledge_poisoning: bool = True


class AgentTool(BaseModel):
    name: str
    risk_level: RiskLevel = "medium"


class AgentConfig(BaseModel):
    enabled: bool = False
    available_tools: list[AgentTool] = Field(default_factory=list)
    test_tool_abuse: bool = True
    test_privilege_escalation: bool = True

    @property
    def high_risk_tools(self) -> list[str]:
        return [t.name for t in self.available_tools if t.risk_level in ("high", "critical")]


class UserPersona(BaseModel):
    type: str = "generic_user"
    description: str = ""


# ── Primary target profile ────────────────────────────────────────────────────

class TargetProfile(BaseModel):
    """Full target profile loaded from ``target_profile.yaml``."""

    domain: DomainType = "generic"
    application_type: ApplicationType = "chat_interface"
    declared_guardrails: list[str] = Field(default_factory=list)
    known_system_prompt_hints: list[str] = Field(default_factory=list)
    attack_priority_override: list[str] = Field(default_factory=list)
    user_persona: UserPersona = Field(default_factory=UserPersona)
    rag_config: RAGConfig = Field(default_factory=RAGConfig)
    agent_config: AgentConfig = Field(default_factory=AgentConfig)
    extra: dict[str, Any] = Field(default_factory=dict)


# ── Threat map (produced by ThreatMapper) ────────────────────────────────────

class MitreAtlasEntry(BaseModel):
    """One MITRE ATLAS technique mapped from an attack category."""
    technique_id: str      # e.g. "AML.T0051"
    technique_name: str
    tactic: str            # e.g. "ML Attack Staging"
    relevance: str = ""    # brief note on why it applies


class AttackCategory(BaseModel):
    """One domain-specific attack category with associated metadata."""
    name: str
    description: str
    owasp_categories: list[str] = Field(default_factory=list)   # e.g. ["LLM01"]
    mitre_atlas: list[MitreAtlasEntry] = Field(default_factory=list)
    suggested_strategies: list[str] = Field(default_factory=list)
    priority: RiskLevel = "medium"
    domain_payload_seeds: list[str] = Field(default_factory=list)


class ThreatMap(BaseModel):
    """Complete threat picture for one target profile."""

    domain: str
    application_type: str
    attack_categories: list[AttackCategory] = Field(default_factory=list)
    compliance_frameworks: list[str] = Field(default_factory=list)
    rag_attack_categories: list[AttackCategory] = Field(default_factory=list)
    agent_attack_categories: list[AttackCategory] = Field(default_factory=list)
    recommended_strategy_weights: dict[str, float] = Field(default_factory=dict)

    @property
    def all_categories(self) -> list[AttackCategory]:
        return (
            self.attack_categories
            + self.rag_attack_categories
            + self.agent_attack_categories
        )

    @property
    def high_priority_categories(self) -> list[AttackCategory]:
        return [c for c in self.all_categories if c.priority in ("high", "critical")]


# ── Detection results ─────────────────────────────────────────────────────────

class RAGDetectionResult(BaseModel):
    """Output of the RAG heuristic detector."""
    rag_likely: bool = False
    confidence: float = 0.0
    signals: list[str] = Field(default_factory=list)
    recommended_tests: list[str] = Field(default_factory=list)


class AgentDetectionResult(BaseModel):
    """Output of the agent heuristic detector."""
    agent_likely: bool = False
    confidence: float = 0.0
    signals: list[str] = Field(default_factory=list)
    detected_tools: list[str] = Field(default_factory=list)
    recommended_tests: list[str] = Field(default_factory=list)
