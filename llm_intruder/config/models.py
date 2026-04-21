from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RagConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    vector_store: str = "unknown"
    chunk_overlap_test: bool = True


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    tool_names: list[str] = Field(default_factory=list)
    max_tool_calls: int = 10


class EngagementConfig(BaseModel):
    """Root engagement configuration loaded from engagement YAML.

    ``extra="ignore"`` allows new fields to be added to the YAML without
    breaking older versions of the tool that don't know about them yet.
    """
    model_config = ConfigDict(extra="ignore")

    engagement_id: str
    authorisation_confirmed: bool
    scope: list[str]
    privacy_mode: bool = True
    judge_provider: str = "ollama"
    max_trials: int = 50
    strategy_weights: dict[str, float] = Field(default_factory=dict)


class TargetProfileConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domain: str
    application_type: str
    declared_guardrails: list[str] = Field(default_factory=list)
    rag_config: RagConfig | None = None
    agent_config: AgentConfig | None = None
