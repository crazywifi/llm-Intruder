from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from llm_intruder.config.loader import load_engagement, load_target_profile
from llm_intruder.config.models import EngagementConfig, TargetProfileConfig
from llm_intruder.exceptions import ConfigurationError


@pytest.fixture()
def engagement_yaml(tmp_path: Path) -> Path:
    content = textwrap.dedent("""\
        engagement_id: "ENG-TEST-001"
        authorisation_confirmed: true
        scope:
          - "https://example.internal"
          - "https://api.example.internal"
        privacy_mode: true
        judge_provider: "ollama"
        max_trials: 10
        strategy_weights:
          direct_injection: 0.5
          role_play: 0.5
    """)
    p = tmp_path / "engagement.yaml"
    p.write_text(content)
    return p


@pytest.fixture()
def target_profile_yaml(tmp_path: Path) -> Path:
    content = textwrap.dedent("""\
        domain: "example.internal"
        application_type: "chatbot"
        declared_guardrails:
          - "no harmful content"
        rag_config:
          enabled: true
          vector_store: "chroma"
          chunk_overlap_test: false
    """)
    p = tmp_path / "target_profile.yaml"
    p.write_text(content)
    return p


def test_load_engagement_valid(engagement_yaml: Path) -> None:
    config = load_engagement(engagement_yaml)
    assert isinstance(config, EngagementConfig)
    assert config.engagement_id == "ENG-TEST-001"
    assert config.authorisation_confirmed is True
    assert len(config.scope) == 2
    assert config.max_trials == 10
    assert config.strategy_weights["direct_injection"] == pytest.approx(0.5)


def test_load_engagement_defaults(tmp_path: Path) -> None:
    content = textwrap.dedent("""\
        engagement_id: "ENG-MIN-001"
        authorisation_confirmed: true
        scope:
          - "https://example.internal"
        strategy_weights: {}
    """)
    p = tmp_path / "min.yaml"
    p.write_text(content)
    config = load_engagement(p)
    assert config.privacy_mode is True
    assert config.judge_provider == "ollama"
    assert config.max_trials == 50


def test_load_engagement_missing_file() -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_engagement("/nonexistent/path/engagement.yaml")


def test_load_engagement_missing_required_field(tmp_path: Path) -> None:
    content = "authorisation_confirmed: true\nscope: []\nstrategy_weights: {}\n"
    p = tmp_path / "bad.yaml"
    p.write_text(content)
    with pytest.raises(ConfigurationError):
        load_engagement(p)


def test_load_target_profile_valid(target_profile_yaml: Path) -> None:
    profile = load_target_profile(target_profile_yaml)
    assert isinstance(profile, TargetProfileConfig)
    assert profile.domain == "example.internal"
    assert profile.rag_config is not None
    assert profile.rag_config.enabled is True
    assert profile.agent_config is None


def test_load_target_profile_missing_file() -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_target_profile("/nonexistent/path/target.yaml")
