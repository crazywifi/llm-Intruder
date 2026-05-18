from __future__ import annotations

from pathlib import Path

import yaml

from llm_intruder.config.models import EngagementConfig, TargetProfileConfig
from llm_intruder.exceptions import ConfigurationError


def load_engagement(path: str | Path) -> EngagementConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigurationError(f"Engagement file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return EngagementConfig(**data)
    except Exception as exc:
        raise ConfigurationError(f"Failed to load engagement config: {exc}") from exc


def load_target_profile(path: str | Path) -> TargetProfileConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigurationError(f"Target profile file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return TargetProfileConfig(**data)
    except Exception as exc:
        raise ConfigurationError(f"Failed to load target profile: {exc}") from exc
