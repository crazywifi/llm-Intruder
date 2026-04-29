"""Load and validate target_profile.yaml files."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from llm_intruder.exceptions import ConfigurationError
from llm_intruder.profiles.models import TargetProfile


def load_target_profile(path: str | Path) -> TargetProfile:
    """Load a ``target_profile.yaml`` and return a validated :class:`TargetProfile`.

    Raises
    ------
    ConfigurationError
        If the file is missing, not valid YAML, or fails Pydantic validation.
    """
    p = Path(path)
    if not p.exists():
        raise ConfigurationError(f"Target profile not found: {p}")

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in target profile {p}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError(
            f"Target profile {p} must be a YAML mapping, got {type(raw).__name__}"
        )

    try:
        return TargetProfile.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(
            f"Target profile {p} failed validation:\n{exc}"
        ) from exc
