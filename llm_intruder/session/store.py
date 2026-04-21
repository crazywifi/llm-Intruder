"""Template store — save and load SessionTemplate YAML files."""
from __future__ import annotations

from pathlib import Path

import yaml

from llm_intruder.exceptions import ConfigurationError
from llm_intruder.session.models import SessionTemplate, SessionTemplateData


def save_template(template: SessionTemplate, path: str | Path) -> None:
    """Serialise *template* to a YAML file at *path*."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = template.model_dump(mode="json")
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def load_template(path: str | Path) -> SessionTemplate:
    """Load and validate a YAML session template from *path*."""
    path = Path(path)
    if not path.exists():
        raise ConfigurationError(f"Session template not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return SessionTemplate.model_validate(raw)
    except Exception as exc:
        raise ConfigurationError(f"Failed to load session template: {exc}") from exc


def list_templates(directory: str | Path = ".") -> list[Path]:
    """Return all ``*.yaml`` files that contain a ``session_template`` key."""
    directory = Path(directory)
    results: list[Path] = []
    for candidate in sorted(directory.rglob("*.yaml")):
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if isinstance(raw, dict) and "session_template" in raw:
                results.append(candidate)
        except Exception:
            continue
    return results
