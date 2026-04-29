"""Load and validate site_adapter.yaml files."""
from __future__ import annotations

from pathlib import Path

import yaml

from llm_intruder.browser.models import SiteAdapterConfig
from llm_intruder.exceptions import ConfigurationError


def load_site_adapter(path: str | Path) -> SiteAdapterConfig:
    """Load *path* and return a validated :class:`SiteAdapterConfig`."""
    path = Path(path)
    if not path.exists():
        raise ConfigurationError(f"Site adapter file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return SiteAdapterConfig(**data)
    except Exception as exc:
        raise ConfigurationError(f"Failed to load site adapter: {exc}") from exc
