"""Load and validate api_adapter.yaml files."""
from __future__ import annotations

from pathlib import Path

import yaml

from llm_intruder.api.models import ApiAdapterConfig
from llm_intruder.exceptions import ConfigurationError


class _DuplicateKeyLoader(yaml.SafeLoader):
    """YAML loader that raises on duplicate mapping keys instead of silently overwriting."""


def _construct_mapping_no_duplicates(loader, node):
    """Build a dict from a YAML mapping node, raising on duplicate keys."""
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node)
    seen: set = set()
    for key, _ in pairs:
        if key in seen:
            raise ConfigurationError(
                f"Duplicate key '{key}' in adapter YAML. "
                "Remove the duplicate — PyYAML silently uses the last value, "
                "which is almost always unintentional."
            )
        seen.add(key)
    return dict(pairs)


_DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_no_duplicates,
)


def load_api_adapter(path: str | Path) -> ApiAdapterConfig:
    """Load *path* and return a validated :class:`ApiAdapterConfig`.

    Raises :class:`ConfigurationError` if the YAML contains duplicate keys
    (e.g. two ``max_body_length`` entries), which PyYAML would otherwise
    resolve silently by keeping the last value.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigurationError(f"API adapter file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        data = yaml.load(raw, Loader=_DuplicateKeyLoader)  # noqa: S506
        return ApiAdapterConfig(**data)
    except ConfigurationError:
        raise
    except Exception as exc:
        raise ConfigurationError(f"Failed to load API adapter: {exc}") from exc
