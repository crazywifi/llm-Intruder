"""Payload library — load YAML templates and query by strategy / tag."""
from __future__ import annotations

import random
from pathlib import Path

import yaml

from llm_intruder.exceptions import ConfigurationError
from llm_intruder.payloads.models import PayloadLibrary, PayloadTemplate

# Placeholder strings that mark payloads as "template stubs" — they are designed
# to be manually customised before use and should never be sent verbatim.
_PLACEHOLDER_MARKERS = [
    "[YOUR HARMFUL REQUEST HERE]",
    "[TARGET HARMFUL REQUEST]",
    "[REDACTED",
    "[target]",
    "[TARGET]",
]


def _is_placeholder_payload(text: str) -> bool:
    """Return True if the payload text contains unfilled template placeholders."""
    return any(marker in text for marker in _PLACEHOLDER_MARKERS)


def load_library(path: str | Path) -> PayloadLibrary:
    """Load and validate a ``payloads.yaml`` file.
    
    Tolerates payloads written with ``category`` instead of ``strategy``
    (older catalogue format) by normalising the field before validation.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigurationError(f"Payload library not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        # Normalise each payload entry:
        #  - promote 'category' → 'strategy' for older catalogue format
        #  - coerce any non-string tags to str (YAML parses bare numbers as int)
        #  - remove template-stub payloads that contain unfilled placeholders
        cleaned = []
        for p in (data or {}).get("payloads", []):
            if "strategy" not in p and "category" in p:
                p["strategy"] = p["category"]
            if "tags" in p and isinstance(p["tags"], list):
                p["tags"] = [str(t) for t in p["tags"]]
            if not _is_placeholder_payload(p.get("text", "")):
                cleaned.append(p)
        if data:
            data["payloads"] = cleaned
        return PayloadLibrary.model_validate(data)
    except Exception as exc:
        raise ConfigurationError(f"Failed to load payload library: {exc}") from exc


def by_strategy(library: PayloadLibrary, strategy: str) -> list[PayloadTemplate]:
    """Return all templates whose ``strategy`` matches (case-insensitive)."""
    return [p for p in library.payloads if p.strategy.lower() == strategy.lower()]


def by_tag(library: PayloadLibrary, tag: str) -> list[PayloadTemplate]:
    """Return all templates that carry *tag*."""
    return [p for p in library.payloads if tag in p.tags]


def load_library_from_catalogue(
    categories: list[str] | None = None,
) -> PayloadLibrary:
    """Build a :class:`PayloadLibrary` directly from the built-in catalogue.

    Reads every ``*.yaml`` file inside ``payloads/catalogue/`` and assembles
    them into a single in-memory library.  This is the automatic fallback used
    when no ``--payloads`` flag is supplied to the CLI — it means you never
    need to generate or ship a combined ``payloads.yaml`` file.

    Parameters
    ----------
    categories:
        Optional list of category names to include (e.g. ``["splitting",
        "crescendo"]``).  ``None`` loads all categories.
    """
    from llm_intruder.payloads.fetcher import load_catalogue  # avoid circular at module level
    raw = load_catalogue(categories=categories)
    templates = [
        PayloadTemplate(
            id=p["id"],
            strategy=p.get("strategy") or p.get("category", "direct_injection"),
            text=p["text"],
            tags=[str(t) for t in p.get("tags", [])],  # coerce ints/floats to str
        )
        for p in raw
        if p.get("text", "").strip()                    # skip blank entries
        and not _is_placeholder_payload(p["text"])      # skip template stubs
    ]
    return PayloadLibrary(payloads=templates)


def pick(
    library: PayloadLibrary,
    strategy: str | None = None,
    rng: random.Random | None = None,
) -> PayloadTemplate:
    """Pick one :class:`PayloadTemplate` at random.

    If *strategy* is given, prefer templates for that strategy.
    Falls back to any template in the library if none match.

    Raises :class:`ConfigurationError` when the library is empty.
    """
    rng = rng or random.Random()
    pool = by_strategy(library, strategy) if strategy else library.payloads
    if not pool:
        import structlog as _structlog
        _structlog.get_logger().warning("payload_strategy_not_found", strategy=strategy, fallback="random")
        pool = library.payloads          # fallback: any payload
    if not pool:
        raise ConfigurationError("Payload library is empty.")
    return rng.choice(pool)
