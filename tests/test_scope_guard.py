from __future__ import annotations

import pytest

from llm_intruder.config.models import EngagementConfig
from llm_intruder.core.scope_guard import check_scope, validate_scope_urls
from llm_intruder.exceptions import ScopeViolationError


def _make_config(*scope_entries: str) -> EngagementConfig:
    return EngagementConfig(
        engagement_id="ENG-TEST",
        authorisation_confirmed=True,
        scope=list(scope_entries),
        strategy_weights={},
    )


# ── check_scope ────────────────────────────────────────────────────────────────

def test_exact_url_in_scope() -> None:
    config = _make_config("https://example.internal")
    check_scope("https://example.internal", config)  # must not raise


def test_subpath_of_scope_entry_passes() -> None:
    config = _make_config("https://example.internal")
    check_scope("https://example.internal/chat", config)


def test_subdomain_of_scope_entry_passes() -> None:
    config = _make_config("example.internal")
    check_scope("https://api.example.internal", config)


def test_url_not_in_scope_raises() -> None:
    config = _make_config("https://example.internal")
    with pytest.raises(ScopeViolationError):
        check_scope("https://evil.com", config)


def test_similar_domain_not_in_scope_raises() -> None:
    config = _make_config("https://example.internal")
    with pytest.raises(ScopeViolationError):
        check_scope("https://notexample.internal", config)


def test_multiple_scope_entries_any_match_passes() -> None:
    config = _make_config("https://app.internal", "https://api.internal")
    check_scope("https://api.internal/v1/chat", config)


def test_scope_violation_error_message_names_url() -> None:
    config = _make_config("https://example.internal")
    with pytest.raises(ScopeViolationError, match="evil.com"):
        check_scope("https://evil.com", config)


# ── validate_scope_urls ───────────────────────────────────────────────────────

def test_validate_scope_urls_valid() -> None:
    config = _make_config("https://example.internal", "http://api.example.internal")
    validate_scope_urls(config)  # must not raise


def test_validate_scope_urls_bare_domain() -> None:
    config = _make_config("example.internal")
    validate_scope_urls(config)  # bare domains are valid


def test_validate_scope_urls_invalid_raises() -> None:
    config = _make_config("")
    with pytest.raises(ScopeViolationError, match="Invalid scope entry"):
        validate_scope_urls(config)
