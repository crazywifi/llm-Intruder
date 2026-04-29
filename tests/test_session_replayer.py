"""Tests for SessionReplayer using a mocked Playwright page."""
from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from llm_intruder.session.models import (
    ClickAction,
    ConditionalAction,
    FillAction,
    NavigateAction,
    ReplaySettings,
    SessionTemplate,
    SessionTemplateData,
    SuccessCheck,
    WaitForSelectorAction,
)
from llm_intruder.session.replayer import ReplayError, SessionReplayer, _resolve_variables


# ── _resolve_variables ────────────────────────────────────────────────────────

def test_resolve_known_variable() -> None:
    assert _resolve_variables("${USERNAME}", {"USERNAME": "alice"}) == "alice"


def test_resolve_multiple_variables() -> None:
    result = _resolve_variables("${A}:${B}", {"A": "foo", "B": "bar"})
    assert result == "foo:bar"


def test_resolve_unknown_variable_unchanged() -> None:
    assert _resolve_variables("${MISSING}", {}) == "${MISSING}"


def test_resolve_no_placeholders() -> None:
    assert _resolve_variables("plain text", {"X": "y"}) == "plain text"


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_replayer(actions: list, success_checks: list | None = None) -> tuple[SessionReplayer, MagicMock]:
    data = SessionTemplateData(
        name="test",
        recorded_at="2026-04-01T10:00:00+00:00",
        target_url="https://example.internal",
        actions=actions,
        replay_settings=ReplaySettings(max_retries=2, retry_delay_seconds=0, slow_mo_ms=0),
        success_validation=success_checks or [],
    )
    replayer = SessionReplayer(
        template=data,
        variables={"USERNAME": "alice", "PASSWORD": "s3cr3t"},
    )
    page = MagicMock()
    page.url = "https://example.internal/dashboard"
    page.context.cookies.return_value = [{"name": "session_id"}]
    page.query_selector.return_value = None  # no conditional elements by default
    return replayer, page


# ── individual action execution ───────────────────────────────────────────────

def test_navigate_action_calls_goto() -> None:
    replayer, page = _make_replayer([
        NavigateAction(type="navigate", url="https://example.internal/login"),
    ])
    replayer.replay(page)
    page.goto.assert_called_once_with(
        "https://example.internal/login", wait_until="networkidle"
    )


def test_fill_action_resolves_variable() -> None:
    replayer, page = _make_replayer([
        FillAction(type="fill", selector="input[name='email']", value="${USERNAME}"),
    ])
    replayer.replay(page)
    page.fill.assert_called_once_with("input[name='email']", "alice")


def test_fill_action_resolves_password() -> None:
    replayer, page = _make_replayer([
        FillAction(type="fill", selector="input[name='password']", value="${PASSWORD}"),
    ])
    replayer.replay(page)
    page.fill.assert_called_once_with("input[name='password']", "s3cr3t")


def test_click_action_no_wait() -> None:
    replayer, page = _make_replayer([
        ClickAction(type="click", selector="button[type='submit']"),
    ])
    replayer.replay(page)
    page.click.assert_called_once_with("button[type='submit']")


def test_click_action_with_navigation_wait() -> None:
    replayer, page = _make_replayer([
        ClickAction(type="click", selector="button[type='submit']", wait_for="navigation"),
    ])
    replayer.replay(page)
    # expect_navigation context manager should be entered
    page.expect_navigation.assert_called_once()


def test_wait_for_selector_action() -> None:
    replayer, page = _make_replayer([
        WaitForSelectorAction(type="wait_for_selector", selector=".dashboard", timeout=5000),
    ])
    replayer.replay(page)
    page.wait_for_selector.assert_called_once_with(".dashboard", timeout=5000)


def test_conditional_action_taken_when_element_present() -> None:
    page = MagicMock()
    page.url = "https://example.internal/dashboard"
    page.context.cookies.return_value = [{"name": "session_id"}]
    page.query_selector.return_value = MagicMock()  # element IS present

    data = SessionTemplateData(
        name="test",
        recorded_at="2026-04-01T10:00:00+00:00",
        target_url="https://example.internal",
        actions=[
            ConditionalAction(
                type="conditional",
                if_selector="input[name='otp']",
                then=[
                    WaitForSelectorAction(type="wait_for_selector", selector=".dashboard"),
                ],
            )
        ],
        replay_settings=ReplaySettings(max_retries=1, retry_delay_seconds=0, slow_mo_ms=0),
    )
    replayer = SessionReplayer(template=data)
    replayer.replay(page)
    page.wait_for_selector.assert_called()


def test_conditional_action_skipped_when_element_absent() -> None:
    page = MagicMock()
    page.url = "https://example.internal/dashboard"
    page.context.cookies.return_value = [{"name": "session_id"}]
    page.query_selector.return_value = None  # element NOT present

    data = SessionTemplateData(
        name="test",
        recorded_at="2026-04-01T10:00:00+00:00",
        target_url="https://example.internal",
        actions=[
            ConditionalAction(
                type="conditional",
                if_selector="input[name='otp']",
                then=[
                    WaitForSelectorAction(type="wait_for_selector", selector=".dashboard"),
                ],
            )
        ],
        replay_settings=ReplaySettings(max_retries=1, retry_delay_seconds=0, slow_mo_ms=0),
    )
    replayer = SessionReplayer(template=data)
    replayer.replay(page)
    page.wait_for_selector.assert_not_called()


# ── success validation ────────────────────────────────────────────────────────

def test_success_check_url_not_contains_passes() -> None:
    replayer, page = _make_replayer(
        actions=[],
        success_checks=[SuccessCheck(type="url_not_contains", patterns=["/login"])],
    )
    page.url = "https://example.internal/dashboard"
    assert replayer.replay(page) is True


def test_success_check_url_not_contains_fails() -> None:
    replayer, page = _make_replayer(
        actions=[],
        success_checks=[SuccessCheck(type="url_not_contains", patterns=["/login"])],
    )
    page.url = "https://example.internal/login"
    # validation fails on every attempt → ReplayError
    with pytest.raises(ReplayError):
        replayer.replay(page)


def test_success_check_cookie_exists_passes() -> None:
    replayer, page = _make_replayer(
        actions=[],
        success_checks=[SuccessCheck(type="cookie_exists", names=["session_id"])],
    )
    page.context.cookies.return_value = [{"name": "session_id"}]
    assert replayer.replay(page) is True


def test_success_check_cookie_missing_fails() -> None:
    replayer, page = _make_replayer(
        actions=[],
        success_checks=[SuccessCheck(type="cookie_exists", names=["session_id"])],
    )
    page.context.cookies.return_value = []
    with pytest.raises(ReplayError):
        replayer.replay(page)


# ── retry behaviour ───────────────────────────────────────────────────────────

def test_retry_on_exception_then_succeed() -> None:
    page = MagicMock()
    page.url = "https://example.internal/dashboard"
    page.context.cookies.return_value = [{"name": "session_id"}]
    page.query_selector.return_value = None

    # goto raises on first call, succeeds on second
    page.goto.side_effect = [RuntimeError("network error"), None]

    data = SessionTemplateData(
        name="test",
        recorded_at="2026-04-01T10:00:00+00:00",
        target_url="https://example.internal",
        actions=[NavigateAction(type="navigate", url="https://example.internal/login")],
        replay_settings=ReplaySettings(max_retries=2, retry_delay_seconds=0, slow_mo_ms=0),
    )
    replayer = SessionReplayer(template=data)
    result = replayer.replay(page)
    assert result is True
    assert page.goto.call_count == 2


def test_all_retries_exhausted_raises_replay_error() -> None:
    page = MagicMock()
    page.goto.side_effect = RuntimeError("always fails")

    data = SessionTemplateData(
        name="test",
        recorded_at="2026-04-01T10:00:00+00:00",
        target_url="https://example.internal",
        actions=[NavigateAction(type="navigate", url="https://example.internal/login")],
        replay_settings=ReplaySettings(max_retries=2, retry_delay_seconds=0, slow_mo_ms=0),
    )
    replayer = SessionReplayer(template=data)
    with pytest.raises(ReplayError, match="2 attempts"):
        replayer.replay(page)
