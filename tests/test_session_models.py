"""Tests for session Pydantic models."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from llm_intruder.session.models import (
    ClickAction,
    ConditionalAction,
    FillAction,
    LogoutDetection,
    LogoutTrigger,
    NavigateAction,
    PauseAction,
    ReplaySettings,
    SessionArtifacts,
    SessionTemplate,
    SessionTemplateData,
    SuccessCheck,
    WaitForSelectorAction,
)


def _minimal_template_dict() -> dict:
    return {
        "session_template": {
            "name": "test_session",
            "recorded_at": "2026-04-01T10:30:00+00:00",
            "target_url": "https://example.internal",
            "actions": [],
        }
    }


# ── Action models ─────────────────────────────────────────────────────────────

def test_navigate_action() -> None:
    a = NavigateAction(type="navigate", url="https://example.internal/login")
    assert a.url == "https://example.internal/login"
    assert a.wait_for == "networkidle"


def test_fill_action_with_variable() -> None:
    a = FillAction(type="fill", selector="input[name='email']", value="${USERNAME}")
    assert "${USERNAME}" in a.value


def test_click_action_defaults() -> None:
    a = ClickAction(type="click", selector="button[type='submit']")
    assert a.wait_for is None


def test_wait_for_selector_action() -> None:
    a = WaitForSelectorAction(type="wait_for_selector", selector=".dashboard", timeout=5000)
    assert a.timeout == 5000


def test_pause_action() -> None:
    a = PauseAction(
        type="pause",
        message="Enter MFA code",
        resume_on_selector=".dashboard",
        timeout=60_000,
    )
    assert a.timeout == 60_000


def test_conditional_action_with_then() -> None:
    a = ConditionalAction(
        type="conditional",
        if_selector="input[name='otp']",
        then=[PauseAction(type="pause", message="MFA", resume_on_selector=".dashboard")],
    )
    assert len(a.then) == 1


# ── LogoutTrigger ─────────────────────────────────────────────────────────────

def test_logout_trigger_http_status() -> None:
    t = LogoutTrigger(type="http_status", codes=[401, 403])
    assert 401 in (t.codes or [])


def test_logout_trigger_invalid_type() -> None:
    with pytest.raises(ValidationError):
        LogoutTrigger(type="invalid_type")


def test_logout_detection_empty() -> None:
    ld = LogoutDetection()
    assert ld.triggers == []


# ── SuccessCheck ──────────────────────────────────────────────────────────────

def test_success_check_url_not_contains() -> None:
    c = SuccessCheck(type="url_not_contains", patterns=["/login"])
    assert "/login" in (c.patterns or [])


def test_success_check_invalid_type() -> None:
    with pytest.raises(ValidationError):
        SuccessCheck(type="bad_type")


# ── ReplaySettings ────────────────────────────────────────────────────────────

def test_replay_settings_defaults() -> None:
    rs = ReplaySettings()
    assert rs.max_retries == 3
    assert rs.on_failure == "pause_campaign"


def test_replay_settings_invalid_on_failure() -> None:
    with pytest.raises(ValidationError):
        ReplaySettings(on_failure="explode")


# ── SessionTemplate round-trip ────────────────────────────────────────────────

def test_session_template_minimal() -> None:
    tmpl = SessionTemplate.model_validate(_minimal_template_dict())
    assert tmpl.session_template.name == "test_session"
    assert tmpl.session_template.actions == []


def test_session_template_missing_required_fields() -> None:
    with pytest.raises(ValidationError):
        SessionTemplate.model_validate({"session_template": {}})


def test_session_template_full() -> None:
    d = _minimal_template_dict()
    d["session_template"]["actions"] = [
        {"type": "navigate", "url": "https://example.internal/login"},
        {"type": "fill", "selector": "input[name='email']", "value": "${USERNAME}"},
        {"type": "click", "selector": "button[type='submit']", "wait_for": "navigation"},
    ]
    d["session_template"]["logout_detection"] = {
        "triggers": [{"type": "http_status", "codes": [401]}]
    }
    tmpl = SessionTemplate.model_validate(d)
    assert len(tmpl.session_template.actions) == 3
    assert len(tmpl.session_template.logout_detection.triggers) == 1
