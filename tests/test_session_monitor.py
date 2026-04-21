"""Tests for the logout detection monitor (pure-logic, no browser)."""
from __future__ import annotations

import pytest

from llm_intruder.session.models import LogoutTrigger
from llm_intruder.session.monitor import PageSnapshot, is_logged_out, which_trigger_fired


# ── helpers ───────────────────────────────────────────────────────────────────

def _http_trigger(codes: list[int]) -> LogoutTrigger:
    return LogoutTrigger(type="http_status", codes=codes)


def _url_trigger(patterns: list[str]) -> LogoutTrigger:
    return LogoutTrigger(type="url_redirect", patterns=patterns)


def _dom_trigger(selectors: list[str]) -> LogoutTrigger:
    return LogoutTrigger(type="dom_element", selectors=selectors)


def _cookie_trigger(names: list[str]) -> LogoutTrigger:
    return LogoutTrigger(type="cookie_missing", names=names)


def _body_trigger(patterns: list[str]) -> LogoutTrigger:
    return LogoutTrigger(type="response_body", patterns=patterns)


# ── http_status trigger ───────────────────────────────────────────────────────

def test_http_401_fires() -> None:
    snap = PageSnapshot(http_status=401)
    assert is_logged_out([_http_trigger([401, 403])], snap)


def test_http_200_does_not_fire() -> None:
    snap = PageSnapshot(http_status=200)
    assert not is_logged_out([_http_trigger([401, 403])], snap)


def test_http_trigger_no_status_in_snap() -> None:
    snap = PageSnapshot(http_status=None)
    assert not is_logged_out([_http_trigger([401])], snap)


# ── url_redirect trigger ──────────────────────────────────────────────────────

def test_url_login_redirect_fires() -> None:
    snap = PageSnapshot(url="https://app.internal/login?next=/dashboard")
    assert is_logged_out([_url_trigger(["*/login*"])], snap)


def test_url_signin_redirect_fires() -> None:
    snap = PageSnapshot(url="https://app.internal/signin")
    assert is_logged_out([_url_trigger(["*/signin*"])], snap)


def test_url_dashboard_does_not_fire() -> None:
    snap = PageSnapshot(url="https://app.internal/dashboard")
    assert not is_logged_out([_url_trigger(["*/login*", "*/signin*"])], snap)


def test_url_session_expired_fires() -> None:
    snap = PageSnapshot(url="https://app.internal/session-expired")
    assert is_logged_out([_url_trigger(["*/session-expired*"])], snap)


# ── dom_element trigger ───────────────────────────────────────────────────────

def test_dom_login_form_fires() -> None:
    snap = PageSnapshot(dom_selectors_present=[".login-form"])
    assert is_logged_out([_dom_trigger([".login-form", "#login-modal"])], snap)


def test_dom_no_match_does_not_fire() -> None:
    snap = PageSnapshot(dom_selectors_present=[".dashboard"])
    assert not is_logged_out([_dom_trigger([".login-form"])], snap)


# ── cookie_missing trigger ────────────────────────────────────────────────────

def test_cookie_missing_fires() -> None:
    snap = PageSnapshot(cookie_names=["other_cookie"])  # session_id absent
    assert is_logged_out([_cookie_trigger(["session_id"])], snap)


def test_cookie_present_does_not_fire() -> None:
    snap = PageSnapshot(cookie_names=["session_id", "auth_token"])
    assert not is_logged_out([_cookie_trigger(["session_id"])], snap)


# ── response_body trigger ─────────────────────────────────────────────────────

def test_response_body_unauthorized_fires() -> None:
    snap = PageSnapshot(response_body='{"error":"unauthorized"}')
    assert is_logged_out([_body_trigger(['"error":"unauthorized"'])], snap)


def test_response_body_no_match_does_not_fire() -> None:
    snap = PageSnapshot(response_body='{"status":"ok"}')
    assert not is_logged_out([_body_trigger(['"error":"unauthorized"'])], snap)


# ── which_trigger_fired ───────────────────────────────────────────────────────

def test_which_trigger_fired_returns_first_match() -> None:
    triggers = [
        _http_trigger([401]),
        _url_trigger(["*/login*"]),
    ]
    snap = PageSnapshot(http_status=401)
    fired = which_trigger_fired(triggers, snap)
    assert fired is not None
    assert fired.type == "http_status"


def test_which_trigger_fired_returns_none_when_no_match() -> None:
    snap = PageSnapshot(http_status=200, url="https://app.internal/chat")
    fired = which_trigger_fired([_http_trigger([401])], snap)
    assert fired is None


# ── combined triggers ─────────────────────────────────────────────────────────

def test_no_triggers_never_fires() -> None:
    snap = PageSnapshot(http_status=401, url="https://app.internal/login")
    assert not is_logged_out([], snap)


def test_multiple_triggers_any_fires() -> None:
    triggers = [_http_trigger([401]), _url_trigger(["*/login*"])]
    # Only the URL trigger matches
    snap = PageSnapshot(url="https://app.internal/login", http_status=200)
    assert is_logged_out(triggers, snap)
