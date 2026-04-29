"""Tests for BrowserDriver using a mocked Playwright page."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from llm_intruder.browser.driver import BrowserDriver
from llm_intruder.browser.models import (
    CapturedResponse,
    CsrfConfig,
    InputConfig,
    ResponseConfig,
    SiteAdapterConfig,
    WaitForReadyConfig,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_adapter(
    submit_method: str = "click",
    csrf_enabled: bool = False,
    wait_for_ready: bool = False,
    stream_method: str = "polling",
) -> SiteAdapterConfig:
    return SiteAdapterConfig(
        target_url="https://example.internal/chat",
        input=InputConfig(
            selector="textarea",
            submit="button.send",
            submit_method=submit_method,  # type: ignore[arg-type]
            clear_before_fill=True,
        ),
        response=ResponseConfig(
            selector=".response",
            stream_detection={"method": stream_method, "stability_ms": 50,
                              "polling_interval_ms": 10, "timeout_ms": 500},
        ),
        csrf=CsrfConfig(enabled=csrf_enabled),
        wait_for_ready=WaitForReadyConfig(selector="textarea", timeout=1000)
        if wait_for_ready else None,
    )


def _make_page(response_text: str = "Model reply") -> MagicMock:
    page = MagicMock()
    # query_selector for response returns element with inner_text
    response_el = MagicMock()
    response_el.inner_text.return_value = response_text
    # Default: query_selector returns the response element
    page.query_selector.return_value = response_el
    # evaluate returns a past timestamp so polling resolves immediately
    page.evaluate.return_value = 0  # last_mut = epoch 0 => very old
    return page


# ── wait_for_ready ────────────────────────────────────────────────────────────

def test_wait_for_ready_called_when_configured() -> None:
    adapter = _make_adapter(wait_for_ready=True)
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.send_payload(page, "test prompt")
    page.wait_for_selector.assert_called_with("textarea", timeout=1000)


def test_wait_for_ready_not_called_when_absent() -> None:
    adapter = _make_adapter(wait_for_ready=False)
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.send_payload(page, "test prompt")
    page.wait_for_selector.assert_not_called()


# ── CSRF harvesting ───────────────────────────────────────────────────────────

def test_csrf_not_harvested_when_disabled() -> None:
    adapter = _make_adapter(csrf_enabled=False)
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.send_payload(page, "test")
    # query_selector should only be called for the response, not CSRF
    # (CSRF disabled → no query_selector call for the csrf token_selector)
    calls = [str(c) for c in page.query_selector.call_args_list]
    assert not any("csrf-token" in c for c in calls)


def test_csrf_harvested_when_enabled() -> None:
    adapter = _make_adapter(csrf_enabled=True)
    # Override CSRF selector explicitly
    adapter.csrf.token_selector = "meta[name='csrf-token']"
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    csrf_el = MagicMock()
    csrf_el.get_attribute.return_value = "tok_abc123"

    def _qs(selector: str) -> MagicMock:
        if "csrf" in selector:
            return csrf_el
        return page.query_selector.return_value

    page.query_selector.side_effect = _qs
    driver.send_payload(page, "test")
    csrf_el.get_attribute.assert_called_once_with("content")


# ── fill_input ────────────────────────────────────────────────────────────────

def test_fill_clears_then_fills() -> None:
    adapter = _make_adapter()
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.send_payload(page, "my payload")
    page.click.assert_any_call("textarea")
    page.type.assert_called_once_with("textarea", "my payload", delay=10)


# ── submit ────────────────────────────────────────────────────────────────────

def test_submit_click() -> None:
    adapter = _make_adapter(submit_method="click")
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.send_payload(page, "hello")
    page.press.assert_not_called()


def test_submit_enter() -> None:
    adapter = _make_adapter(submit_method="enter")
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.send_payload(page, "hello")
    page.press.assert_called_once_with("textarea", "Enter")
    page.click.assert_any_call("textarea")


# ── full pipeline ─────────────────────────────────────────────────────────────

def test_send_payload_returns_captured_response() -> None:
    adapter = _make_adapter(stream_method="polling")
    driver = BrowserDriver(adapter=adapter)
    page = _make_page(response_text="The model said hello.")
    result = driver.send_payload(page, "hello")
    assert isinstance(result, CapturedResponse)
    assert result.text == "The model said hello."


def test_send_payload_hashes_are_set() -> None:
    adapter = _make_adapter(stream_method="polling")
    driver = BrowserDriver(adapter=adapter)
    page = _make_page(response_text="response content")
    result = driver.send_payload(page, "my payload")
    assert len(result.payload_hash) == 64
    assert len(result.response_hash) == 64


def test_send_payload_wipe_not_detected_when_response_stable() -> None:
    adapter = _make_adapter(stream_method="polling")
    driver = BrowserDriver(adapter=adapter)
    page = _make_page(response_text="stable response")
    result = driver.send_payload(page, "hello")
    # Response present both times → not wiped
    assert result.was_wiped is False


def test_send_payload_wipe_detected() -> None:
    # polling needs 1 + stability_threshold calls to stabilise on "full text",
    # then 1 final _read_selector, then 1 wipe-check _read_selector.
    # stability_ms=50, polling_ms=10  →  threshold=5  →  total ~7 "full text" calls.
    # Switch to "" on call 8+ so the wipe check fires.
    adapter = _make_adapter(stream_method="polling")
    driver = BrowserDriver(adapter=adapter)
    page = MagicMock()
    page.evaluate.return_value = 0

    call_count = {"n": 0}
    def _qs(selector: str) -> MagicMock:
        el = MagicMock()
        call_count["n"] += 1
        el.inner_text.return_value = "full text" if call_count["n"] <= 7 else ""
        return el

    page.query_selector.side_effect = _qs
    result = driver.send_payload(page, "trigger wipe")
    assert result.was_wiped is True


# ── wait_and_navigate ─────────────────────────────────────────────────────────

def test_wait_and_navigate_calls_goto() -> None:
    adapter = _make_adapter(wait_for_ready=True)
    driver = BrowserDriver(adapter=adapter)
    page = _make_page()
    driver.wait_and_navigate(page)
    page.goto.assert_called_once_with(
        "https://example.internal/chat", wait_until="networkidle"
    )
