"""Tests for ResponseCapture — both mutation_observer and polling strategies."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from llm_intruder.browser.models import ResponseConfig, StreamDetectionConfig, WipeDetectionConfig
from llm_intruder.browser.response_capture import ResponseCapture
from llm_intruder.browser.llm_detector import SmartResponseReader
from llm_intruder.core.audit_log import sha256


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_config(
    method: str = "polling",
    stability_ms: int = 50,
    polling_ms: int = 10,
    timeout_ms: int = 500,
    wipe_enabled: bool = False,
) -> ResponseConfig:
    return ResponseConfig(
        selector=".response",
        stream_detection=StreamDetectionConfig(
            method=method,  # type: ignore[arg-type]
            stability_ms=stability_ms,
            polling_interval_ms=polling_ms,
            timeout_ms=timeout_ms,
        ),
        wipe_detection=WipeDetectionConfig(enabled=wipe_enabled),
    )


def _page_with_text(text: str) -> MagicMock:
    page = MagicMock()
    el = MagicMock()
    el.inner_text.return_value = text
    page.query_selector.return_value = el
    # For mutation_observer: make evaluate return old timestamp (= stable immediately)
    page.evaluate.return_value = 0
    return page


# ── polling strategy ──────────────────────────────────────────────────────────

def test_polling_captures_stable_text() -> None:
    cfg = _make_config(method="polling")
    cap = ResponseCapture(cfg)
    page = _page_with_text("Model said hello.")
    result = cap.capture(page, "hello")
    assert result.text == "Model said hello."


def test_polling_sets_hashes() -> None:
    cfg = _make_config(method="polling")
    cap = ResponseCapture(cfg)
    page = _page_with_text("response text")
    result = cap.capture(page, "my payload")
    assert result.payload_hash == sha256("my payload")
    assert result.response_hash == sha256("response text")


def test_polling_stream_detected_flag() -> None:
    cfg = _make_config(method="polling")
    cap = ResponseCapture(cfg)
    page = _page_with_text("stable")
    result = cap.capture(page, "p")
    assert result.stream_detected is True


def test_polling_empty_selector_returns_empty() -> None:
    cfg = _make_config(method="polling")
    cap = ResponseCapture(cfg)
    page = MagicMock()
    page.evaluate.return_value = 0
    page.query_selector.return_value = None   # element not in DOM
    result = cap.capture(page, "p")
    assert result.text == ""


def test_polling_timeout_still_returns_text() -> None:
    """If stream never stabilises, return whatever text was last seen."""
    cfg = _make_config(method="polling", stability_ms=9999, timeout_ms=60)
    cap = ResponseCapture(cfg)
    # Text changes on every call (never stable within timeout)
    call = {"n": 0}
    def _qs(sel: str) -> MagicMock:
        el = MagicMock()
        call["n"] += 1
        el.inner_text.return_value = f"chunk_{call['n']}"
        return el
    page = MagicMock()
    page.evaluate.return_value = 0
    page.query_selector.side_effect = _qs
    result = cap.capture(page, "p")
    assert result.text.startswith("chunk_")
    assert result.stream_detected is False


# ── mutation_observer strategy ────────────────────────────────────────────────

def test_mutation_observer_captures_text() -> None:
    cfg = _make_config(method="mutation_observer", stability_ms=50, polling_ms=10)
    cap = ResponseCapture(cfg)
    page = _page_with_text("MO response text")
    # evaluate: setup JS returns None; last_mut returns epoch 0 (very old)
    page.evaluate.side_effect = [None, 0, None]  # setup, last_mut, disconnect
    result = cap.capture(page, "q")
    assert result.text == "MO response text"


def test_mutation_observer_injects_js() -> None:
    cfg = _make_config(method="mutation_observer")
    cap = ResponseCapture(cfg)
    page = _page_with_text("any text")
    page.evaluate.return_value = 0
    cap.capture(page, "q")
    # At least 2 evaluate calls: setup JS + last_mut poll
    assert page.evaluate.call_count >= 2


# ── wipe detection ────────────────────────────────────────────────────────────

def test_wipe_not_detected_when_response_stable() -> None:
    cfg = _make_config(method="polling", wipe_enabled=True)
    cap = ResponseCapture(cfg)
    page = _page_with_text("stable response")
    result = cap.capture(page, "p")
    assert result.was_wiped is False


def test_wipe_detected_when_text_disappears() -> None:
    # stability_ms=50, polling_ms=10 → threshold=5 → need ~7 "full text" reads
    # before switching to "" so the wipe-check _read_selector gets empty.
    cfg = _make_config(method="polling", wipe_enabled=True, timeout_ms=500)
    cap = ResponseCapture(cfg)
    page = MagicMock()
    page.evaluate.return_value = 0
    call = {"n": 0}
    def _qs(sel: str) -> MagicMock:
        el = MagicMock()
        call["n"] += 1
        el.inner_text.return_value = "full text" if call["n"] <= 7 else ""
        return el
    page.query_selector.side_effect = _qs
    result = cap.capture(page, "p")
    assert result.was_wiped is True


def test_wipe_check_disabled() -> None:
    cfg = _make_config(method="polling", wipe_enabled=False)
    cap = ResponseCapture(cfg)
    page = MagicMock()
    page.evaluate.return_value = 0
    el = MagicMock()
    el.inner_text.return_value = ""
    page.query_selector.return_value = el
    result = cap.capture(page, "p")
    assert result.was_wiped is False


# ── duration ──────────────────────────────────────────────────────────────────

def test_capture_duration_is_positive() -> None:
    cfg = _make_config(method="polling")
    cap = ResponseCapture(cfg)
    page = _page_with_text("text")
    result = cap.capture(page, "p")
    assert result.capture_duration_ms >= 0


def test_auto_selector_uses_fallback_container() -> None:
    cfg = ResponseConfig(
        selector="__AUTO__",
        stream_detection=StreamDetectionConfig(
            method="polling",
            stability_ms=50,
            polling_interval_ms=10,
            timeout_ms=100,
        ),
        wipe_detection=WipeDetectionConfig(enabled=False),
    )
    cap = ResponseCapture(cfg)
    page = MagicMock()
    page.evaluate.return_value = 0

    def _qs(sel: str):
        if sel == "__AUTO__":
            return None
        if sel == '[role="log"]':
            el = MagicMock()
            el.inner_text.return_value = "captured response"
            return el
        return None

    page.query_selector.side_effect = _qs
    result = cap.capture(page, "p")
    assert result.text == "captured response"


def test_smart_response_reader_strips_echoed_payload_prefix() -> None:
    text = SmartResponseReader._strip_echoed_payload(
        "Hello, what can you help me with? Hello! I can help.",
        "Hello, what can you help me with?",
    )
    assert text == "Hello! I can help."


def test_smart_response_reader_infers_response_selector() -> None:
    page = MagicMock()
    page.evaluate.return_value = {"selector": ".response", "score": 100}
    result = SmartResponseReader.infer_response_selector(
        page,
        "Hello! I can help.",
        sent_payload="Hello, what can you help me with?",
    )
    assert result == {"selector": ".response", "score": 100}


def test_smart_response_reader_infers_selector_from_outer_html() -> None:
    page = MagicMock()
    el = MagicMock()
    el.is_visible.return_value = True

    def _qs(selector: str):
        return el if selector == '[data-testid="assistant-message"]' else None

    page.query_selector.side_effect = _qs
    result = SmartResponseReader.infer_response_selector_from_outer_html(
        page,
        '<div data-testid="assistant-message" class="foo bar">Hello</div>',
    )
    assert result == {"selector": '[data-testid="assistant-message"]', "source": "outer_html"}
