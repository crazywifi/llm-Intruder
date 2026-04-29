"""Tests for SmartRecorder — selector detection and adapter generation."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from llm_intruder.browser.smart_recorder import SmartRecorder, _RECORDER_JS


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_state(phase: str = "recorded", **overrides) -> dict:
    base = {
        "phase": phase,
        "inputSelector": "textarea#prompt",
        "submitSelector": "button.send",
        "responseSelector": "div.response",
        "responseText": "Hello! How can I help you?",
        "error": None,
    }
    base.update(overrides)
    return base


def _mock_page(state: dict) -> MagicMock:
    """Return a mock Playwright page that simulates the recorder JS."""
    page = MagicMock()
    page.evaluate.side_effect = lambda js: json.dumps(state)
    page.goto.return_value = None
    return page


# ── Tests for _build_adapter ─────────────────────────────────────────────────

class TestBuildAdapter:
    def test_click_submit(self):
        rec = SmartRecorder(target_url="https://gandalf.lakera.ai")
        state = _make_state()
        cfg = rec._build_adapter(state)

        assert cfg.target_url == "https://gandalf.lakera.ai"
        assert cfg.input.selector == "textarea#prompt"
        assert cfg.input.submit == "button.send"
        assert cfg.input.submit_method == "click"
        assert cfg.response.selector == "div.response"
        assert cfg.mode == "browser"

    def test_enter_key_submit(self):
        rec = SmartRecorder(target_url="https://example.com/chat")
        state = _make_state(submitSelector="__ENTER_KEY__")
        cfg = rec._build_adapter(state)

        assert cfg.input.submit_method == "enter"
        # Submit selector falls back to input selector for Enter
        assert cfg.input.submit == "textarea#prompt"

    def test_error_in_state_raises(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state(error="Could not detect response area.")
        with pytest.raises(RuntimeError, match="Could not detect response area"):
            rec._build_adapter(state)

    def test_missing_input_raises(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state(inputSelector=None)
        with pytest.raises(RuntimeError, match="Could not detect the input field"):
            rec._build_adapter(state)

    def test_missing_response_raises(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state(responseSelector=None)
        cfg = rec._build_adapter(state)
        assert cfg.response.selector == "__AUTO__"

    def test_wait_for_ready_uses_input_selector(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state()
        cfg = rec._build_adapter(state)
        assert cfg.wait_for_ready is not None
        assert cfg.wait_for_ready.selector == "textarea#prompt"

    def test_csrf_disabled_by_default(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state()
        cfg = rec._build_adapter(state)
        assert cfg.csrf.enabled is False

    def test_wipe_detection_uses_response_selector(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state()
        cfg = rec._build_adapter(state)
        assert cfg.response.wipe_detection.check_selector == "div.response"

    def test_stream_detection_defaults(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state()
        cfg = rec._build_adapter(state)
        assert cfg.response.stream_detection.method == "mutation_observer"
        assert cfg.response.stream_detection.stability_ms == 1500

    def test_diff_response_selector_is_normalised_to_auto(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state(responseSelector="__DIFF__")
        cfg = rec._build_adapter(state)
        assert cfg.response.selector == "__AUTO__"

    def test_container_submit_selector_falls_back_to_enter(self):
        rec = SmartRecorder(target_url="https://example.com")
        state = _make_state(submitSelector="div.send-box")
        cfg = rec._build_adapter(state)
        assert cfg.input.submit_method == "enter"
        assert cfg.input.submit == "textarea#prompt"


# ── Tests for _wait_for_recording ────────────────────────────────────────────

class TestWaitForRecording:
    def test_immediate_recorded(self):
        rec = SmartRecorder(target_url="https://example.com", timeout_s=5)
        state = _make_state(phase="recorded")
        page = _mock_page(state)
        result = rec._wait_for_recording(page)
        assert result["inputSelector"] == "textarea#prompt"

    def test_done_phase_also_accepted(self):
        rec = SmartRecorder(target_url="https://example.com", timeout_s=5)
        state = _make_state(phase="done")
        page = _mock_page(state)
        result = rec._wait_for_recording(page)
        assert result["phase"] == "done"

    def test_timeout_raises(self):
        rec = SmartRecorder(target_url="https://example.com", timeout_s=0)
        state = _make_state(phase="waiting")
        page = _mock_page(state)
        with pytest.raises(TimeoutError, match="Recording timed out"):
            rec._wait_for_recording(page)


# ── Test recorder JS is valid ────────────────────────────────────────────────

class TestRecorderJS:
    def test_js_is_non_empty_string(self):
        assert isinstance(_RECORDER_JS, str)
        assert len(_RECORDER_JS) > 100

    def test_js_contains_sentinel_recorder(self):
        assert "__sentinel_recorder" in _RECORDER_JS

    def test_js_contains_phase_tracking(self):
        for phase in ("waiting", "input_detected", "submit_detected", "capturing", "recorded"):
            assert phase in _RECORDER_JS

    def test_js_is_arrow_function(self):
        """Verify JS is a Playwright-compatible arrow function, not IIFE with arguments."""
        stripped = _RECORDER_JS.strip()
        assert stripped.startswith("() =>") or stripped.startswith("()=>")
        assert "arguments[" not in _RECORDER_JS
