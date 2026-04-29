"""Tests for browser Pydantic models and adapter loader."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from llm_intruder.browser.adapter_loader import load_site_adapter
from llm_intruder.browser.models import (
    CapturedResponse,
    CsrfConfig,
    InputConfig,
    ResponseConfig,
    SiteAdapterConfig,
    StreamDetectionConfig,
    WaitForReadyConfig,
    WipeDetectionConfig,
)
from llm_intruder.exceptions import ConfigurationError


# ── InputConfig ───────────────────────────────────────────────────────────────

def test_input_config_defaults() -> None:
    inp = InputConfig(selector="textarea", submit="button")
    assert inp.submit_method == "click"
    assert inp.clear_before_fill is True


def test_input_config_enter_method() -> None:
    inp = InputConfig(selector="textarea", submit="button", submit_method="enter")
    assert inp.submit_method == "enter"


def test_input_config_invalid_submit_method() -> None:
    with pytest.raises(ValidationError):
        InputConfig(selector="textarea", submit="button", submit_method="tab")


# ── StreamDetectionConfig ─────────────────────────────────────────────────────

def test_stream_detection_defaults() -> None:
    sd = StreamDetectionConfig()
    assert sd.method == "mutation_observer"
    assert sd.stability_ms == 800
    assert sd.timeout_ms == 60_000


def test_stream_detection_polling() -> None:
    sd = StreamDetectionConfig(method="polling", stability_ms=500)
    assert sd.method == "polling"
    assert sd.stability_ms == 500


def test_stream_detection_invalid_method() -> None:
    with pytest.raises(ValidationError):
        StreamDetectionConfig(method="websocket")


# ── ResponseConfig ────────────────────────────────────────────────────────────

def test_response_config_minimal() -> None:
    rc = ResponseConfig(selector=".response")
    assert rc.selector == ".response"
    assert rc.stream_detection.method == "mutation_observer"
    assert rc.wipe_detection.enabled is True


# ── CsrfConfig ────────────────────────────────────────────────────────────────

def test_csrf_config_disabled_by_default() -> None:
    cfg = CsrfConfig()
    assert cfg.enabled is False


def test_csrf_config_enabled() -> None:
    cfg = CsrfConfig(enabled=True, token_selector="input[name='_token']")
    assert cfg.enabled is True


# ── SiteAdapterConfig ─────────────────────────────────────────────────────────

def _minimal_adapter_dict() -> dict:
    return {
        "target_url": "https://example.internal/chat",
        "input": {"selector": "textarea", "submit": "button"},
        "response": {"selector": ".response"},
    }


def test_site_adapter_minimal() -> None:
    cfg = SiteAdapterConfig(**_minimal_adapter_dict())
    assert cfg.mode == "browser"
    assert cfg.target_url == "https://example.internal/chat"
    assert cfg.wait_for_ready is None


def test_site_adapter_with_wait_for_ready() -> None:
    d = _minimal_adapter_dict()
    d["wait_for_ready"] = {"selector": "textarea", "timeout": 15000}
    cfg = SiteAdapterConfig(**d)
    assert cfg.wait_for_ready is not None
    assert cfg.wait_for_ready.timeout == 15000


def test_site_adapter_invalid_mode() -> None:
    d = _minimal_adapter_dict()
    d["mode"] = "ftp"
    with pytest.raises(ValidationError):
        SiteAdapterConfig(**d)


def test_site_adapter_missing_target_url() -> None:
    with pytest.raises(ValidationError):
        SiteAdapterConfig(
            input={"selector": "textarea", "submit": "button"},
            response={"selector": ".response"},
        )


# ── CapturedResponse ──────────────────────────────────────────────────────────

def test_captured_response_defaults() -> None:
    cr = CapturedResponse(text="hello")
    assert cr.was_wiped is False
    assert cr.stream_detected is False
    assert cr.capture_duration_ms == 0.0


def test_captured_response_hashes_present() -> None:
    cr = CapturedResponse(
        text="response text",
        payload_hash="a" * 64,
        response_hash="b" * 64,
    )
    assert len(cr.payload_hash) == 64


# ── load_site_adapter ─────────────────────────────────────────────────────────

def test_load_site_adapter_valid(tmp_path: Path) -> None:
    content = textwrap.dedent("""\
        target_url: "https://example.internal/chat"
        input:
          selector: "textarea"
          submit: "button"
        response:
          selector: ".response"
    """)
    p = tmp_path / "adapter.yaml"
    p.write_text(content)
    cfg = load_site_adapter(p)
    assert cfg.target_url == "https://example.internal/chat"


def test_load_site_adapter_missing_file() -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_site_adapter("/nonexistent/site_adapter.yaml")


def test_load_site_adapter_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("target_url: only_this_field: nothing_else")
    with pytest.raises(ConfigurationError):
        load_site_adapter(p)


def test_load_example_site_adapter() -> None:
    """Bundled example must load without error."""
    example = Path(__file__).parent.parent / "examples" / "site_adapter.yaml"
    if example.exists():
        cfg = load_site_adapter(example)
        assert cfg.target_url
        assert cfg.input.selector
