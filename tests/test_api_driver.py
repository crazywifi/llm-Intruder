"""Tests for ApiDriver — thin orchestration layer over ApiClient."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from llm_intruder.api.driver import ApiDriver
from llm_intruder.api.models import ApiAdapterConfig, EndpointConfig, RateLimitConfig
from llm_intruder.browser.models import CapturedResponse
from llm_intruder.core.audit_log import sha256


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_adapter(streaming: bool = False) -> ApiAdapterConfig:
    return ApiAdapterConfig(
        endpoint=EndpointConfig(
            url="https://api.example.internal/v1/chat",
            streaming=streaming,
            timeout_seconds=5.0,
        ),
        headers={"Authorization": "Bearer ${API_KEY}"},
        request_template='{"messages":[{"role":"user","content":"${PAYLOAD}"}]}',
        rate_limiting=RateLimitConfig(max_retries=0, backoff_factor=0.01),
    )


def _patch_client_send(return_text: str, streamed: bool = False):
    """Patch ApiClient.send to return (return_text, streamed)."""
    return patch(
        "llm_intruder.api.client.ApiClient.send",
        return_value=(return_text, streamed),
    )


# ── return type ───────────────────────────────────────────────────────────────

def test_send_payload_returns_captured_response() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter, variables={"API_KEY": "key"})
    with _patch_client_send("The model replied."):
        result = driver.send_payload("hello")
    assert isinstance(result, CapturedResponse)


def test_send_payload_text_matches() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("response text"):
        result = driver.send_payload("my prompt")
    assert result.text == "response text"


# ── hashing ───────────────────────────────────────────────────────────────────

def test_payload_hash_correct() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("ignored response"):
        result = driver.send_payload("my payload")
    assert result.payload_hash == sha256("my payload")


def test_response_hash_correct() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("model output"):
        result = driver.send_payload("prompt")
    assert result.response_hash == sha256("model output")


def test_hash_length_is_64_chars() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("some text"):
        result = driver.send_payload("p")
    assert len(result.payload_hash) == 64
    assert len(result.response_hash) == 64


# ── stream flag ───────────────────────────────────────────────────────────────

def test_stream_detected_false_for_non_streaming() -> None:
    adapter = _make_adapter(streaming=False)
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("text", streamed=False):
        result = driver.send_payload("p")
    assert result.stream_detected is False


def test_stream_detected_true_for_streaming() -> None:
    adapter = _make_adapter(streaming=True)
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("streamed text", streamed=True):
        result = driver.send_payload("p")
    assert result.stream_detected is True


# ── wipe always false for API mode ────────────────────────────────────────────

def test_was_wiped_always_false() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send("some reply"):
        result = driver.send_payload("p")
    assert result.was_wiped is False


# ── empty response ────────────────────────────────────────────────────────────

def test_empty_response_handled() -> None:
    adapter = _make_adapter()
    driver = ApiDriver(adapter=adapter)
    with _patch_client_send(""):
        result = driver.send_payload("p")
    assert result.text == ""
    assert result.response_hash == sha256("")


# ── variable passthrough ──────────────────────────────────────────────────────

def test_variables_passed_to_client() -> None:
    adapter = _make_adapter()
    captured_vars: dict = {}

    original_init = __import__(
        "llm_intruder.api.client", fromlist=["ApiClient"]
    ).ApiClient.__init__

    def _fake_init(self, adapter, variables=None):
        captured_vars.update(variables or {})
        original_init(self, adapter, variables)

    with patch("llm_intruder.api.client.ApiClient.__init__", _fake_init):
        with patch("llm_intruder.api.client.ApiClient.send", return_value=("ok", False)):
            driver = ApiDriver(adapter=adapter, variables={"API_KEY": "secret"})
            driver.send_payload("test")

    assert captured_vars.get("API_KEY") == "secret"
