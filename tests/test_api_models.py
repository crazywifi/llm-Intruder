"""Tests for API adapter Pydantic models and loader."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from llm_intruder.api.adapter_loader import load_api_adapter
from llm_intruder.api.models import (
    ApiAdapterConfig,
    AuthRefreshConfig,
    EndpointConfig,
    RateLimitConfig,
    ResponseExtractionConfig,
)
from llm_intruder.exceptions import ConfigurationError


# ── EndpointConfig ────────────────────────────────────────────────────────────

def test_endpoint_defaults() -> None:
    ep = EndpointConfig(url="https://api.example.internal/v1/chat")
    assert ep.method == "POST"
    assert ep.streaming is False
    assert ep.stream_format == "sse"
    assert ep.timeout_seconds == 60.0


def test_endpoint_streaming_ndjson() -> None:
    ep = EndpointConfig(
        url="https://api.example.internal/v1/chat",
        streaming=True,
        stream_format="ndjson",
    )
    assert ep.stream_format == "ndjson"


def test_endpoint_invalid_method() -> None:
    with pytest.raises(ValidationError):
        EndpointConfig(url="https://api.example.internal/", method="DELETE")


def test_endpoint_invalid_stream_format() -> None:
    with pytest.raises(ValidationError):
        EndpointConfig(url="https://api.example.internal/", stream_format="websocket")


# ── ResponseExtractionConfig ──────────────────────────────────────────────────

def test_extraction_defaults() -> None:
    ext = ResponseExtractionConfig()
    assert ext.json_path == "$.choices[0].message.content"
    assert ext.stream_path == "$.choices[0].delta.content"
    assert ext.stream_delimiter == "data: "


# ── RateLimitConfig ───────────────────────────────────────────────────────────

def test_rate_limit_defaults() -> None:
    rl = RateLimitConfig()
    assert rl.requests_per_minute == 60
    assert 429 in rl.retry_on_status
    assert rl.backoff_factor == 2.0
    assert rl.max_retries == 3


def test_rate_limit_custom() -> None:
    rl = RateLimitConfig(requests_per_minute=10, max_retries=1, backoff_factor=1.5)
    assert rl.max_retries == 1


# ── AuthRefreshConfig ─────────────────────────────────────────────────────────

def test_auth_refresh_disabled_by_default() -> None:
    cfg = AuthRefreshConfig()
    assert cfg.enabled is False


def test_auth_refresh_enabled() -> None:
    cfg = AuthRefreshConfig(
        enabled=True,
        token_url="https://auth.example.internal/token",
        expires_buffer_seconds=120,
    )
    assert cfg.expires_buffer_seconds == 120


# ── ApiAdapterConfig ──────────────────────────────────────────────────────────

def _minimal_api_dict() -> dict:
    return {
        "endpoint": {"url": "https://api.example.internal/v1/chat"},
        "request_template": '{"messages":[{"role":"user","content":"${PAYLOAD}"}]}',
    }


def test_api_adapter_minimal() -> None:
    cfg = ApiAdapterConfig(**_minimal_api_dict())
    assert cfg.mode == "api"
    assert cfg.endpoint.url == "https://api.example.internal/v1/chat"
    assert "${PAYLOAD}" in cfg.request_template


def test_api_adapter_missing_endpoint() -> None:
    with pytest.raises(ValidationError):
        ApiAdapterConfig(request_template="{}}")


def test_api_adapter_missing_template() -> None:
    with pytest.raises(ValidationError):
        ApiAdapterConfig(endpoint={"url": "https://api.example.internal/"})


def test_api_adapter_full() -> None:
    d = _minimal_api_dict()
    d["headers"] = {"Authorization": "Bearer ${API_KEY}"}
    d["endpoint"]["streaming"] = True
    d["rate_limiting"] = {"max_retries": 5, "backoff_factor": 3.0}
    cfg = ApiAdapterConfig(**d)
    assert cfg.rate_limiting.max_retries == 5
    assert "Authorization" in cfg.headers


# ── load_api_adapter ──────────────────────────────────────────────────────────

def test_load_api_adapter_valid(tmp_path: Path) -> None:
    content = textwrap.dedent("""\
        endpoint:
          url: "https://api.example.internal/v1/chat"
        request_template: '{"messages":[{"role":"user","content":"${PAYLOAD}"}]}'
        headers:
          Content-Type: application/json
    """)
    p = tmp_path / "api_adapter.yaml"
    p.write_text(content)
    cfg = load_api_adapter(p)
    assert cfg.endpoint.url == "https://api.example.internal/v1/chat"


def test_load_api_adapter_missing_file() -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_api_adapter("/nonexistent/api_adapter.yaml")


def test_load_api_adapter_invalid(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("endpoint:\n  url: missing_template_field")
    with pytest.raises(ConfigurationError):
        load_api_adapter(p)


def test_load_example_api_adapter() -> None:
    example = Path(__file__).parent.parent / "examples" / "api_adapter.yaml"
    if example.exists():
        cfg = load_api_adapter(example)
        assert cfg.endpoint.url
        assert cfg.request_template
