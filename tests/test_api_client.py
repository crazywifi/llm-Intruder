"""Tests for ApiClient — httpx interactions (mocked), JWT refresh, backoff."""
from __future__ import annotations

import base64
import json
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from llm_intruder.api.client import ApiClient, _backoff_seconds, _jwt_exp, _token_needs_refresh
from llm_intruder.api.models import (
    ApiAdapterConfig,
    AuthRefreshConfig,
    EndpointConfig,
    RateLimitConfig,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_adapter(
    streaming: bool = False,
    stream_format: str = "sse",
    max_retries: int = 0,
    auth_refresh: bool = False,
    retry_on_status: list[int] | None = None,
) -> ApiAdapterConfig:
    return ApiAdapterConfig(
        endpoint=EndpointConfig(
            url="https://api.example.internal/v1/chat",
            streaming=streaming,
            stream_format=stream_format,  # type: ignore[arg-type]
            timeout_seconds=5.0,
        ),
        headers={"Authorization": "Bearer ${API_KEY}", "Content-Type": "application/json"},
        request_template='{"messages":[{"role":"user","content":"${PAYLOAD}"}]}',
        rate_limiting=RateLimitConfig(
            max_retries=max_retries,
            backoff_factor=0.01,  # tiny backoff for tests
            retry_on_status=retry_on_status or [429, 503],
        ),
        auth_refresh=AuthRefreshConfig(enabled=auth_refresh),
    )


def _make_jwt(exp: float) -> str:
    """Create a minimal unsigned JWT with the given exp claim."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload_data = json.dumps({"exp": exp}).encode()
    payload = base64.urlsafe_b64encode(payload_data).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


def _mock_response(json_data: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status}",
            request=MagicMock(),
            response=MagicMock(status_code=status),
        )
    return resp


# ── _backoff_seconds ──────────────────────────────────────────────────────────

def test_backoff_attempt_0() -> None:
    assert _backoff_seconds(0, 2.0) == pytest.approx(1.0)


def test_backoff_attempt_1() -> None:
    assert _backoff_seconds(1, 2.0) == pytest.approx(2.0)


def test_backoff_attempt_2() -> None:
    assert _backoff_seconds(2, 2.0) == pytest.approx(4.0)


def test_backoff_capped_at_60() -> None:
    assert _backoff_seconds(100, 2.0) == 60.0


# ── _jwt_exp ──────────────────────────────────────────────────────────────────

def test_jwt_exp_returns_timestamp() -> None:
    future = time.time() + 3600
    token = _make_jwt(future)
    exp = _jwt_exp(token)
    assert exp == pytest.approx(future, abs=1)


def test_jwt_exp_invalid_token() -> None:
    assert _jwt_exp("not.a.jwt") is None


def test_jwt_exp_two_parts() -> None:
    assert _jwt_exp("only.twoparts") is None


# ── _token_needs_refresh ──────────────────────────────────────────────────────

def test_token_not_expired() -> None:
    token = _make_jwt(time.time() + 3600)
    assert _token_needs_refresh(token, 60) is False


def test_token_expires_within_buffer() -> None:
    token = _make_jwt(time.time() + 30)  # expires in 30s
    assert _token_needs_refresh(token, 60) is True  # buffer is 60s


def test_token_already_expired() -> None:
    token = _make_jwt(time.time() - 10)
    assert _token_needs_refresh(token, 60) is True


def test_token_undecodable_assumed_valid() -> None:
    assert _token_needs_refresh("garbage.token.here", 60) is False


# ── Non-streaming send ────────────────────────────────────────────────────────

def test_non_streaming_extracts_json_path() -> None:
    adapter = _make_adapter(streaming=False)
    client = ApiClient(adapter=adapter, variables={"API_KEY": "test-key"})

    response_data = {"choices": [{"message": {"content": "The model replied."}}]}
    mock_resp = _mock_response(response_data)

    with patch("httpx.Client.request", return_value=mock_resp):
        text, streamed = client.send("hello")

    assert text == "The model replied."
    assert streamed is False


def test_non_streaming_substitutes_api_key_in_headers() -> None:
    adapter = _make_adapter(streaming=False)
    client = ApiClient(adapter=adapter, variables={"API_KEY": "sk-abc"})

    mock_resp = _mock_response({"choices": [{"message": {"content": "ok"}}]})
    captured_headers: dict = {}

    def _mock_request(method, url, headers, content, **kw):
        captured_headers.update(headers)
        return mock_resp

    with patch("httpx.Client.request", side_effect=_mock_request):
        client.send("test")

    assert captured_headers.get("Authorization") == "Bearer sk-abc"


# ── SSE streaming send ────────────────────────────────────────────────────────

def test_sse_streaming_joins_chunks() -> None:
    adapter = _make_adapter(streaming=True, stream_format="sse")
    client = ApiClient(adapter=adapter, variables={"API_KEY": "key"})

    sse_lines = [
        'data: {"choices":[{"delta":{"content":"Hello"}}]}',
        'data: {"choices":[{"delta":{"content":" world"}}]}',
        "data: [DONE]",
    ]

    mock_stream = MagicMock()
    mock_stream.__enter__ = MagicMock(return_value=mock_stream)
    mock_stream.__exit__ = MagicMock(return_value=False)
    mock_stream.iter_lines.return_value = iter(sse_lines)
    mock_stream.raise_for_status = MagicMock()
    mock_stream.status_code = 200

    with patch("httpx.Client.stream", return_value=mock_stream):
        text, streamed = client.send("say hello")

    assert text == "Hello world"
    assert streamed is True


def test_ndjson_streaming_joins_chunks() -> None:
    adapter = _make_adapter(streaming=True, stream_format="ndjson")
    client = ApiClient(adapter=adapter, variables={"API_KEY": "key"})

    ndjson_lines = [
        '{"choices":[{"delta":{"content":"Foo"}}]}',
        '{"choices":[{"delta":{"content":"Bar"}}]}',
    ]

    mock_stream = MagicMock()
    mock_stream.__enter__ = MagicMock(return_value=mock_stream)
    mock_stream.__exit__ = MagicMock(return_value=False)
    mock_stream.iter_lines.return_value = iter(ndjson_lines)
    mock_stream.raise_for_status = MagicMock()
    mock_stream.status_code = 200

    with patch("httpx.Client.stream", return_value=mock_stream):
        text, streamed = client.send("test")

    assert text == "FooBar"
    assert streamed is True


# ── Retry / backoff ───────────────────────────────────────────────────────────

def test_retry_on_429_then_success() -> None:
    adapter = _make_adapter(streaming=False, max_retries=2)
    client = ApiClient(adapter=adapter, variables={"API_KEY": "key"})

    success_resp = _mock_response({"choices": [{"message": {"content": "ok"}}]})
    fail_resp = _mock_response({}, status=429)

    call_count = {"n": 0}
    def _mock_request(*args, **kwargs):
        call_count["n"] += 1
        return fail_resp if call_count["n"] == 1 else success_resp

    with patch("httpx.Client.request", side_effect=_mock_request):
        text, _ = client.send("test")

    assert text == "ok"
    assert call_count["n"] == 2


def test_all_retries_exhausted_raises() -> None:
    adapter = _make_adapter(streaming=False, max_retries=1, retry_on_status=[429])
    client = ApiClient(adapter=adapter, variables={"API_KEY": "key"})

    fail_resp = _mock_response({}, status=429)

    with patch("httpx.Client.request", return_value=fail_resp):
        with pytest.raises(httpx.HTTPStatusError):
            client.send("test")


def test_non_retryable_status_raises_immediately() -> None:
    adapter = _make_adapter(streaming=False, max_retries=3, retry_on_status=[429])
    client = ApiClient(adapter=adapter, variables={"API_KEY": "key"})

    fail_resp = _mock_response({}, status=401)  # 401 not in retry list
    call_count = {"n": 0}

    def _mock_request(*args, **kwargs):
        call_count["n"] += 1
        return fail_resp

    with patch("httpx.Client.request", side_effect=_mock_request):
        with pytest.raises(httpx.HTTPStatusError):
            client.send("test")

    assert call_count["n"] == 1  # no retry for 401
