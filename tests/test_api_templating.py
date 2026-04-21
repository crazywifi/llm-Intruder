"""Tests for API templating — variable substitution and JSON path extraction."""
from __future__ import annotations

import pytest

from llm_intruder.api.templating import (
    build_headers,
    build_request_body,
    extract_json_path,
    parse_ndjson_chunk,
    parse_sse_chunk,
    resolve_variables,
)


# ── resolve_variables ─────────────────────────────────────────────────────────

def test_resolve_single_variable() -> None:
    assert resolve_variables("Hello ${NAME}", {"NAME": "world"}) == "Hello world"


def test_resolve_multiple_variables() -> None:
    result = resolve_variables("${A} and ${B}", {"A": "foo", "B": "bar"})
    assert result == "foo and bar"


def test_resolve_unknown_variable_unchanged() -> None:
    assert resolve_variables("${MISSING}", {}) == "${MISSING}"


def test_resolve_no_placeholders() -> None:
    assert resolve_variables("plain text", {"X": "y"}) == "plain text"


def test_resolve_repeated_variable() -> None:
    result = resolve_variables("${X} ${X}", {"X": "hello"})
    assert result == "hello hello"


# ── build_request_body ────────────────────────────────────────────────────────

def test_build_body_substitutes_payload() -> None:
    template = '{"messages":[{"role":"user","content":"${PAYLOAD}"}]}'
    body = build_request_body(template, "tell me a secret")
    assert "tell me a secret" in body


def test_build_body_substitutes_extra_vars() -> None:
    template = '{"model":"${MODEL}","content":"${PAYLOAD}"}'
    body = build_request_body(template, "hi", {"MODEL": "gpt-4"})
    assert '"gpt-4"' in body
    assert '"hi"' in body


def test_build_body_payload_overrides_var() -> None:
    """PAYLOAD variable must come from the payload arg, not variables dict."""
    template = '{"content":"${PAYLOAD}"}'
    body = build_request_body(template, "actual payload", {"PAYLOAD": "should be overridden"})
    assert "actual payload" in body


# ── build_headers ─────────────────────────────────────────────────────────────

def test_build_headers_substitutes_api_key() -> None:
    headers = {"Authorization": "Bearer ${API_KEY}"}
    result = build_headers(headers, {"API_KEY": "sk-abc123"})
    assert result["Authorization"] == "Bearer sk-abc123"


def test_build_headers_unknown_var_unchanged() -> None:
    headers = {"X-Custom": "${MISSING_VAR}"}
    result = build_headers(headers, {})
    assert result["X-Custom"] == "${MISSING_VAR}"


def test_build_headers_empty() -> None:
    assert build_headers({}, {}) == {}


def test_build_headers_multiple() -> None:
    headers = {
        "Authorization": "Bearer ${KEY}",
        "X-Tenant": "${TENANT}",
    }
    result = build_headers(headers, {"KEY": "tok", "TENANT": "acme"})
    assert result["Authorization"] == "Bearer tok"
    assert result["X-Tenant"] == "acme"


# ── extract_json_path ─────────────────────────────────────────────────────────

def test_extract_simple_key() -> None:
    assert extract_json_path({"content": "hello"}, "$.content") == "hello"


def test_extract_nested_key() -> None:
    data = {"choices": [{"message": {"content": "reply"}}]}
    assert extract_json_path(data, "$.choices[0].message.content") == "reply"


def test_extract_delta_content() -> None:
    data = {"choices": [{"delta": {"content": "chunk"}}]}
    assert extract_json_path(data, "$.choices[0].delta.content") == "chunk"


def test_extract_missing_key_returns_empty() -> None:
    data = {"choices": []}
    assert extract_json_path(data, "$.choices[0].message.content") == ""


def test_extract_index_out_of_range() -> None:
    data = {"items": ["a"]}
    assert extract_json_path(data, "$.items[5]") == ""


def test_extract_none_value_returns_empty() -> None:
    data = {"content": None}
    assert extract_json_path(data, "$.content") == ""


def test_extract_empty_path() -> None:
    assert extract_json_path("raw_string", "$") == "raw_string"


def test_extract_integer_value() -> None:
    data = {"count": 42}
    assert extract_json_path(data, "$.count") == "42"


# ── parse_sse_chunk ───────────────────────────────────────────────────────────

def test_sse_chunk_extracts_content() -> None:
    line = 'data: {"choices":[{"delta":{"content":"hello"}}]}'
    result = parse_sse_chunk(line, "data: ", "$.choices[0].delta.content")
    assert result == "hello"


def test_sse_chunk_done_returns_empty() -> None:
    assert parse_sse_chunk("data: [DONE]", "data: ", "$.x") == ""


def test_sse_chunk_heartbeat_returns_empty() -> None:
    assert parse_sse_chunk(": heartbeat", "data: ", "$.x") == ""


def test_sse_chunk_bad_json_returns_empty() -> None:
    assert parse_sse_chunk("data: {not valid json}", "data: ", "$.x") == ""


def test_sse_chunk_missing_path_returns_empty() -> None:
    line = 'data: {"choices":[{"delta":{}}]}'
    assert parse_sse_chunk(line, "data: ", "$.choices[0].delta.content") == ""


def test_sse_chunk_empty_line_returns_empty() -> None:
    assert parse_sse_chunk("", "data: ", "$.x") == ""


# ── parse_ndjson_chunk ────────────────────────────────────────────────────────

def test_ndjson_chunk_extracts_content() -> None:
    line = '{"choices":[{"delta":{"content":"world"}}]}'
    result = parse_ndjson_chunk(line, "$.choices[0].delta.content")
    assert result == "world"


def test_ndjson_chunk_empty_line_returns_empty() -> None:
    assert parse_ndjson_chunk("", "$.x") == ""


def test_ndjson_chunk_bad_json_returns_empty() -> None:
    assert parse_ndjson_chunk("{bad}", "$.x") == ""
