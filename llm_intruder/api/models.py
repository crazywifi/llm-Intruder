"""Pydantic v2 models for api_adapter.yaml — API Driver configuration."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EndpointConfig(BaseModel):
    url: str
    method: Literal["GET", "POST", "PUT", "PATCH"] = "POST"
    streaming: bool = False
    stream_format: Literal["sse", "ndjson", "none"] = "sse"
    timeout_seconds: float = 60.0


class ResponseExtractionConfig(BaseModel):
    """JSONPath-style paths to pull the model text out of the response body."""
    json_path: str = "$.choices[0].message.content"   # non-streaming
    stream_path: str = "$.choices[0].delta.content"   # per-chunk in streaming
    stream_delimiter: str = "data: "                  # prefix stripped before JSON parse


class RateLimitConfig(BaseModel):
    requests_per_minute: int = 60
    retry_on_status: list[int] = Field(default_factory=lambda: [429, 503])
    backoff_factor: float = 2.0
    max_retries: int = 3


class AuthRefreshConfig(BaseModel):
    """Optional JWT token refresh before the token expires."""
    enabled: bool = False
    token_url: str = ""
    refresh_token: str = ""          # may contain ${REFRESH_TOKEN} placeholder
    expires_buffer_seconds: int = 60  # refresh this many seconds before expiry


class ApiAdapterConfig(BaseModel):
    """Root model for api_adapter.yaml.

    request_body_type controls how the request body is sent:
      json       — Content-Type: application/json  (default, current behaviour)
      multipart  — Content-Type: multipart/form-data  (httpx files= param)
      form       — Content-Type: application/x-www-form-urlencoded
      text       — Content-Type: text/plain
      xml        — Content-Type: application/xml
      graphql    — Content-Type: application/json  (wraps in {"query":...})
      raw        — no Content-Type override; sends request_template bytes as-is

    For multipart / form types the request_template should be a JSON object
    whose keys become form field names and values (with ${PAYLOAD} substituted)
    become field values.  Example::

        request_body_type: multipart
        request_template: |
          {
            "defender": "baseline",
            "prompt": "${PAYLOAD}"
          }

    For graphql the request_template should be the GraphQL query string
    (with ${PAYLOAD} substituted into it), which will be wrapped as::

        {"query": "<template>"}
    """
    mode: Literal["api"] = "api"
    endpoint: EndpointConfig
    headers: dict[str, str] = Field(default_factory=dict)
    request_template: str            # body template; ${PAYLOAD} is substituted
    request_body_type: Literal[
        "json", "multipart", "form", "text", "xml", "graphql", "raw", "prefill"
    ] = "json"
    # prefill: Like json but auto-appends an {"role":"assistant","content":"..."} message
    # after the last user message, bypassing refusal-generation entirely.
    # The assistant prefill text is extracted from the ${PAYLOAD} string when the
    # PrefillMutator is used (prefix format: "[PREFILL:text]actual_payload").
    # Without PrefillMutator, a default starter is used. Only works on APIs that
    # support an assistant role in the messages array (OpenAI-compatible, Anthropic).
    response_extraction: ResponseExtractionConfig = Field(
        default_factory=ResponseExtractionConfig
    )
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    auth_refresh: AuthRefreshConfig = Field(default_factory=AuthRefreshConfig)
    proxy_url: str | None = Field(default=None, description="HTTP proxy URL e.g. http://127.0.0.1:8080 (Burp Suite)")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates. Set False when using Burp proxy (self-signed cert).")
    max_body_length: int | None = Field(default=None, description="Truncate request body to this many characters before sending. Use when the target API enforces a hard input length limit (e.g. 150 chars).")
