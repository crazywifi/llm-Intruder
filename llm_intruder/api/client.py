"""httpx-based API client with streaming, JWT refresh, and backoff retry.

Design
------
* Synchronous httpx — async upgrade arrives in Phase 10.
* All mutable state (current Bearer token, expiry) lives on the
  ``ApiClient`` instance so it survives across multiple ``send_payload``
  calls in a campaign.
* JWT decode is signature-free (we only read the ``exp`` claim to decide
  when to refresh — verification is the target API's job).
* request_body_type selects the wire format:
    json      → Content-Type: application/json  (default)
    multipart → Content-Type: multipart/form-data  (httpx files=)
    form      → Content-Type: application/x-www-form-urlencoded  (httpx data=)
    text      → Content-Type: text/plain
    xml       → Content-Type: application/xml
    graphql   → Content-Type: application/json  wraps query string in {"query":…}
    raw       → sends template bytes with no Content-Type override
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import structlog

from llm_intruder.api.models import ApiAdapterConfig, AuthRefreshConfig
from llm_intruder.api.templating import (
    build_headers,
    build_request_body,
    extract_json_path,
    parse_ndjson_chunk,
    parse_sse_chunk,
)

log = structlog.get_logger()

# Default assistant prefill when PrefillMutator is not used.
# Enough words to prime the model past its refusal gate.
_DEFAULT_ASSISTANT_PREFILL = (
    "Sure, I can help with that. Here's the information you requested:"
)


# ── JWT helpers ────────────────────────────────────────────────────────────────

def _jwt_exp(token: str) -> float | None:
    """Return the ``exp`` Unix timestamp from a JWT, or ``None`` on failure."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def _token_needs_refresh(token: str, buffer_seconds: int) -> bool:
    """Return True if the token expires within *buffer_seconds* from now."""
    exp = _jwt_exp(token)
    if exp is None:
        return False  # can't decode — assume still valid
    return time.time() >= (exp - buffer_seconds)


# ── Backoff retry ──────────────────────────────────────────────────────────────

def _backoff_seconds(attempt: int, factor: float) -> float:
    """Exponential backoff: ``factor^attempt`` seconds (capped at 60s)."""
    return min(factor ** attempt, 60.0)


# ── Body builder ───────────────────────────────────────────────────────────────

def _build_httpx_kwargs(body_str: str, body_type: str, headers: dict[str, str]) -> dict:
    """Return kwargs for httpx.request() based on *body_type*.

    Mutates *headers* in place to set the correct Content-Type when needed.
    Returns a dict with exactly one of: content, data, files.
    """
    bt = body_type.lower()

    if bt == "json":
        # Ensure Content-Type unless caller set it
        headers.setdefault("Content-Type", "application/json")
        return {"content": body_str.encode()}

    if bt in ("multipart", "form"):
        # Parse the template as a JSON object to get field name → value pairs
        try:
            field_map: dict[str, str] = json.loads(body_str)
        except json.JSONDecodeError:
            # Fallback: treat entire body as a single "payload" field
            field_map = {"payload": body_str}

        if bt == "multipart":
            # httpx files= sends multipart/form-data
            # Remove Content-Type so httpx sets the boundary automatically
            headers.pop("Content-Type", None)
            files = {k: (None, v) for k, v in field_map.items()}
            return {"files": files}
        else:
            # form → application/x-www-form-urlencoded
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return {"data": field_map}

    if bt == "text":
        headers.setdefault("Content-Type", "text/plain")
        # Send the body as-is.  Multi-line payloads (crescendo, many-shot, etc.)
        # rely on newlines to separate turns — stripping them silently corrupts
        # those strategies.  If the target rejects multi-line bodies, set
        # request_body_type: raw in the adapter and pre-collapse the template.
        return {"content": body_str.encode()}

    if bt == "xml":
        headers.setdefault("Content-Type", "application/xml")
        return {"content": body_str.encode()}

    if bt == "graphql":
        headers.setdefault("Content-Type", "application/json")
        wrapped = json.dumps({"query": body_str})
        return {"content": wrapped.encode()}

    if bt == "prefill":
        # Assistant-role prefill injection.
        #
        # Appends {"role": "assistant", "content": "<prefill_text>"} after the last
        # user message in a messages-style JSON body.  The model then completes from
        # the prefill rather than generating a refusal from scratch.
        #
        # Prefill text is extracted from a "[PREFILL:text]" prefix that
        # PrefillMutator embeds into the payload before template rendering.
        # If no prefix is present, a default starter is used.
        headers.setdefault("Content-Type", "application/json")
        try:
            body = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            # Not valid JSON — fall back to raw body delivery
            return {"content": body_str.encode()}

        messages: list = body.get("messages", [])

        # Only inject if the last message is NOT already from "assistant"
        if messages and messages[-1].get("role") != "assistant":
            # Extract prefill text from the last user message if PrefillMutator
            # embedded it as a "[PREFILL:text]" prefix inside the content value
            prefill_text = _DEFAULT_ASSISTANT_PREFILL
            last_content: str = messages[-1].get("content", "")
            prefix_end = last_content.find("]", last_content.find("[PREFILL:"))
            if last_content.startswith("[PREFILL:") and prefix_end != -1:
                prefill_text = last_content[9:prefix_end]  # extract between "[PREFILL:" and "]"
                # Remove the prefix marker from the user message
                messages[-1] = dict(messages[-1])
                messages[-1]["content"] = last_content[prefix_end + 1:]

            body["messages"] = messages + [
                {"role": "assistant", "content": prefill_text}
            ]
            log.debug("prefill_injected", prefill_preview=prefill_text[:60])

        return {"content": json.dumps(body).encode()}

    # raw — send as-is
    return {"content": body_str.encode()}


# ── Main client ────────────────────────────────────────────────────────────────

class ApiClient:
    """
    Stateful httpx client wrapping one ``api_adapter.yaml`` configuration.

    Parameters
    ----------
    adapter:
        Validated :class:`ApiAdapterConfig`.
    variables:
        ``${VAR}`` substitution table (API keys, system prompts, etc.).
    """

    def __init__(
        self,
        adapter: ApiAdapterConfig,
        variables: dict[str, str] | None = None,
    ) -> None:
        self.adapter = adapter
        self.variables: dict[str, str] = variables or {}
        self._current_token: str | None = None   # updated by JWT refresh
        proxy_url = getattr(adapter, 'proxy_url', None)
        verify_ssl = getattr(adapter, 'verify_ssl', True)
        client_kwargs: dict = {"timeout": adapter.endpoint.timeout_seconds}
        if proxy_url:
            client_kwargs["proxy"] = proxy_url   # httpx ≥0.24 uses 'proxy', not 'proxies'
            log.info("api_client_proxy", proxy=proxy_url, verify_ssl=verify_ssl)
            if not verify_ssl:
                log.warning("ssl_verification_disabled", note="TLS certificate validation is OFF — all certificates accepted")
        if not verify_ssl:
            client_kwargs["verify"] = False
        self._client = httpx.Client(**client_kwargs)

    def close(self) -> None:
        """Close the underlying httpx connection pool."""
        self._client.close()

    def __enter__(self) -> "ApiClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def send(self, payload: str) -> tuple[str, bool, str, str]:
        """
        Deliver *payload* to the configured endpoint.

        Returns ``(response_text, stream_detected, request_body, target_url)``.
        Handles retries internally on 429/503.
        """
        self._maybe_refresh_token()

        headers = build_headers(self.adapter.headers, self._effective_variables())

        # Truncate payload BEFORE template rendering so JSON structure stays valid
        max_len = getattr(self.adapter, "max_body_length", None)
        effective_payload = payload
        if max_len and len(payload) > max_len:
            effective_payload = payload[:max_len]
            log.debug("payload_truncated", original_len=len(payload), max_len=max_len)

        body_str = build_request_body(
            self.adapter.request_template, effective_payload, self._effective_variables()
        )
        body_type = self.adapter.request_body_type

        rl = self.adapter.rate_limiting
        ep = self.adapter.endpoint

        for attempt in range(rl.max_retries + 1):
            log.debug("api_send", attempt=attempt, url=ep.url)
            try:
                if ep.streaming:
                    text, streamed = self._send_streaming(headers, body_str, body_type)
                else:
                    text, streamed = self._send_non_streaming(headers, body_str, body_type)

                log.info(
                    "api_response",
                    chars=len(text),
                    streamed=streamed,
                    attempt=attempt,
                )
                return text, streamed, body_str, ep.url

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in rl.retry_on_status and attempt < rl.max_retries:
                    wait = _backoff_seconds(attempt, rl.backoff_factor)
                    log.warning(
                        "api_retry",
                        status=status,
                        attempt=attempt,
                        wait_s=wait,
                    )
                    time.sleep(wait)
                    continue
                raise  # re-raise on final attempt or non-retryable status

            except httpx.TimeoutException as exc:
                if attempt < rl.max_retries:
                    wait = _backoff_seconds(attempt, rl.backoff_factor)
                    log.warning("api_timeout_retry", attempt=attempt, wait_s=wait)
                    time.sleep(wait)
                    continue
                raise

        return "", False, "", ""  # pragma: no cover

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _effective_variables(self) -> dict[str, str]:
        """Merge caller-supplied variables with the current JWT token."""
        ev = dict(self.variables)
        if self._current_token:
            ev["CURRENT_TOKEN"] = self._current_token
        return ev

    def _send_non_streaming(
        self, headers: dict[str, str], body_str: str, body_type: str
    ) -> tuple[str, bool]:
        ep = self.adapter.endpoint
        # Build headers copy so _build_httpx_kwargs can mutate it
        h = dict(headers)
        kwargs = _build_httpx_kwargs(body_str, body_type, h)
        resp = self._client.request(
            method=ep.method,
            url=ep.url,
            headers=h,
            **kwargs,
        )
        resp.raise_for_status()
        # Try JSON extraction first; if response is not JSON, return text
        try:
            text = extract_json_path(resp.json(), self.adapter.response_extraction.json_path)
            if not text:
                # json_path returned empty — return full body as fallback
                text = resp.text
        except Exception:
            text = resp.text
        return text, False

    def _send_streaming(
        self, headers: dict[str, str], body_str: str, body_type: str
    ) -> tuple[str, bool]:
        ep = self.adapter.endpoint
        ext = self.adapter.response_extraction
        chunks: list[str] = []

        h = dict(headers)
        kwargs = _build_httpx_kwargs(body_str, body_type, h)

        with self._client.stream(
            method=ep.method,
            url=ep.url,
            headers=h,
            **kwargs,
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if ep.stream_format == "sse":
                    chunk = parse_sse_chunk(
                        line, ext.stream_delimiter, ext.stream_path
                    )
                elif ep.stream_format == "ndjson":
                    chunk = parse_ndjson_chunk(line, ext.stream_path)
                else:
                    chunk = line
                if chunk:
                    chunks.append(chunk)

        return "".join(chunks), True

    # ------------------------------------------------------------------
    # JWT refresh
    # ------------------------------------------------------------------

    def _maybe_refresh_token(self) -> None:
        cfg: AuthRefreshConfig = self.adapter.auth_refresh
        if not cfg.enabled:
            return

        auth_header = self.adapter.headers.get("Authorization", "")
        token_part = auth_header.replace("Bearer ", "").replace("${CURRENT_TOKEN}", "")
        current = self._current_token or token_part.strip()

        if not _token_needs_refresh(current, cfg.expires_buffer_seconds):
            return

        log.info("jwt_refresh", token_url=cfg.token_url)
        refresh_tok = self.variables.get("REFRESH_TOKEN", cfg.refresh_token)

        max_refresh_attempts = 3
        last_error: Exception | None = None
        for attempt in range(max_refresh_attempts):
            try:
                resp = self._client.post(
                    cfg.token_url,
                    json={"grant_type": "refresh_token", "refresh_token": refresh_tok},
                )
                resp.raise_for_status()
                data = resp.json()
                self._current_token = (
                    data.get("access_token")
                    or data.get("token")
                    or data.get("id_token")
                    or ""
                )
                log.info("jwt_refresh_success", attempt=attempt)
                return
            except Exception as exc:
                last_error = exc
                wait = _backoff_seconds(attempt, 2.0)
                log.warning(
                    "jwt_refresh_retry",
                    error=str(exc),
                    attempt=attempt,
                    wait_s=wait,
                )
                time.sleep(wait)

        log.error("jwt_refresh_failed_all_attempts", error=str(last_error))
        raise RuntimeError(
            f"JWT refresh failed after {max_refresh_attempts} attempts: {last_error}"
        )
