"""Async httpx API client — Phase 10 upgrade of the sync ApiClient.

Provides:
  - AsyncApiClient: async send with 429/backoff/JWT-refresh support
  - DryRunAsyncClient: zero-network simulated client for dry runs and tests
"""
from __future__ import annotations

import asyncio

import httpx
import structlog

from llm_intruder.api.models import ApiAdapterConfig
from llm_intruder.api.templating import (
    build_headers,
    build_request_body,
    extract_json_path,
    parse_ndjson_chunk,
    parse_sse_chunk,
)
from llm_intruder.resilience.backoff import RetryAfterBackoff
from llm_intruder.resilience.models import RetryConfig

log = structlog.get_logger()


class AsyncApiClient:
    """Async httpx client equivalent to the sync :class:`~llm_intruder.api.client.ApiClient`.

    Handles:

    * Non-streaming and SSE/NDJSON streaming responses
    * 429 / 502 / 503 / 504 retry with exponential backoff + full jitter
    * ``Retry-After`` header respect on 429
    * JWT token refresh in async context (non-blocking)

    Parameters
    ----------
    adapter:
        Validated :class:`~llm_intruder.api.models.ApiAdapterConfig`.
    variables:
        ``${VAR}`` substitution table.
    retry_config:
        Override default :class:`~llm_intruder.resilience.models.RetryConfig`.
    """

    def __init__(
        self,
        adapter: ApiAdapterConfig,
        variables: dict[str, str] | None = None,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.adapter = adapter
        self.variables: dict[str, str] = variables or {}
        self._current_token: str | None = None
        self._retry = retry_config or RetryConfig()
        self.last_retry_count: int = 0
        self._backoff = RetryAfterBackoff(
            factor=self._retry.backoff_factor,
            jitter=self._retry.jitter,
            max_seconds=self._retry.max_backoff_seconds,
        )

    # ── Public ────────────────────────────────────────────────────────────────

    async def send(self, payload: str) -> tuple[str, bool]:
        """Deliver *payload* asynchronously.

        Returns
        -------
        tuple[str, bool]
            ``(response_text, stream_detected)``
        """
        await self._maybe_refresh_token()

        headers = build_headers(self.adapter.headers, self._effective_variables())
        body = build_request_body(
            self.adapter.request_template, payload, self._effective_variables()
        )
        ep = self.adapter.endpoint

        self.last_retry_count = 0
        for attempt in range(self._retry.max_retries + 1):
            self.last_retry_count = attempt
            log.debug("async_api_send", attempt=attempt, url=ep.url)
            try:
                async with httpx.AsyncClient(timeout=ep.timeout_seconds) as client:
                    if ep.streaming:
                        text, streamed = await self._send_streaming(client, headers, body)
                    else:
                        text, streamed = await self._send_non_streaming(client, headers, body)

                log.info(
                    "async_api_response",
                    chars=len(text), streamed=streamed, attempt=attempt,
                )
                return text, streamed

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in self._retry.retry_on_status and attempt < self._retry.max_retries:
                    resp_headers = (
                        dict(exc.response.headers)
                        if self._retry.respect_retry_after else None
                    )
                    wait = self._backoff.wait_time(attempt, resp_headers)
                    log.warning(
                        "async_api_retry",
                        status=status, attempt=attempt, wait_s=round(wait, 2),
                    )
                    await asyncio.sleep(wait)
                    continue
                raise

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                if attempt < self._retry.max_retries:
                    wait = self._backoff.wait_time(attempt)
                    log.warning(
                        "async_api_timeout_retry",
                        attempt=attempt, wait_s=round(wait, 2),
                    )
                    await asyncio.sleep(wait)
                    continue
                raise

        return "", False  # pragma: no cover

    # ── Private ───────────────────────────────────────────────────────────────

    async def _send_non_streaming(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        body: str,
    ) -> tuple[str, bool]:
        ep = self.adapter.endpoint
        resp = await client.request(
            method=ep.method,
            url=ep.url,
            headers=headers,
            content=body.encode(),
        )
        resp.raise_for_status()
        text = extract_json_path(resp.json(), self.adapter.response_extraction.json_path)
        return text, False

    async def _send_streaming(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        body: str,
    ) -> tuple[str, bool]:
        ep = self.adapter.endpoint
        ext = self.adapter.response_extraction
        chunks: list[str] = []
        async with client.stream(
            method=ep.method,
            url=ep.url,
            headers=headers,
            content=body.encode(),
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if ep.stream_format == "sse":
                    chunk = parse_sse_chunk(line, ext.stream_delimiter, ext.stream_path)
                elif ep.stream_format == "ndjson":
                    chunk = parse_ndjson_chunk(line, ext.stream_path)
                else:
                    chunk = line
                if chunk:
                    chunks.append(chunk)
        return "".join(chunks), True

    async def _maybe_refresh_token(self) -> None:
        from llm_intruder.api.client import _token_needs_refresh

        cfg = self.adapter.auth_refresh
        if not cfg.enabled:
            return

        auth_header = self.adapter.headers.get("Authorization", "")
        token_part = auth_header.replace("Bearer ", "").replace("${CURRENT_TOKEN}", "")
        current = self._current_token or token_part.strip()

        if not _token_needs_refresh(current, cfg.expires_buffer_seconds):
            return

        log.info("async_jwt_refresh", token_url=cfg.token_url)
        refresh_tok = self.variables.get("REFRESH_TOKEN", cfg.refresh_token)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
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
                log.info("async_jwt_refresh_success")
        except Exception as exc:
            log.warning("async_jwt_refresh_failed", error=str(exc))

    def _effective_variables(self) -> dict[str, str]:
        ev = dict(self.variables)
        if self._current_token:
            ev["CURRENT_TOKEN"] = self._current_token
        return ev


# ── Dry-run simulated client ──────────────────────────────────────────────────

class DryRunAsyncClient:
    """Simulated async client that never makes real network calls.

    Returns a canned ``[DRY RUN]`` response immediately (with a minimal
    artificial delay) so the pool concurrency and evidence machinery can
    be exercised without a live target.

    Parameters
    ----------
    delay_seconds:
        Simulated per-request latency (default 0.001 s = 1 ms).
    fail_after:
        If set, raises an exception after this many successful sends
        (used to exercise error-handling paths in tests).
    """

    def __init__(
        self,
        delay_seconds: float = 0.001,
        fail_after: int | None = None,
    ) -> None:
        self._delay = delay_seconds
        self._fail_after = fail_after
        self._send_count = 0

    async def send(self, payload: str) -> tuple[str, bool]:
        """Return a canned response after ``delay_seconds``."""
        await asyncio.sleep(self._delay)
        self._send_count += 1
        if self._fail_after is not None and self._send_count > self._fail_after:
            raise RuntimeError(
                f"DryRunAsyncClient: simulated failure after {self._fail_after} sends"
            )
        return f"[DRY RUN] payload_len={len(payload)}", False
