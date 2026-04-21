"""API Driver — thin orchestration layer over ApiClient.

Returns the same :class:`~llm_intruder.browser.models.CapturedResponse` type
as the Browser Driver so the rest of the pipeline is mode-agnostic.
"""
from __future__ import annotations

import structlog

from llm_intruder.api.client import ApiClient
from llm_intruder.api.models import ApiAdapterConfig
from llm_intruder.browser.models import CapturedResponse
from llm_intruder.core.audit_log import sha256

log = structlog.get_logger()


class ApiDriver:
    """
    Delivers payloads via direct HTTP/SSE and returns a :class:`CapturedResponse`.

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
        self._client = ApiClient(adapter=adapter, variables=variables)

    def send_payload(self, payload: str) -> CapturedResponse:
        """Send *payload* and return a :class:`CapturedResponse`."""
        log.info("api_driver_send", chars=len(payload), url=self.adapter.endpoint.url)
        text, streamed, request_body, target_url = self._client.send(payload)
        return CapturedResponse(
            text=text,
            stream_detected=streamed,
            was_wiped=False,       # APIs don't wipe DOM text
            payload_hash=sha256(payload),
            response_hash=sha256(text),
            request_body=request_body,
            target_url=target_url,
        )
