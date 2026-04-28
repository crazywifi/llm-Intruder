"""Async LM Studio judge provider (OpenAI-compatible API).

Drop-in async companion to LMStudioProvider. Used by the concurrent backfill
engine to fan out multiple judge calls in parallel, matching the speedup
already available for Ollama via AsyncOllamaProvider.

Performance notes
-----------------
* Uses ``httpx.AsyncClient`` for true async HTTP — all ``workers`` requests
  are in-flight simultaneously, limited only by LM Studio's own concurrency.
* LM Studio's default server handles at least 1-2 parallel requests; for
  more, increase the server's context slots in the LM Studio UI settings.
* Recommended workers: 2-4 (test with your hardware).

Parallel setup
--------------
In LM Studio > Server settings, increase "Context overflow policy" and
enable GPU layers to maximise throughput per request.

Usage (internal — called by cli.py)
------------------------------------
    from llm_intruder.judge.lmstudio_provider_async import AsyncLMStudioProvider
    provider = AsyncLMStudioProvider(model="auto")
    summary = backfill_verdicts_concurrent(
        provider=provider,
        db_session=session,
        engagement_id=config.engagement_id,
        workers=2,
    )
"""
from __future__ import annotations

import httpx
import structlog

from llm_intruder.judge.rubric import SYSTEM_PROMPT

log = structlog.get_logger()

DEFAULT_BASE_URL = "http://localhost:1234/v1"


class AsyncLMStudioProvider:
    """Async judge provider using LM Studio's local OpenAI-compatible API.

    Parameters
    ----------
    model:
        Model ID as returned by ``/v1/models``. Pass ``"auto"`` to pick
        the first available loaded model.
    base_url:
        Override if LM Studio is running on a non-default port.
    timeout:
        HTTP timeout in seconds. Default 120 s — local models can be slow.
    """

    NAME = "lmstudio"

    def __init__(
        self,
        model: str = "auto",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 120.0,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._resolved_model: str | None = None

    async def generate(self, prompt: str) -> str:
        """Send *prompt* to LM Studio asynchronously and return the raw response."""
        if prompt.startswith(SYSTEM_PROMPT):
            user_part = prompt[len(SYSTEM_PROMPT):].strip()
        else:
            user_part = prompt

        model = await self._resolve_model()
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers={"Content-Type": "application/json"},
                json={
                    "model": model,
                    "temperature": 0.0,
                    "max_tokens": 512,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_part},
                    ],
                },
            )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]

    async def is_available(self) -> bool:
        """Return True if LM Studio is running and has at least one model loaded."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self._base_url}/models")
            return len(resp.json().get("data", [])) > 0
        except Exception:
            return False

    async def _resolve_model(self) -> str:
        if self._model != "auto":
            return self._model
        if self._resolved_model:
            return self._resolved_model
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{self._base_url}/models")
        models = [m["id"] for m in resp.json().get("data", [])]
        if not models:
            raise RuntimeError(
                "LM Studio has no models loaded. "
                "Open LM Studio and load a model first."
            )
        self._resolved_model = models[0]
        log.info("lmstudio_async_auto_model", model=self._resolved_model)
        return self._resolved_model
