"""Async Ollama HTTP provider — wraps the local Ollama REST API with asyncio.

Drop-in async companion to OllamaProvider. Used by the concurrent backfill
engine to fan out multiple judge calls in parallel, drastically reducing
wall-clock time when judging many pending trials.

Performance notes (v3 — speed-optimised)
-----------------------------------------
Same ``options`` block as the sync provider:

* ``num_ctx: 2048``    — smaller KV-cache, biggest single speed win.
* ``num_predict: 256`` — caps output; verdict JSON is ~120 tokens.
* ``temperature: 0.0`` / ``top_k: 1`` — greedy decode, deterministic.
* ``num_thread: 0``    — auto-select all physical cores.

Combined with the concurrent backfill engine (workers=4, set
OLLAMA_NUM_PARALLEL=4 before starting Ollama), these options bring
500 trials from ~90 min down to ~8-15 min on CPU hardware.

Usage (internal)
----------------
    provider = AsyncOllamaProvider(model="llama3.2:3b")
    verdict_str = await provider.generate(prompt)

Parallel setup
--------------
Before starting Ollama set:
    export OLLAMA_NUM_PARALLEL=4
    ollama serve

Then pass workers=4 to backfill_verdicts_concurrent().
"""
from __future__ import annotations

import httpx

from llm_intruder.exceptions import SentinelAIError


class OllamaUnavailableError(SentinelAIError):
    """Raised when the Ollama server cannot be reached."""


class AsyncOllamaProvider:
    """Async HTTP client for a local Ollama instance.

    Shares the same interface as OllamaProvider but exposes an async
    ``generate`` coroutine so it can be awaited inside asyncio tasks.

    Parameters
    ----------
    base_url:
        Base URL of the Ollama server (default ``http://localhost:11434``).
    model:
        Name of the Ollama model to use (e.g. ``"llama3.2:3b"``).
        Smaller models are significantly faster for judge-only workloads.
    timeout:
        HTTP timeout in seconds.  With capped ``num_predict``, 60 s is
        sufficient even on CPU-only hardware.
    num_ctx:
        KV-cache / context window size (default 2048).
    num_predict:
        Maximum tokens to generate (default 256).
    num_thread:
        CPU threads for inference (0 = auto, recommended).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2:3b",
        timeout: float = 60.0,
        num_ctx: int = 2048,
        num_predict: int = 256,
        num_thread: int = 0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._num_ctx = num_ctx
        self._num_predict = num_predict
        self._num_thread = num_thread

    async def generate(self, prompt: str) -> str:
        """Send *prompt* to Ollama asynchronously and return the raw response.

        Returns
        -------
        str
            The model's text output (expected to be JSON for judge calls).

        Raises
        ------
        OllamaUnavailableError
            If the server is unreachable or returns a non-200 status.
        """
        url = f"{self.base_url}/api/generate"
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            # ── SPEED OPTIMISATION OPTIONS ──────────────────────────────
            "options": {
                "num_ctx": self._num_ctx,
                "num_predict": self._num_predict,
                "temperature": 0.0,
                "top_k": 1,
                "num_thread": self._num_thread,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=body)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            raise OllamaUnavailableError(
                f"Cannot reach Ollama at {self.base_url}: {exc}"
            ) from exc

        if resp.status_code != 200:
            raise OllamaUnavailableError(
                f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        try:
            data = resp.json()
        except Exception as exc:
            raise OllamaUnavailableError(
                f"Ollama response is not valid JSON: {exc}"
            ) from exc

        return data.get("response", "")

    async def is_available(self) -> bool:
        """Return True if the Ollama server responds to a health ping."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
            return resp.status_code == 200
        except Exception:
            return False
