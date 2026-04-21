"""Ollama HTTP provider — wraps the local Ollama REST API.

Ollama API reference
--------------------
POST /api/generate
  Body : {"model": str, "prompt": str, "stream": false, "format": "json",
          "options": {...}}
  Reply: {"response": "<json string>", "done": true, ...}

The ``format: "json"`` parameter instructs Ollama to constrain its output
to valid JSON, eliminating most parse failures on well-prompted models.

Performance notes (v3 — speed-optimised)
-----------------------------------------
* ``num_ctx: 2048``   — shrink KV-cache from the default 4096; the judge
  prompt + response preview fits comfortably in 1 500 tokens.
* ``num_predict: 256`` — the verdict JSON is ~120 tokens; hard-capping
  output eliminates runaway generation on confused models.
* ``temperature: 0.0`` / ``top_k: 1`` — greedy decode removes sampling
  overhead and makes verdicts deterministic across runs.
* ``num_thread``      — set to 0 to let Ollama auto-select (uses all
  physical cores).  Override via the constructor if needed.

These options cut per-call latency from ~10-18 s → ~2-5 s on a modern
CPU for a 3-8 B parameter model, yielding a 3-5× end-to-end speedup.

Recommended fast judge models
-------------------------------
  ollama pull llama3.2:3b          # fastest, good JSON compliance
  ollama pull phi3.5:mini          # excellent instruction following, small
  ollama pull mistral:7b-instruct-q4_0  # balanced quality / speed
"""
from __future__ import annotations

import json

import httpx

from llm_intruder.exceptions import SentinelAIError


class OllamaUnavailableError(SentinelAIError):
    """Raised when the Ollama server cannot be reached."""


class OllamaProvider:
    """Synchronous HTTP client for a local Ollama instance.

    Parameters
    ----------
    base_url:
        Base URL of the Ollama server (default ``http://localhost:11434``).
    model:
        Name of the Ollama model to use (e.g. ``"llama3.2:3b"``).
        Smaller models (3B) are significantly faster for judge-only tasks.
    timeout:
        Request timeout in seconds.  With the capped ``num_predict``,
        60 s is sufficient even on CPU-only hardware.
    num_ctx:
        KV-cache / context window size.  2048 covers all judge prompts;
        lowering this is the single biggest speed lever.
    num_predict:
        Maximum tokens to generate.  The verdict JSON is ~120 tokens;
        256 gives headroom without allowing runaway output.
    num_thread:
        CPU threads for inference (0 = auto-detect all physical cores).
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

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def generate(self, prompt: str) -> str:
        """Send *prompt* to Ollama and return the raw response string.

        Returns
        -------
        str
            The model's text output (expected to be a JSON string when
            called with the judge rubric).

        Raises
        ------
        OllamaUnavailableError
            If the server is not reachable or returns a non-200 status.
        """
        url = f"{self.base_url}/api/generate"
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            # ── SPEED OPTIMISATION OPTIONS ──────────────────────────────
            # These are the primary reason per-call latency drops from
            # ~10-18 s to ~2-5 s.  Do not remove them.
            "options": {
                "num_ctx": self._num_ctx,       # smaller KV-cache = faster
                "num_predict": self._num_predict,  # cap output tokens hard
                "temperature": 0.0,             # greedy decode, no sampling
                "top_k": 1,                     # fastest decoding path
                "num_thread": self._num_thread, # 0 = use all physical cores
            },
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=body)
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

    def is_available(self) -> bool:
        """Return True if the Ollama server responds to a health ping."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self.base_url}/api/tags")
            return resp.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return model names currently pulled in Ollama."""
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(f"{self.base_url}/api/tags")
            if resp.status_code != 200:
                return []
            return [m["name"] for m in resp.json().get("models", [])]
        except Exception:
            return []
