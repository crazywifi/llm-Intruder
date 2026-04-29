"""LM Studio local judge provider (OpenAI-compatible API) — Phase 13."""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

DEFAULT_BASE_URL = "http://localhost:1234/v1"


class LMStudioProvider:
    """Judge provider using LM Studio's local OpenAI-compatible API.

    LM Studio exposes ``http://localhost:1234/v1`` as an OpenAI-compatible
    server. No API key is required. The model string must match the ID
    returned by ``GET /v1/models`` (including quantization suffix).

    Parameters
    ----------
    model:
        Model ID as returned by ``/v1/models``. Pass ``"auto"`` to use
        the first available loaded model.
    base_url:
        Override if LM Studio is running on a non-default port.
    timeout:
        HTTP timeout. Local models can be slow; default is 120 s.
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

    def is_available(self) -> bool:
        """Return True if LM Studio is running and has at least one model loaded."""
        try:
            resp = httpx.get(
                f"{self._base_url}/models", timeout=3.0
            )
            data = resp.json().get("data", [])
            return len(data) > 0
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return model IDs currently loaded in LM Studio."""
        try:
            resp = httpx.get(f"{self._base_url}/models", timeout=5.0)
            return [m["id"] for m in resp.json().get("data", [])]
        except Exception:
            return []

    def generate(self, prompt: str) -> str:
        """Send prompt to LM Studio and return the raw text response."""
        from llm_intruder.judge.rubric import SYSTEM_PROMPT
        if prompt.startswith(SYSTEM_PROMPT):
            user_part = prompt[len(SYSTEM_PROMPT):].strip()
        else:
            user_part = prompt

        model = self._resolve_model()
        try:
            resp = httpx.post(
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
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            log.warning("lmstudio_judge_error", error=str(exc), model=model)
            raise

    def _resolve_model(self) -> str:
        if self._model != "auto":
            return self._model
        if self._resolved_model:
            return self._resolved_model
        models = self.list_models()
        if not models:
            raise RuntimeError(
                "LM Studio has no models loaded. "
                "Open LM Studio and load a model first."
            )
        self._resolved_model = models[0]
        log.info("lmstudio_auto_model", model=self._resolved_model)
        return self._resolved_model
