"""Google Gemini judge provider — Phase 13."""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

GEMINI_MODELS = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]
DEFAULT_MODEL = "gemini-2.0-flash"
_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider:
    """Judge provider using the Google Gemini API.

    Parameters
    ----------
    api_key:
        Gemini API key from aistudio.google.com.
    model:
        Model ID. Defaults to gemini-2.0-flash (fastest).
    timeout:
        HTTP timeout in seconds.
    """

    NAME = "gemini"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("Gemini API key is required")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str) -> str:
        """Send prompt to Gemini and return the raw text response."""
        from llm_intruder.judge.rubric import SYSTEM_PROMPT
        if prompt.startswith(SYSTEM_PROMPT):
            user_part = prompt[len(SYSTEM_PROMPT):].strip()
        else:
            user_part = prompt

        url = f"{_BASE}/{self._model}:generateContent"
        try:
            resp = httpx.post(
                url,
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": self._api_key,
                },
                json={
                    "contents": [
                        {"role": "user", "parts": [{"text": user_part}]}
                    ],
                    "systemInstruction": {
                        "parts": [{"text": SYSTEM_PROMPT}]
                    },
                    "generationConfig": {
                        "temperature": 0.0,
                        "maxOutputTokens": 512,
                    },
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as exc:
            log.warning("gemini_judge_error", error=str(exc), model=self._model)
            raise
