"""Grok (xAI) judge provider — uses the xAI API with OpenAI-compatible interface.

xAI's Grok models are available at https://api.x.ai/v1 using a standard
OpenAI-compatible Chat Completions endpoint.

Get an API key at https://console.x.ai/
"""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

GROK_BASE = "https://api.x.ai/v1/chat/completions"

GROK_MODELS = [
    "grok-3-mini-beta",
    "grok-3-beta",
    "grok-2-1212",
    "grok-beta",
]

DEFAULT_MODEL = "grok-3-mini-beta"


class GrokProvider:
    """Judge provider using the xAI Grok API.

    Parameters
    ----------
    api_key:
        xAI API key from console.x.ai.
    model:
        Grok model ID. Defaults to grok-3-mini-beta (fast and cost-effective).
    timeout:
        HTTP timeout in seconds.
    """

    NAME = "grok"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("xAI API key is required (get one at console.x.ai)")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str) -> str:
        """Send prompt to Grok and return the raw text response."""
        from llm_intruder.judge.rubric import SYSTEM_PROMPT
        user_part = prompt[len(SYSTEM_PROMPT):].strip() if prompt.startswith(SYSTEM_PROMPT) else prompt

        try:
            resp = httpx.post(
                GROK_BASE,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "temperature": 0,
                    "max_tokens": 512,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": user_part},
                    ],
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            log.warning("grok_judge_error", error=str(exc), model=self._model)
            raise
