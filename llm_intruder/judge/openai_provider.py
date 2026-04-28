"""OpenAI ChatGPT judge provider — Phase 13."""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

OPENAI_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"]
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider:
    """Judge provider using the OpenAI Chat Completions API.

    Parameters
    ----------
    api_key:
        OpenAI API key from platform.openai.com.
    model:
        Model ID. Defaults to gpt-4o-mini (cheapest capable model).
    base_url:
        Override for Azure OpenAI or other compatible endpoints.
    timeout:
        HTTP timeout in seconds.
    """

    NAME = "openai"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = "https://api.openai.com/v1/chat/completions",
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("OpenAI API key is required")
        self._api_key = api_key
        self._model = model
        self._base_url = base_url
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str) -> str:
        """Send prompt to OpenAI and return the raw text response."""
        from llm_intruder.judge.rubric import SYSTEM_PROMPT
        if prompt.startswith(SYSTEM_PROMPT):
            user_part = prompt[len(SYSTEM_PROMPT):].strip()
        else:
            user_part = prompt

        try:
            resp = httpx.post(
                self._base_url,
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
                        {"role": "user", "content": user_part},
                    ],
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            log.warning("openai_judge_error", error=str(exc), model=self._model)
            raise
