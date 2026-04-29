"""Anthropic Claude judge provider — Phase 13."""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

CLAUDE_MODELS = [
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-6",
    "claude-opus-4-6",
]
DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class ClaudeProvider:
    """Judge provider using the Anthropic Claude API.

    Parameters
    ----------
    api_key:
        Anthropic API key from console.anthropic.com.
    model:
        Model ID. Defaults to claude-haiku-4-5 (fastest, cheapest).
    timeout:
        HTTP timeout in seconds.
    """

    NAME = "claude"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("Anthropic API key is required")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._base_url = "https://api.anthropic.com/v1/messages"

    def is_available(self) -> bool:
        """Return True if the API key appears valid (non-empty)."""
        return bool(self._api_key)

    def generate(self, prompt: str) -> str:
        """Send prompt to Claude and return the raw text response."""
        # Split the rubric system prompt from the user turn
        # The prompt from rubric.py starts with SYSTEM_PROMPT then adds examples + trial
        # We send the first block as the system field and the rest as the user message
        from llm_intruder.judge.rubric import SYSTEM_PROMPT
        if prompt.startswith(SYSTEM_PROMPT):
            user_part = prompt[len(SYSTEM_PROMPT):].strip()
        else:
            user_part = prompt

        try:
            resp = httpx.post(
                self._base_url,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self._model,
                    "max_tokens": 512,
                    "temperature": 0,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_part}],
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]
        except Exception as exc:
            log.warning("claude_judge_error", error=str(exc), model=self._model)
            raise
