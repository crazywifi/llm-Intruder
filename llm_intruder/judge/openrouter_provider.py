"""OpenRouter judge provider — routes to hundreds of models via one API key.

OpenRouter (https://openrouter.ai) is an OpenAI-compatible gateway that
aggregates 200+ models including many free-tier options.  A single API key
gives access to GPT-4o, Claude, Gemini, Llama, Mistral, and more.

Free-tier models (no billing required, rate-limited):
  meta-llama/llama-3.3-70b-instruct:free
  meta-llama/llama-3.2-3b-instruct:free
  google/gemma-3-4b-it:free
  mistralai/mistral-7b-instruct:free
  qwen/qwen-2.5-72b-instruct:free
  deepseek/deepseek-r1:free
  deepseek/deepseek-chat-v3-0324:free

Get a free API key at https://openrouter.ai/keys
"""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()

OPENROUTER_BASE = "https://openrouter.ai/api/v1/chat/completions"

OPENROUTER_MODELS = [
    # Free models (no cost)
    "meta-llama/llama-3.3-70b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "google/gemma-3-4b-it:free",
    "mistralai/mistral-7b-instruct:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "deepseek/deepseek-r1:free",
    "deepseek/deepseek-chat-v3-0324:free",
    # Paid models
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "anthropic/claude-3.5-haiku",
    "anthropic/claude-sonnet-4-5",
    "google/gemini-2.0-flash-001",
    "mistralai/mistral-large",
    "x-ai/grok-3-mini-beta",
]

DEFAULT_MODEL = "meta-llama/llama-3.3-70b-instruct:free"


class OpenRouterProvider:
    """Judge provider using OpenRouter's OpenAI-compatible API.

    Parameters
    ----------
    api_key:
        OpenRouter API key (free at openrouter.ai/keys).
    model:
        Any model slug from openrouter.ai/models — defaults to Llama 3.3 70B
        free tier which is capable enough for security verdict judgment.
    timeout:
        HTTP timeout in seconds.
    """

    NAME = "openrouter"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise ValueError("OpenRouter API key is required (get one free at openrouter.ai/keys)")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def is_available(self) -> bool:
        return bool(self._api_key)

    def generate(self, prompt: str) -> str:
        """Send prompt to OpenRouter and return the raw text response."""
        from llm_intruder.judge.rubric import SYSTEM_PROMPT
        user_part = prompt[len(SYSTEM_PROMPT):].strip() if prompt.startswith(SYSTEM_PROMPT) else prompt

        try:
            resp = httpx.post(
                OPENROUTER_BASE,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://llm-intruder.io",
                    "X-Title": "LLM-Intruder",
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
            log.warning("openrouter_judge_error", error=str(exc), model=self._model)
            raise
