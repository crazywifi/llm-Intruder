"""Auto-detect Ollama and LM Studio local LLM servers."""
from __future__ import annotations

import asyncio

import httpx

from llm_intruder.dashboard.models import LocalLLMStatus

OLLAMA_URL = "http://localhost:11434"
LMSTUDIO_URL = "http://localhost:1234"

_TIMEOUT = 2.0  # seconds


async def _check_ollama() -> tuple[bool, list[str]]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            if r.status_code == 200:
                data = r.json()
                models = [m["name"] for m in data.get("models", [])]
                return True, models
    except Exception:
        pass
    return False, []


async def _check_lmstudio() -> tuple[bool, list[str]]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(f"{LMSTUDIO_URL}/v1/models")
            if r.status_code == 200:
                data = r.json()
                models = [m["id"] for m in data.get("data", [])]
                return True, models
    except Exception:
        pass
    return False, []


async def probe_local_llms() -> LocalLLMStatus:
    ollama_ok, ollama_models = await _check_ollama()
    lmstudio_ok, lmstudio_models = await _check_lmstudio()
    return LocalLLMStatus(
        ollama_available=ollama_ok,
        ollama_models=ollama_models,
        lmstudio_available=lmstudio_ok,
        lmstudio_models=lmstudio_models,
    )
