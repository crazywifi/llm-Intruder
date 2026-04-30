"""ModelDriver — test LLM models directly via their native SDK or API.

This is how tools like Garak and PyRIT work — they call the model's API directly
instead of going through a web UI or a custom HTTP endpoint.

Supported providers
-------------------
openai      → openai Python SDK (pip install openai)
anthropic   → anthropic Python SDK (pip install anthropic)
ollama      → direct HTTP to localhost Ollama server (no extra install)
gemini      → google-generativeai SDK (pip install google-generativeai)
huggingface → HuggingFace Inference API (pip install huggingface_hub)

All providers return the same CapturedResponse so the rest of the pipeline
(HuntRunner, ConversationSession, ResponseClassifier) works unchanged.

model_adapter.yaml example
--------------------------
    mode: model
    provider: openai
    model: gpt-4o
    system_prompt: "You are a helpful assistant."
    api_key: ${OPENAI_API_KEY}
    temperature: 0.7
    max_tokens: 1024

For providers without an api_key (local Ollama):
    mode: model
    provider: ollama
    model: llama3.2:3b
    base_url: http://localhost:11434
    system_prompt: "You are a helpful assistant."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from llm_intruder.browser.models import CapturedResponse
from llm_intruder.core.audit_log import sha256

log = structlog.get_logger()


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class ModelAdapterConfig:
    """Configuration for direct LLM model testing."""
    provider: str                          # openai | anthropic | ollama | gemini | huggingface
    model: str                             # e.g. gpt-4o, claude-3-5-sonnet-20241022
    system_prompt: str = ""
    api_key: str = ""                      # may be empty for local models
    base_url: str = ""                     # for ollama or custom endpoints
    temperature: float = 0.7
    max_tokens: int = 1024
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, data: dict, variables: dict[str, str] | None = None) -> "ModelAdapterConfig":
        """Load from a parsed YAML dict, substituting ${VAR} placeholders."""
        import re
        vars_ = variables or {}

        def sub(val: str) -> str:
            return re.sub(
                r"\$\{(\w+)\}",
                lambda m: vars_.get(m.group(1), m.group(0)),
                val,
            )

        return cls(
            provider=data.get("provider", "").lower(),
            model=sub(data.get("model", "")),
            system_prompt=sub(data.get("system_prompt", "")),
            api_key=sub(data.get("api_key", "")),
            base_url=sub(data.get("base_url", "")),
            temperature=float(data.get("temperature", 0.7)),
            max_tokens=int(data.get("max_tokens", 1024)),
        )


# ── Main driver ───────────────────────────────────────────────────────────────

class ModelDriver:
    """
    Delivers payloads directly to an LLM via its native API/SDK.

    Presents the same ``send_payload(payload: str) -> CapturedResponse``
    interface as ApiDriver and BrowserHuntDriver so the entire hunt pipeline
    works without modification.

    Parameters
    ----------
    config:
        :class:`ModelAdapterConfig` with provider, model, credentials.
    """

    def __init__(self, config: ModelAdapterConfig) -> None:
        self._config = config
        log.info(
            "model_driver_init",
            provider=config.provider,
            model=config.model,
        )

    def send_payload(self, payload: str) -> CapturedResponse:
        """Send *payload* to the model and return a CapturedResponse."""
        p = self._config.provider

        if p == "openai":
            text = self._send_openai(payload)
        elif p == "anthropic":
            text = self._send_anthropic(payload)
        elif p == "ollama":
            text = self._send_ollama(payload)
        elif p == "gemini":
            text = self._send_gemini(payload)
        elif p in ("huggingface", "hf"):
            text = self._send_huggingface(payload)
        else:
            raise ValueError(
                f"Unknown model provider '{p}'. "
                "Supported: openai, anthropic, ollama, gemini, huggingface"
            )

        log.info("model_driver_response", provider=p, chars=len(text))
        return CapturedResponse(
            text=text,
            stream_detected=False,
            was_wiped=False,
            payload_hash=sha256(payload),
            response_hash=sha256(text),
            request_body=payload,
            target_url=f"model://{p}/{self._config.model}",
        )

    # ── Provider implementations ──────────────────────────────────────────────

    def _send_openai(self, payload: str) -> str:
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            )
        cfg = self._config
        kwargs: dict = {}
        if cfg.api_key:
            kwargs["api_key"] = cfg.api_key
        if cfg.base_url:
            kwargs["base_url"] = cfg.base_url

        client = OpenAI(**kwargs)
        messages = []
        if cfg.system_prompt:
            messages.append({"role": "system", "content": cfg.system_prompt})
        messages.append({"role": "user", "content": payload})

        resp = client.chat.completions.create(
            model=cfg.model,
            messages=messages,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
        )
        return resp.choices[0].message.content or ""

    def _send_anthropic(self, payload: str) -> str:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            )
        cfg = self._config
        client = anthropic.Anthropic(api_key=cfg.api_key or None)

        kwargs: dict = {
            "model": cfg.model,
            "max_tokens": cfg.max_tokens,
            "messages": [{"role": "user", "content": payload}],
        }
        if cfg.system_prompt:
            kwargs["system"] = cfg.system_prompt

        resp = client.messages.create(**kwargs)
        return resp.content[0].text if resp.content else ""

    def _send_ollama(self, payload: str) -> str:
        import httpx
        cfg = self._config
        base = (cfg.base_url or "http://localhost:11434").rstrip("/")
        url = f"{base}/api/generate"

        body: dict = {
            "model": cfg.model,
            "prompt": payload,
            "stream": False,
            "options": {
                "temperature": cfg.temperature,
                "num_predict": cfg.max_tokens,
            },
        }
        if cfg.system_prompt:
            body["system"] = cfg.system_prompt

        with httpx.Client(timeout=120.0) as client:
            resp = client.post(url, json=body)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()

    def _send_gemini(self, payload: str) -> str:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError(
                "google-generativeai not installed. Run: pip install google-generativeai"
            )
        cfg = self._config
        if cfg.api_key:
            genai.configure(api_key=cfg.api_key)

        model = genai.GenerativeModel(
            model_name=cfg.model,
            system_instruction=cfg.system_prompt or None,
        )
        resp = model.generate_content(
            payload,
            generation_config=genai.GenerationConfig(
                temperature=cfg.temperature,
                max_output_tokens=cfg.max_tokens,
            ),
        )
        return resp.text or ""

    def _send_huggingface(self, payload: str) -> str:
        try:
            from huggingface_hub import InferenceClient
        except ImportError:
            raise ImportError(
                "huggingface_hub not installed. Run: pip install huggingface_hub"
            )
        cfg = self._config
        client = InferenceClient(token=cfg.api_key or None)

        messages = []
        if cfg.system_prompt:
            messages.append({"role": "system", "content": cfg.system_prompt})
        messages.append({"role": "user", "content": payload})

        resp = client.chat_completion(
            model=cfg.model,
            messages=messages,
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
        )
        return resp.choices[0].message.content or ""


# ── Loader ────────────────────────────────────────────────────────────────────

def load_model_adapter(path: str, variables: dict[str, str] | None = None) -> ModelAdapterConfig:
    """Load a model_adapter.yaml and return a ModelAdapterConfig."""
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data.get("mode") != "model":
        raise ValueError(f"Expected mode: model in {path}, got: {data.get('mode')}")
    return ModelAdapterConfig.from_yaml(data, variables)
