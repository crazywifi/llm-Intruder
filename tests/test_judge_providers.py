"""Tests for Phase 13 judge providers (Claude, OpenAI, Gemini, LM Studio)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from llm_intruder.judge.claude_provider import ClaudeProvider, CLAUDE_MODELS
from llm_intruder.judge.gemini_provider import GeminiProvider
from llm_intruder.judge.lmstudio_provider import LMStudioProvider
from llm_intruder.judge.openai_provider import OpenAIProvider
from llm_intruder.judge.provider_registry import discover_local_providers


# ── ClaudeProvider ────────────────────────────────────────────────────────────

class TestClaudeProvider:
    def test_init_requires_api_key(self):
        with pytest.raises(ValueError, match="API key"):
            ClaudeProvider(api_key="")

    def test_init_stores_model(self):
        p = ClaudeProvider(api_key="sk-ant-test", model="claude-sonnet-4-6")
        assert p._model == "claude-sonnet-4-6"

    def test_is_available_true_with_key(self):
        p = ClaudeProvider(api_key="sk-ant-test")
        assert p.is_available() is True

    def test_default_model(self):
        p = ClaudeProvider(api_key="sk-ant-test")
        assert p._model == "claude-haiku-4-5-20251001"

    def test_name(self):
        assert ClaudeProvider.NAME == "claude"

    def test_claude_models_list(self):
        assert len(CLAUDE_MODELS) >= 3
        assert "claude-haiku-4-5-20251001" in CLAUDE_MODELS

    def test_generate_calls_api(self):
        p = ClaudeProvider(api_key="sk-ant-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "content": [{"text": '{"verdict":"pass","confidence":0.9,"reason":"blocked"}'}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = p.generate("Test prompt")

        assert "pass" in result
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        # Check API key header
        assert call_kwargs.kwargs["headers"]["x-api-key"] == "sk-ant-test"
        # Check model in body
        assert call_kwargs.kwargs["json"]["model"] == "claude-haiku-4-5-20251001"

    def test_generate_uses_system_field(self):
        """Claude API requires system as top-level field, not a message."""
        p = ClaudeProvider(api_key="sk-ant-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"content": [{"text": "result"}]}
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            p.generate("user message")

        body = mock_post.call_args.kwargs["json"]
        assert "system" in body
        assert "messages" in body
        # Messages should only have user role
        for msg in body["messages"]:
            assert msg["role"] == "user"


# ── OpenAIProvider ────────────────────────────────────────────────────────────

class TestOpenAIProvider:
    def test_init_requires_api_key(self):
        with pytest.raises(ValueError, match="API key"):
            OpenAIProvider(api_key="")

    def test_name(self):
        assert OpenAIProvider.NAME == "openai"

    def test_is_available(self):
        p = OpenAIProvider(api_key="sk-test")
        assert p.is_available() is True

    def test_default_model(self):
        p = OpenAIProvider(api_key="sk-test")
        assert p._model == "gpt-4o-mini"

    def test_generate_uses_bearer_auth(self):
        p = OpenAIProvider(api_key="sk-real-key")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"verdict":"fail","confidence":0.8,"reason":"x"}'}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = p.generate("test")

        headers = mock_post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer sk-real-key"

    def test_generate_sends_system_message(self):
        """OpenAI expects system prompt as role='system' message."""
        p = OpenAIProvider(api_key="sk-test")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "result"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            p.generate("user message")

        body = mock_post.call_args.kwargs["json"]
        roles = [m["role"] for m in body["messages"]]
        assert "system" in roles
        assert "user" in roles

    def test_custom_base_url(self):
        p = OpenAIProvider(api_key="sk-test", base_url="http://localhost:11434/v1/chat/completions")
        assert "localhost" in p._base_url


# ── GeminiProvider ────────────────────────────────────────────────────────────

class TestGeminiProvider:
    def test_init_requires_api_key(self):
        with pytest.raises(ValueError, match="API key"):
            GeminiProvider(api_key="")

    def test_name(self):
        assert GeminiProvider.NAME == "gemini"

    def test_default_model(self):
        p = GeminiProvider(api_key="AIzaTest")
        assert "gemini" in p._model

    def test_is_available(self):
        p = GeminiProvider(api_key="AIzaTest")
        assert p.is_available() is True

    def test_generate_uses_header_key(self):
        p = GeminiProvider(api_key="AIzaTest123")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "verdict text"}]}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            result = p.generate("test")

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert headers.get("x-goog-api-key") == "AIzaTest123"
        # Verify key is NOT in query params (security fix)
        params = call_kwargs.kwargs.get("params", {})
        assert "key" not in params

    def test_generate_uses_correct_content_structure(self):
        """Gemini uses role='user' and parts=[{text}] format."""
        p = GeminiProvider(api_key="AIzaTest")
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "result"}]}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            p.generate("user message")

        body = mock_post.call_args.kwargs["json"]
        assert "contents" in body
        for content in body["contents"]:
            assert "parts" in content


# ── LMStudioProvider ──────────────────────────────────────────────────────────

class TestLMStudioProvider:
    def test_name(self):
        assert LMStudioProvider.NAME == "lmstudio"

    def test_default_base_url(self):
        p = LMStudioProvider()
        assert "localhost:1234" in p._base_url

    def test_is_available_true_when_models_exist(self):
        p = LMStudioProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "llama-3.2-1b"}]}

        with patch("httpx.get", return_value=mock_resp):
            assert p.is_available() is True

    def test_is_available_false_when_no_server(self):
        import httpx as _httpx
        p = LMStudioProvider()
        with patch("httpx.get", side_effect=_httpx.ConnectError("refused")):
            assert p.is_available() is False

    def test_is_available_false_when_no_models(self):
        p = LMStudioProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": []}

        with patch("httpx.get", return_value=mock_resp):
            assert p.is_available() is False

    def test_list_models(self):
        p = LMStudioProvider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [{"id": "model-a"}, {"id": "model-b"}]
        }
        with patch("httpx.get", return_value=mock_resp):
            models = p.list_models()
        assert models == ["model-a", "model-b"]

    def test_resolve_model_auto(self):
        p = LMStudioProvider(model="auto")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "llama-3"}]}
        with patch("httpx.get", return_value=mock_resp):
            resolved = p._resolve_model()
        assert resolved == "llama-3"

    def test_resolve_model_explicit(self):
        p = LMStudioProvider(model="mistral-7b")
        assert p._resolve_model() == "mistral-7b"

    def test_generate_uses_openai_format(self):
        """LM Studio uses OpenAI-compatible /v1/chat/completions."""
        p = LMStudioProvider(model="test-model")
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.json.return_value = {"data": [{"id": "test-model"}]}

        mock_post = MagicMock()
        mock_post.json.return_value = {
            "choices": [{"message": {"content": "response text"}}]
        }
        mock_post.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_get):
            with patch("httpx.post", return_value=mock_post) as mp:
                p.generate("test prompt")

        body = mp.call_args.kwargs["json"]
        assert "messages" in body
        assert body["model"] == "test-model"


# ── Provider registry ─────────────────────────────────────────────────────────

class TestProviderRegistry:
    def test_discover_returns_list(self):
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.ConnectError("refused")):
            result = discover_local_providers()
        assert isinstance(result, list)

    def test_discover_finds_ollama(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": [{"name": "llama3.1"}]}

        def fake_get(url, **kwargs):
            if "11434" in url:
                return mock_resp
            raise Exception("no server")

        with patch("httpx.get", side_effect=fake_get):
            result = discover_local_providers()

        ollama_entries = [r for r in result if r["provider"] == "ollama"]
        assert len(ollama_entries) == 1
        assert "llama3.1" in ollama_entries[0]["models"]

    def test_discover_finds_lmstudio(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "qwen-2.5"}]}

        import httpx as _httpx

        def fake_get(url, **kwargs):
            if "1234" in url:
                return mock_resp
            raise _httpx.ConnectError("refused")

        with patch("httpx.get", side_effect=fake_get):
            result = discover_local_providers()

        lms_entries = [r for r in result if r["provider"] == "lmstudio"]
        assert len(lms_entries) == 1

    def test_discover_empty_when_nothing_running(self):
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.ConnectError("refused")):
            result = discover_local_providers()
        assert result == []
