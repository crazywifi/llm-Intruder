"""llm_intruder.judge — LLM judge engine and provider registry."""
from llm_intruder.judge.claude_provider import ClaudeProvider
from llm_intruder.judge.engine import JudgeEngine
from llm_intruder.judge.gemini_provider import GeminiProvider
from llm_intruder.judge.heuristic_provider import HeuristicProvider
from llm_intruder.judge.lmstudio_provider import LMStudioProvider
from llm_intruder.judge.models import JudgeVerdict
from llm_intruder.judge.ollama_provider import OllamaProvider
from llm_intruder.judge.openai_provider import OpenAIProvider
from llm_intruder.judge.provider_registry import discover_local_providers, print_discovery_report

__all__ = [
    # Engine
    "JudgeEngine",
    # Providers
    "HeuristicProvider",
    "OllamaProvider",
    "ClaudeProvider",
    "OpenAIProvider",
    "GeminiProvider",
    "LMStudioProvider",
    # Registry
    "discover_local_providers",
    "print_discovery_report",
    # Models
    "JudgeVerdict",
]
