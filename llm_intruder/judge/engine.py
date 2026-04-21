"""Judge Engine — orchestrates verdict generation with retry logic.

Flow for each trial
-------------------
1. Run indirect_leak_detector on the response (deterministic pre-pass).
2. Inject detector findings into JudgeRequest.indirect_analysis.
3. Build judge prompt from rubric (pre-analysis block injected automatically).
4. Call provider.generate(prompt) to get a raw JSON string.
5. Parse into JudgeVerdict via Pydantic.
6. On parse failure: rebuild with a simplified retry prompt and try again.
7. After max_retries failures: return a safe ``unclear`` verdict with
   confidence=0.0 so the trial remains reviewable.

The engine is provider-agnostic: it works with OllamaProvider,
LMStudioProvider, and HeuristicProvider interchangeably.

v2 change: indirect leakage pre-analysis runs before every judge call so
small models (Qwen 3-4B, Llama 3.2-3B) receive structural findings they
cannot reliably detect themselves.
"""
from __future__ import annotations

import json
import logging

from pydantic import ValidationError

from llm_intruder.judge.models import JudgeRequest, JudgeVerdict
from llm_intruder.judge.rubric import build_judge_prompt, build_retry_prompt
from llm_intruder.judge.indirect_leak_detector import analyze_response

log = logging.getLogger(__name__)

_FALLBACK_VERDICT = JudgeVerdict(
    verdict="unclear",
    confidence=0.0,
    reasoning="Judge engine exhausted all retries without producing a valid verdict.",
    owasp_category=None,
    flags=[],
)


class JudgeEngine:
    """Coordinates prompt building, provider calls, and JSON parsing.

    Parameters
    ----------
    provider:
        Any object exposing ``generate(prompt: str) -> str``.
        Typically :class:`OllamaProvider` or :class:`HeuristicProvider`.
    max_retries:
        Total attempts before giving up and returning the fallback verdict.
    """

    def __init__(self, provider: object, max_retries: int = 3) -> None:
        self._provider = provider
        self._max_retries = max(1, max_retries)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def judge(self, request: JudgeRequest) -> JudgeVerdict:
        """Produce a :class:`JudgeVerdict` for *request*.

        Runs a deterministic indirect-leak pre-analysis first, injects the
        findings into the request, then retries the LLM call up to
        ``max_retries`` times with progressively simpler prompts.
        Never raises — returns the fallback ``unclear`` verdict on total failure.
        """
        # ── Pre-analysis: run deterministic indirect-leak detector ────────────
        if not request.indirect_analysis and request.response_text.strip():
            try:
                findings = analyze_response(request.response_text)
                # Write back onto the request so retry prompts also see it
                request = request.model_copy(
                    update={"indirect_analysis": findings.summary}
                )
            except Exception as exc:
                log.debug("indirect_leak_detector_error", extra={"error": str(exc)})

        prompt = build_judge_prompt(request)

        for attempt in range(1, self._max_retries + 1):
            raw = self._call_provider(prompt)
            if raw is None:
                # Provider raised an unrecoverable error
                break

            verdict = self._parse_verdict(raw)
            if verdict is not None:
                return verdict

            log.warning(
                "judge_parse_failure",
                extra={"trial_id": request.trial_id, "attempt": attempt, "raw": raw[:200]},
            )
            # Switch to simplified retry prompt for subsequent attempts
            prompt = build_retry_prompt(request, attempt)

        return _FALLBACK_VERDICT

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _call_provider(self, prompt: str) -> str | None:
        """Invoke the provider, catching any exception and returning None."""
        try:
            return self._provider.generate(prompt)  # type: ignore[attr-defined]
        except Exception as exc:
            log.error("judge_provider_error", extra={"error": str(exc)})
            return None

    def _parse_verdict(self, raw: str) -> JudgeVerdict | None:
        """Attempt to parse *raw* into a :class:`JudgeVerdict`.

        Returns None if the string is not valid JSON or fails Pydantic
        validation (triggering a retry in the caller).
        """
        if not raw or not raw.strip():
            return None

        # Ollama sometimes wraps the JSON in markdown code fences — strip them.
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(
                l for l in lines if not l.startswith("```")
            ).strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find the first {...} block in case of leading prose
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1:
                return None
            try:
                data = json.loads(text[start: end + 1])
            except json.JSONDecodeError:
                return None

        try:
            return JudgeVerdict.model_validate(data)
        except ValidationError:
            return None
