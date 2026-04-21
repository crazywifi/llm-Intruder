"""Concurrent backfill engine — judges pending trials in parallel.

Why this exists
---------------
The original ``backfill_verdicts`` in ``backfill.py`` is sequential: it calls
the Ollama API, waits for the response, writes to DB, then moves to the next
trial.  A single llama3 call on CPU hardware takes 5-30 s, so 100 trials =
8-50 minutes.

This module replaces that loop with an asyncio-based fan-out:

    1. Fetch ALL pending trials from DB (same query, main thread).
    2. Dispatch up to ``workers`` concurrent Ollama requests via asyncio.
    3. Collect results as they finish (using asyncio.gather for true
       concurrency rather than sequential task awaiting).
    4. Write ALL verdicts back to DB in a SINGLE batched commit at the end
       (SQLite doesn't support concurrent writes, so all DB writes happen on
       the main thread — but one commit instead of N commits saves significant
       overhead at scale).

Performance changes vs original (v2 → v3)
------------------------------------------
* ``asyncio.gather`` replaces sequential ``await task`` in a loop — all
  tasks now run truly in parallel up to the semaphore limit, not one-by-one.
* Single batched ``db_session.commit()`` after all results are collected
  instead of one commit per trial — eliminates 500 fsync() calls for 500
  trials, saving several seconds of wall-clock time.
* ``asyncio.get_event_loop()`` replaced with ``asyncio.get_running_loop()``
  to avoid DeprecationWarning in Python 3.10+.

Speedup
-------
With ``workers=4`` and ``OLLAMA_NUM_PARALLEL=4`` and the speed-optimised
provider options (num_ctx=2048, num_predict=256, temperature=0):

  500 trials × ~3-5 s each / 4 parallel = ~375-625 s ≈ 6-10 min
  (vs original ~90 min sequential with untuned options)

Thread safety
-------------
asyncio tasks share the event loop but never touch SQLAlchemy directly.
All Session calls happen in the main thread after ``asyncio.run`` returns.

Setup
-----
Before starting Ollama:
    export OLLAMA_NUM_PARALLEL=4
    ollama serve

Usage (internal — called by cli.py)
------------------------------------
    from llm_intruder.judge.backfill_concurrent import backfill_verdicts_concurrent
    from llm_intruder.judge.ollama_provider_async import AsyncOllamaProvider

    provider = AsyncOllamaProvider(model="llama3.2:3b")

    summary = backfill_verdicts_concurrent(
        provider=provider,          # Use AsyncOllamaProvider for best speed
        db_session=session,
        engagement_id=config.engagement_id,
        workers=4,                  # Match OLLAMA_NUM_PARALLEL
        limit=None,
        provider_name="ollama/llama3.2:3b",
        on_progress=callback,
    )
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Callable, Optional

import structlog
from pydantic import ValidationError
from sqlalchemy.orm import Session

from llm_intruder.db.schema import Finding, Trial
from llm_intruder.judge.models import BackfillSummary, JudgeRequest, JudgeVerdict
from llm_intruder.judge.rubric import build_judge_prompt, build_retry_prompt
from llm_intruder.judge.indirect_leak_detector import analyze_response as _detect_indirect

log = structlog.get_logger()
_pylog = logging.getLogger(__name__)


def _extract_payload_text(request_payload: str | None) -> str:
    """Extract human-readable prompt text from a stored request_payload JSON."""
    if not request_payload:
        return ""
    try:
        data = json.loads(request_payload)
        for key in ("prompt", "message", "input", "text", "query", "content"):
            if key in data and isinstance(data[key], str):
                return data[key][:500]
        return request_payload[:300]
    except (json.JSONDecodeError, TypeError):
        return request_payload[:300]

_FALLBACK_VERDICT = JudgeVerdict(
    verdict="unclear",
    confidence=0.0,
    reasoning="Concurrent judge engine exhausted all retries without a valid verdict.",
    owasp_category=None,
    flags=[],
)

MAX_RETRIES = 3


# ── Helpers (mirrored from engine.py / backfill.py) ──────────────────────────

def _parse_verdict(raw: str) -> Optional[JudgeVerdict]:
    """Attempt to parse *raw* into a JudgeVerdict. Returns None on failure."""
    if not raw or not raw.strip():
        return None
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(l for l in lines if not l.startswith("```")).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
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


def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.60:
        return "medium"
    return "low"


def _make_finding(trial: Trial, verdict: JudgeVerdict) -> Finding:
    return Finding(
        engagement_id=trial.engagement_id,
        trial_id=trial.trial_id,
        category=trial.strategy,
        severity=_confidence_to_severity(verdict.confidence),
        owasp_category=verdict.owasp_category or "unclassified",
        description=(
            f"[{verdict.verdict.upper()} | confidence={verdict.confidence:.2f}] "
            f"{verdict.reasoning}"
            + (f" | flags: {', '.join(verdict.flags)}" if verdict.flags else "")
        ),
    )


# ── Async worker ──────────────────────────────────────────────────────────────

@dataclass
class _TrialResult:
    trial: Trial
    verdict: JudgeVerdict
    skipped: bool = False


async def _judge_one(
    provider,
    request: JudgeRequest,
    semaphore: asyncio.Semaphore,
) -> JudgeVerdict:
    """Call provider.generate with retry logic, honouring the semaphore.

    Runs the indirect-leak detector before building the prompt so structural
    findings are injected — matches the behaviour of the sync JudgeEngine.
    """
    # Deterministic pre-analysis (fast, no I/O — safe to run outside semaphore)
    if not request.indirect_analysis and request.response_text.strip():
        try:
            findings = _detect_indirect(request.response_text)
            request = request.model_copy(update={"indirect_analysis": findings.summary})
        except Exception:
            pass

    prompt = build_judge_prompt(request)

    async with semaphore:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # Support both sync and async providers
                if asyncio.iscoroutinefunction(provider.generate):
                    raw = await provider.generate(prompt)
                else:
                    # Run sync provider in a thread pool so we don't block loop
                    # Use get_running_loop() — get_event_loop() is deprecated in 3.10+
                    loop = asyncio.get_running_loop()
                    raw = await loop.run_in_executor(None, provider.generate, prompt)
            except Exception as exc:
                _pylog.error(
                    "concurrent_judge_provider_error",
                    extra={"trial_id": request.trial_id, "error": str(exc)},
                )
                return _FALLBACK_VERDICT

            verdict = _parse_verdict(raw)
            if verdict is not None:
                return verdict

            _pylog.warning(
                "concurrent_judge_parse_failure",
                extra={"trial_id": request.trial_id, "attempt": attempt},
            )
            prompt = build_retry_prompt(request, attempt)

    return _FALLBACK_VERDICT


async def _run_all(
    provider,
    trial_requests: list[tuple[Trial, JudgeRequest]],
    workers: int,
) -> list[_TrialResult]:
    """Fan out all judge requests concurrently and collect results.

    Uses ``asyncio.gather`` so all tasks run truly in parallel (up to the
    semaphore limit) rather than being awaited sequentially.
    """
    semaphore = asyncio.Semaphore(workers)

    # Build (trial, coroutine) pairs
    pairs: list[tuple[Trial, asyncio.Task]] = [
        (
            trial,
            asyncio.create_task(
                _judge_one(provider, req, semaphore),
                name=f"judge-{req.trial_id}",
            ),
        )
        for trial, req in trial_requests
    ]

    tasks = [task for _, task in pairs]
    trials = [trial for trial, _ in pairs]

    # gather() waits for ALL tasks in parallel — much faster than
    # sequential "for task in tasks: await task"
    verdicts = await asyncio.gather(*tasks, return_exceptions=False)

    return [
        _TrialResult(trial=trial, verdict=verdict)
        for trial, verdict in zip(trials, verdicts)
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def backfill_verdicts_concurrent(
    provider,
    db_session: Session,
    engagement_id: str,
    workers: int = 4,
    limit: Optional[int] = None,
    provider_name: str = "ollama",
    on_progress: Optional[Callable] = None,
) -> BackfillSummary:
    """Judge all pending trials concurrently and write results to DB.

    Parameters
    ----------
    provider:
        Any object with ``generate(prompt: str) -> str``.
        For maximum throughput use ``AsyncOllamaProvider`` (async generate)
        with model ``"llama3.2:3b"`` or ``"phi3.5:mini"``.
        Falls back gracefully to sync providers via ``run_in_executor``.
    db_session:
        Active SQLAlchemy session (all writes happen here, main thread only).
    engagement_id:
        Only process trials belonging to this engagement.
    workers:
        Number of concurrent Ollama requests. Must match the
        ``OLLAMA_NUM_PARALLEL`` env var set before starting Ollama.
        Default raised to 4 (was 5 in v2; 4 is safer default for most CPUs).
    limit:
        Cap on total trials processed this run.
    provider_name:
        Label stored in BackfillSummary.
    on_progress:
        Optional callback ``(current, total, verdict, confidence) -> None``.

    Returns
    -------
    BackfillSummary
    """
    # ── 1. Fetch pending trials (main thread, sync) ───────────────────────────
    query = (
        db_session.query(Trial)
        .filter(
            Trial.engagement_id == engagement_id,
            Trial.verdict == "pending",
        )
        .order_by(Trial.id)
    )
    if limit is not None:
        query = query.limit(limit)

    pending_trials: list[Trial] = query.all()
    total_pending = len(pending_trials)

    log.info(
        "concurrent_backfill_start",
        engagement_id=engagement_id,
        pending=total_pending,
        workers=workers,
        provider=provider_name,
    )

    judged = 0
    failed_to_judge = 0
    verdict_counts: dict[str, int] = {}

    # ── 2. Separate dry-run / empty trials (no need to judge) ─────────────────
    trial_requests: list[tuple[Trial, JudgeRequest]] = []
    skipped_count = 0

    for trial in pending_trials:
        response_text = trial.response_text or ""
        if "[dry run" in response_text.lower() or not response_text.strip():
            log.debug("concurrent_backfill_skip_dry_run", trial_id=trial.trial_id)
            skipped_count += 1
            verdict_counts["skipped"] = verdict_counts.get("skipped", 0) + 1
            continue

        payload_text = _extract_payload_text(trial.request_payload)

        request = JudgeRequest(
            trial_id=trial.trial_id,
            engagement_id=trial.engagement_id,
            strategy=trial.strategy,
            payload_preview=(
                payload_text
                or f"[strategy={trial.strategy}] hash={trial.payload_hash[:16]}..."
            ),
            payload_text=payload_text,
            response_text=response_text[:2000],
            # indirect_analysis left empty — _judge_one fills it via detector
        )
        trial_requests.append((trial, request))

    failed_to_judge += skipped_count

    # ── 3. Run concurrent judge calls via asyncio ─────────────────────────────
    if trial_requests:
        results = asyncio.run(_run_all(provider, trial_requests, workers=workers))
    else:
        results = []

    # ── 4. Write results to DB — SINGLE BATCHED COMMIT ───────────────────────
    # Original code committed once per trial (500 commits for 500 trials).
    # Batching all writes into one commit saves significant I/O overhead,
    # especially on SQLite where each commit triggers an fsync().
    for result in results:
        trial = result.trial
        verdict = result.verdict

        trial.verdict = verdict.verdict
        trial.confidence = verdict.confidence

        if verdict.is_finding:
            finding = _make_finding(trial, verdict)
            db_session.add(finding)

        verdict_counts[verdict.verdict] = verdict_counts.get(verdict.verdict, 0) + 1
        judged += 1

        log.info(
            "trial_judged_concurrent",
            trial_id=trial.trial_id,
            verdict=verdict.verdict,
            confidence=f"{verdict.confidence:.2f}",
        )

        if on_progress is not None:
            try:
                on_progress(
                    judged + failed_to_judge,
                    total_pending,
                    verdict.verdict,
                    verdict.confidence,
                )
            except Exception:
                pass

    # Single commit for all 500 trials instead of 500 individual commits
    db_session.commit()

    summary = BackfillSummary(
        engagement_id=engagement_id,
        total_pending=total_pending,
        judged=judged,
        failed_to_judge=failed_to_judge,
        verdict_counts=verdict_counts,
        provider=provider_name,
    )
    log.info("concurrent_backfill_complete", **summary.model_dump())
    return summary
