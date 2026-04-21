"""Backfill engine — queries pending trials and writes judge verdicts to SQLite.

Algorithm
---------
1. SELECT trials WHERE engagement_id = ? AND verdict = 'pending'
   (optionally capped at *limit*).
2. For each row: build a JudgeRequest from the stored data.
3. Call engine.judge() → JudgeVerdict.
4. UPDATE trial SET verdict=?, confidence=? WHERE trial_id=?.
5. If verdict == "fail": insert a Finding row.
6. Return BackfillSummary with counts.

Findings
--------
When a trial verdict is "fail", a Finding row is created with:
- category  : the strategy name (e.g. "roleplay_reframe")
- severity  : mapped from confidence (≥0.85 → high, ≥0.60 → medium, else low)
- owasp_category : from the verdict
- description : the judge's reasoning
"""
from __future__ import annotations

import json

import structlog
from sqlalchemy.orm import Session

from llm_intruder.db.schema import Finding, Trial
from llm_intruder.judge.engine import JudgeEngine
from llm_intruder.judge.models import BackfillSummary, JudgeRequest, JudgeVerdict

log = structlog.get_logger()


def _extract_payload_text(request_payload: str | None) -> str:
    """Extract the human-readable prompt text from a stored request_payload JSON.

    The stored value looks like:
        {"defender": "...", "prompt": "the actual attack text"}

    Returns the prompt field value, or the raw string if parsing fails.
    """
    if not request_payload:
        return ""
    try:
        data = json.loads(request_payload)
        # Try common field names used by adapters
        for key in ("prompt", "message", "input", "text", "query", "content"):
            if key in data and isinstance(data[key], str):
                return data[key][:500]
        # Fallback: return entire JSON but truncated
        return request_payload[:300]
    except (json.JSONDecodeError, TypeError):
        return request_payload[:300]


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


def backfill_verdicts(
    engine: JudgeEngine,
    db_session: Session,
    engagement_id: str,
    limit: int | None = None,
    provider_name: str = "ollama",
    on_progress: object = None,
) -> BackfillSummary:
    """Judge all pending trials for *engagement_id* and write results to DB.

    Parameters
    ----------
    engine:
        A configured :class:`JudgeEngine` instance.
    db_session:
        Active SQLAlchemy session (will be committed per trial).
    engagement_id:
        Only process trials belonging to this engagement.
    limit:
        If set, process at most this many trials per call.
    provider_name:
        Label stored in the summary (``"ollama"`` or ``"heuristic"``).
    on_progress:
        Optional callback ``(current: int, total: int, verdict: str, confidence: float) -> None``
        called after each trial is judged, for live progress display.

    Returns
    -------
    BackfillSummary
    """
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

    judged = 0
    failed_to_judge = 0
    verdict_counts: dict[str, int] = {}

    log.info(
        "backfill_start",
        engagement_id=engagement_id,
        pending=total_pending,
        provider=provider_name,
    )

    for trial in pending_trials:
        response_text = trial.response_text or ""

        # Skip dry-run placeholders — no real response to judge
        if "[dry run" in response_text.lower() or not response_text.strip():
            log.debug("backfill_skip_dry_run", trial_id=trial.trial_id)
            failed_to_judge += 1
            verdict_counts["skipped"] = verdict_counts.get("skipped", 0) + 1
            continue

        # HTTP error responses (400, 401, 403, 404, 429, 500, etc.) → "error" verdict
        # Pattern: "[ERROR: Client error 'NNN <status>' for url '...']"
        import re as _re
        if response_text.lstrip().startswith("[ERROR:"):
            status_match = _re.search(r"'(\d{3})\s+[^']*'", response_text)
            http_code = status_match.group(1) if status_match else "?"
            trial.verdict = "error"
            trial.confidence = 0.0
            db_session.add(trial)
            try:
                db_session.commit()
            except Exception:
                db_session.rollback()
            judged += 1
            verdict_counts["error"] = verdict_counts.get("error", 0) + 1
            log.info("backfill_http_error", trial_id=trial.trial_id, http_code=http_code)
            if on_progress:
                try:
                    on_progress(judged, total_pending, "error", 0.0)
                except Exception:
                    pass
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
            # indirect_analysis left empty — engine.judge() fills it via detector
        )

        try:
            verdict = engine.judge(request)
        except Exception as exc:
            log.error("backfill_judge_error", trial_id=trial.trial_id, error=str(exc))
            failed_to_judge += 1
            continue

        # Update trial
        trial.verdict = verdict.verdict
        trial.confidence = verdict.confidence

        # Create Finding for confirmed attacks
        if verdict.is_finding:
            finding = _make_finding(trial, verdict)
            db_session.add(finding)

        db_session.commit()

        verdict_counts[verdict.verdict] = verdict_counts.get(verdict.verdict, 0) + 1
        judged += 1

        log.info(
            "trial_judged",
            trial_id=trial.trial_id,
            verdict=verdict.verdict,
            confidence=f"{verdict.confidence:.2f}",
        )

        if on_progress is not None:
            try:
                on_progress(judged + failed_to_judge, total_pending, verdict.verdict, verdict.confidence)
            except Exception:
                pass  # never let progress callback break the loop

    summary = BackfillSummary(
        engagement_id=engagement_id,
        total_pending=total_pending,
        judged=judged,
        failed_to_judge=failed_to_judge,
        verdict_counts=verdict_counts,
        provider=provider_name,
    )
    log.info("backfill_complete", **summary.model_dump())
    return summary
