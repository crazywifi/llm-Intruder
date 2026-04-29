"""Campaign Runner — trial loop with cross-product (Intruder-style) or weighted strategy selection.

Intruder mode  (explicit_work supplied by runner_bridge)
--------------------------------------------------------
Runs every combination the user selected:
  Pass 0 — plain text      : every payload sent verbatim (passthrough)
  Pass 1 — mutation strats : every payload × every selected mutation strategy
  Pass 2 — encoding techs  : every payload × every selected encoding technique

Total trials = payloads × (1 + n_strategies + n_encoding_techniques)

Legacy modes  (kept for CLI compatibility)
------------------------------------------
all_payloads mode (--all-payloads)
  Iterates through EVERY payload in the library exactly once (shuffled).
  Each payload is sent with the mutator matching its strategy field (or
  passthrough if no dedicated mutator exists).

default mode
  Weighted-random strategy selection, random payload pick, up to max_trials.

no_mutate mode (--no-mutate)
  Skips the mutator entirely — raw template text sent as-is.
  Compatible with all modes.

Verdict stays ``"pending"`` — Phase 6 (Local Judge) will backfill it.
"""
from __future__ import annotations

import random
import sys
import uuid
from typing import Any

import structlog
from sqlalchemy.orm import Session

from llm_intruder.config.models import EngagementConfig
from llm_intruder.core.audit_log import sha256, write_audit_entry
from llm_intruder.db.schema import Trial
from llm_intruder.payloads.library import PayloadLibrary, pick
from llm_intruder.payloads.models import CampaignSummary, MutatedPayload, TrialResult
from llm_intruder.payloads.mutators.registry import get_mutator

log = structlog.get_logger()


def _weighted_choice(weights: dict[str, float], rng: random.Random) -> str:
    """Pick one strategy key using normalised float weights."""
    strategies = list(weights.keys())
    w = list(weights.values())
    return rng.choices(strategies, weights=w, k=1)[0]


class CampaignRunner:
    """Runs a fixed-trial campaign and persists results to SQLite."""

    def __init__(
        self,
        config: EngagementConfig,
        library: PayloadLibrary,
        driver: Any,          # ApiDriver | BrowserDriver — duck-typed
        db_session: Session,
        seed: int | None = None,
    ) -> None:
        self.config = config
        self.library = library
        self.driver = driver
        self.db_session = db_session
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def run(
        self,
        max_trials: int | None = None,
        dry_run: bool = False,
        all_payloads: bool = False,
        no_mutate: bool = False,
        on_trial_complete=None,
        should_stop=None,      # callable() → bool: checked before each trial
        should_pause=None,     # callable() → bool: blocks trial loop while True
        explicit_work: list | None = None,
        # ↑ Intruder-style: list of (PayloadTemplate, strategy: str, encoding: str|None)
        # When supplied, all_payloads / max_trials are ignored.
    ) -> CampaignSummary:
        """Execute the campaign and return a :class:`CampaignSummary`.

        Parameters
        ----------
        max_trials:
            How many trials to run in default (random) mode.
            Ignored when *all_payloads* or *explicit_work* is given.
        dry_run:
            Mutate (or not) and display payloads without sending them.
        all_payloads:
            Legacy: iterate every payload once (shuffled) with its own strategy's
            mutator.  Overridden by *explicit_work* when supplied.
        no_mutate:
            Skip the mutator — send raw template text as-is.
        explicit_work:
            Pre-built cross-product list from runner_bridge.  Each item is a
            tuple ``(template, strategy, encoding_technique | None)`` where:
            - strategy = "passthrough" for plain-text pass
            - strategy = a mutator name like "roleplay_reframe" for mutation pass
            - strategy = "encoding_bypass", encoding_technique = "base64" for encoding pass
        """
        weights = self.config.strategy_weights
        if not weights:
            from llm_intruder.payloads.mutators.registry import available_strategies
            weights = {s: 1.0 for s in available_strategies()}

        # ── Build the work list ───────────────────────────────────────────────
        if explicit_work is not None:
            # Intruder-style cross-product — runner_bridge pre-built the full list
            work = list(explicit_work)
            n = len(work)
            mode_str = "intruder"
        elif all_payloads:
            # Legacy: every payload once, shuffled, strategy from template.strategy field
            raw = list(self.library.payloads)
            self._rng.shuffle(raw)
            work = [(p, p.strategy, None) for p in raw]
            n = len(work)
            mode_str = "all-payloads"
        else:
            # Default: random weighted sampling
            n = max_trials if max_trials is not None else self.config.max_trials
            work = None   # generated per-trial below
            mode_str = "default"

        if no_mutate:
            mode_str += "+no-mutate"

        log.info(
            "campaign_start",
            engagement_id=self.config.engagement_id,
            max_trials=n,
            mode=mode_str,
            dry_run=dry_run,
        )

        results: list[TrialResult] = []
        strategies_used: dict[str, int] = {}

        enc = sys.stdout.encoding or "utf-8"

        def _safe(s: str, length: int = 120) -> str:
            return s[:length].encode(enc, errors="replace").decode(enc, errors="replace")

        for trial_num in range(1, n + 1):
            # ── Honour stop / pause requests from the dashboard ───────────────
            if should_stop and should_stop():
                log.info("campaign_stopped_by_request", trial_num=trial_num)
                break
            if should_pause:
                import time as _time
                while should_pause():
                    _time.sleep(0.25)
                    if should_stop and should_stop():
                        break
                if should_stop and should_stop():
                    break

            # ── Pick template ─────────────────────────────────────────────────
            if work is not None:
                template, strategy, encoding_technique = work[trial_num - 1]
            else:
                # default random mode
                strategy = _weighted_choice(weights, self._rng)
                template = pick(self.library, strategy=strategy, rng=self._rng)
                encoding_technique = None

            # ── Mutate ────────────────────────────────────────────────────────
            if no_mutate or strategy == "passthrough":
                mutated = MutatedPayload(
                    trial_id=str(uuid.uuid4()),
                    strategy=strategy,
                    original_text=template.text,
                    mutated_text=template.text,
                    mutation_metadata={"mutator": "passthrough"},
                )
            elif encoding_technique is not None:
                # Explicit encoding technique — use EncodingBypassMutator with fixed technique
                from llm_intruder.payloads.mutators.encoding_bypass import EncodingBypassMutator
                enc_mutator = EncodingBypassMutator(
                    technique=encoding_technique,
                    seed=self._rng.randint(0, 2**31),
                )
                enc_result = enc_mutator.mutate(template.text)
                mutated = MutatedPayload(
                    trial_id=enc_result.trial_id,
                    strategy=f"enc:{encoding_technique}",
                    original_text=enc_result.original_text,
                    mutated_text=enc_result.mutated_text,
                    mutation_metadata={
                        **enc_result.mutation_metadata,
                        "encoding_technique": encoding_technique,
                    },
                )
            else:
                mutator = get_mutator(strategy, seed=self._rng.randint(0, 2**31))
                mutated = mutator.mutate(template.text)

            strategies_used[mutated.strategy] = strategies_used.get(mutated.strategy, 0) + 1

            # ── Progress line ─────────────────────────────────────────────────
            if strategy == "passthrough":
                pass_tag = "[PLAIN]"
            elif encoding_technique is not None:
                pass_tag = f"[ENC:{encoding_technique}]"
            else:
                pass_tag = "[MUT]"

            print(
                f"  [{trial_num:>5}/{n}] {pass_tag} strategy={mutated.strategy:<32} "
                f"payload_id={template.id}",
                flush=True,
            )

            if dry_run:
                print(f"         [DRY RUN] {_safe(mutated.mutated_text)}")
                result = TrialResult(
                    trial_id=mutated.trial_id,
                    engagement_id=self.config.engagement_id,
                    strategy=mutated.strategy,
                    payload_hash=sha256(mutated.mutated_text),
                    response_hash=sha256(""),
                    response_preview="[dry run — not sent]",
                )
            else:
                result = self._execute_trial(mutated)

            results.append(result)
            self._persist_trial(result)

            # Per-trial progress callback (used by dashboard for live updates)
            if on_trial_complete is not None:
                try:
                    on_trial_complete(trial_num, n, mutated.strategy, result)
                except Exception:
                    pass  # never let callback break the campaign loop

        summary = CampaignSummary(
            engagement_id=self.config.engagement_id,
            total_trials=n,
            strategies_used=strategies_used,
            dry_run=dry_run,
        )
        log.info("campaign_complete", **summary.model_dump(exclude={"completed_at"}))
        return summary

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _execute_trial(self, mutated: MutatedPayload) -> TrialResult:
        """Send the mutated payload and capture the response."""
        request_body = ""
        target_url = ""
        try:
            from llm_intruder.api.driver import ApiDriver
            from llm_intruder.api.templating import build_request_body
            if isinstance(self.driver, ApiDriver):
                request_body = build_request_body(
                    self.driver.adapter.request_template,
                    mutated.mutated_text,
                )
                target_url = self.driver.adapter.endpoint.url
        except Exception:
            pass

        try:
            captured = self.driver.send_payload(mutated.mutated_text)
            response_text = captured.text
            response_hash = captured.response_hash
            request_body = getattr(captured, "request_body", "") or request_body
            target_url = getattr(captured, "target_url", "") or target_url
        except Exception as exc:
            log.warning("trial_error", error=str(exc), trial_id=mutated.trial_id)
            response_text = f"[ERROR: {exc}]"
            response_hash = sha256(response_text)

        # For browser (Web Application) mode, request_body is never populated —
        # there is no HTTP body to capture from a Playwright interaction.
        # Fall back to the raw payload text typed into the browser UI so the
        # "Request Payload" column in reports is always populated regardless of mode.
        if not request_body:
            request_body = mutated.mutated_text

        write_audit_entry(
            self.db_session,
            engagement_id=self.config.engagement_id,
            event_type="trial",
            operator="campaign_runner",
            payload=mutated.mutated_text,
            response=response_text,
            details={
                "trial_id": mutated.trial_id,
                "strategy": mutated.strategy,
                "original_payload_id": mutated.original_text[:60],
            },
        )

        return TrialResult(
            trial_id=mutated.trial_id,
            engagement_id=self.config.engagement_id,
            strategy=mutated.strategy,
            payload_hash=sha256(mutated.mutated_text),
            response_hash=response_hash,
            request_payload=request_body,
            target_url=target_url,
            response_preview=response_text[:2000],
        )

    def _persist_trial(self, result: TrialResult) -> None:
        """Write one row to the ``trials`` SQLite table."""
        row = Trial(
            engagement_id=result.engagement_id,
            trial_id=result.trial_id,
            strategy=result.strategy,
            payload_hash=result.payload_hash,
            response_hash=result.response_hash,
            request_payload=result.request_payload,
            target_url=result.target_url,
            response_text=result.response_preview,
            verdict=result.verdict,
            confidence=result.confidence,
        )
        self.db_session.add(row)
        self.db_session.commit()
