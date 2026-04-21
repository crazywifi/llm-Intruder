"""Interactive Hunt REPL — live LLM red-teaming in a read-eval-print loop.

Launch via:
    redteam repl --engagement eng.yaml --adapter adapter.yaml [options]

REPL commands
─────────────
  run [N] [strategy]   Run N trials (default 1). Optional strategy name.
  fire <payload>        Send a custom raw payload directly to the target.
  strategies            List available strategies with current adaptive weights.
  payloads [strategy]   List payloads (optionally filtered by strategy).
  status                Show running totals and outcome breakdown.
  best                  Show the best trial recorded so far.
  trial <N>             Show full details for trial number N.
  goal <keyword>        Set or update the success keyword.
  set <key> <value>     Change a live config setting (see `set help`).
  weights               Print current strategy weight table.
  export md [path]      Export current results as Markdown.
  export html [path]    Export current results as HTML.
  export json [path]    Export current results as JSON.
  clear                 Clear the terminal screen.
  help                  Show this help.
  quit / exit           Exit the REPL.
"""
from __future__ import annotations

import json
import os
import shlex
import textwrap
import time
from typing import Optional

from llm_intruder.hunt.models import HuntConfig, HuntMode, HuntResult, TrialResult
from llm_intruder.adaptive.response_classifier import ResponseType

# ── ANSI colour helpers ────────────────────────────────────────────────────────

_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_MAGENTA = "\033[95m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{_RESET}"


def _verdict_color(verdict: str, response_type: ResponseType) -> str:
    if response_type == ResponseType.SUCCESS:
        return _GREEN
    if response_type == ResponseType.PARTIAL_LEAK:
        return _YELLOW
    if response_type == ResponseType.HARD_REFUSAL:
        return _RED
    if response_type == ResponseType.SOFT_REFUSAL:
        return _YELLOW
    return _DIM


_BANNER = """\
╔══════════════════════════════════════════════════════════════╗
║          LLM-Intruder  INTERACTIVE  HUNT  REPL               ║
║  Type  help  for commands.   quit  or  Ctrl-C  to exit.     ║
╚══════════════════════════════════════════════════════════════╝"""

_SET_HELP = """\
  set mode <adaptive|pair|multi_turn|tap|full>
  set max-turns <N>
  set stop-on-success <true|false>
  set attacker-model <model-name>
  set pair-refinements <N>"""


# ── Main REPL class ────────────────────────────────────────────────────────────

class HuntREPL:
    """Interactive REPL wrapping a :class:`~llm_intruder.hunt.runner.HuntRunner`.

    Parameters
    ----------
    runner:
        A fully initialised HuntRunner (driver, library, profile all wired up).
    db_session:
        Optional SQLAlchemy session for persisting results.
    engagement_path:
        Path to the engagement YAML (for export filenames / next-steps hints).
    """

    def __init__(
        self,
        runner,
        db_session=None,
        engagement_path: str = "engagement.yaml",
    ) -> None:
        self._runner           = runner
        self._db_session       = db_session
        self._engagement_path  = engagement_path
        self._result           = HuntResult(engagement_id=runner.config.engagement_id)
        self._start_time       = time.time()
        # history of all trials for `trial N` lookup
        self._trials: list[TrialResult] = []

    # ── Entry point ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Enter the read-eval-print loop."""
        print(_c(_CYAN, _BANNER))
        print(f"\n  Engagement : {self._runner.config.engagement_id}")
        print(f"  Mode       : {self._runner.config.mode.value}")
        print(f"  Goal       : {self._runner.profile.goal[:70]}")
        if self._runner.profile.goal_keywords:
            print(f"  Keywords   : {', '.join(self._runner.profile.goal_keywords)}")
        print()

        # Warm up (baseline probe)
        print(_c(_DIM, "  Running warm-up probe..."))
        try:
            self._runner._warm_up()
        except Exception as exc:
            print(_c(_YELLOW, f"  [WARN] Warm-up failed: {exc}"))
        print(_c(_DIM, "  Ready.\n"))

        while True:
            try:
                line = input(_c(_CYAN, "sentinel> ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            try:
                should_continue = self._dispatch(line)
            except Exception as exc:
                print(_c(_RED, f"  [ERROR] {exc}"))
                should_continue = True
            if not should_continue:
                break

        elapsed = time.time() - self._start_time
        print(_c(_DIM, f"\n  Session ended after {elapsed:.1f}s — {len(self._trials)} trials."))
        if self._trials:
            print(self._result.summary_table())

    # ── Command dispatcher ─────────────────────────────────────────────────────

    def _dispatch(self, line: str) -> bool:
        """Parse *line* and execute the matching command.  Returns False to quit."""
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if not parts:
            return True

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("quit", "exit", "q"):
            return False

        if cmd in ("help", "?", "h"):
            self._cmd_help()
        elif cmd == "run":
            self._cmd_run(args)
        elif cmd == "fire":
            self._cmd_fire(args)
        elif cmd == "strategies":
            self._cmd_strategies()
        elif cmd == "payloads":
            self._cmd_payloads(args)
        elif cmd == "status":
            self._cmd_status()
        elif cmd == "best":
            self._cmd_best()
        elif cmd == "trial":
            self._cmd_trial(args)
        elif cmd == "goal":
            self._cmd_goal(args)
        elif cmd == "set":
            self._cmd_set(args)
        elif cmd == "weights":
            self._cmd_weights()
        elif cmd == "export":
            self._cmd_export(args)
        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
        else:
            print(_c(_RED, f"  Unknown command: {cmd!r}  (type 'help')"))
        return True

    # ── Command implementations ────────────────────────────────────────────────

    def _cmd_help(self) -> None:
        print(_c(_CYAN, textwrap.dedent("""\

          LLM-Intruder Interactive Hunt REPL — Commands
          ─────────────────────────────────────────────
          run [N] [strategy]   Run N trials (default 1). Optional strategy name.
          fire <payload>        Send a custom raw payload to the target.
          strategies            List strategies + current adaptive weights.
          payloads [strategy]   List payloads (optional strategy filter).
          status                Running totals and outcome breakdown.
          best                  Show best trial so far.
          trial <N>             Full details for trial number N.
          goal <keyword>        Set the success keyword (overrides profile).
          set <key> <value>     Change live config  (type 'set help').
          weights               Strategy weight table.
          export md [path]      Export results as Markdown.
          export html [path]    Export results as HTML.
          export json [path]    Export results as JSON.
          clear                 Clear screen.
          help                  This message.
          quit / exit           Exit REPL.
        """)))

    # ── run ───────────────────────────────────────────────────────────────────

    def _cmd_run(self, args: list[str]) -> None:
        n = 1
        strategy: str | None = None
        for arg in args:
            if arg.isdigit():
                n = int(arg)
            else:
                strategy = arg

        for i in range(n):
            trial = self._runner.step(strategy=strategy)
            self._result.record_trial(trial)
            self._trials.append(trial)
            self._print_trial(trial)

            if trial.is_success and self._runner.config.stop_on_first_success:
                print(_c(_GREEN, "\n  [SUCCESS] Goal achieved — stopping."))
                break

    # ── fire ──────────────────────────────────────────────────────────────────

    def _cmd_fire(self, args: list[str]) -> None:
        if not args:
            print(_c(_RED, "  Usage: fire <payload text>"))
            return
        payload = " ".join(args)
        trial = self._runner.send_raw(payload)
        self._result.record_trial(trial)
        self._trials.append(trial)
        self._print_trial(trial)

    # ── strategies ────────────────────────────────────────────────────────────

    def _cmd_strategies(self) -> None:
        try:
            weights = self._runner._selector.get_weights()
        except AttributeError:
            # Fallback: list strategies from library
            weights = {
                s: 1.0
                for s in sorted({p.strategy for p in self._runner.library.payloads})
            }

        print(_c(_BOLD, "\n  Strategy                        Weight   Trials  Successes"))
        print("  " + "─" * 60)
        for strat, w in sorted(weights.items(), key=lambda x: -x[1]):
            se = self._result.strategy_effectiveness.get(strat, {})
            total = se.get("total", 0)
            succ  = se.get("successes", 0)
            bar   = "█" * min(int(w * 20), 20)
            print(f"  {strat:<30}  {w:.3f}   {total:>5}   {succ:>5}   {bar}")
        print()

    # ── payloads ──────────────────────────────────────────────────────────────

    def _cmd_payloads(self, args: list[str]) -> None:
        strategy_filter = args[0].lower() if args else None
        payloads = self._runner.library.payloads
        if strategy_filter:
            payloads = [p for p in payloads if p.strategy.lower() == strategy_filter]

        if not payloads:
            print(_c(_YELLOW, f"  No payloads found for strategy {strategy_filter!r}"))
            return

        print(_c(_BOLD, f"\n  {'Strategy':<25}  {'Category':<20}  Template (truncated)"))
        print("  " + "─" * 80)
        for p in payloads[:50]:
            tpl = (p.template or "").replace("\n", " ")[:50]
            print(f"  {p.strategy:<25}  {p.category:<20}  {tpl}")
        if len(payloads) > 50:
            print(f"  … and {len(payloads) - 50} more")
        print()

    # ── status ────────────────────────────────────────────────────────────────

    def _cmd_status(self) -> None:
        r = self._result
        elapsed = time.time() - self._start_time
        print(_c(_BOLD, "\n  ── Hunt Status ──────────────────────────────────────"))
        print(f"  Trials run      : {r.total_trials}")
        print(f"  Successes       : {_c(_GREEN if r.successes else _DIM, str(r.successes))}")
        print(f"  Partial leaks   : {_c(_YELLOW if r.partial_leaks else _DIM, str(r.partial_leaks))}")
        print(f"  Soft refusals   : {r.soft_refusals}")
        print(f"  Hard refusals   : {_c(_RED if r.hard_refusals else _DIM, str(r.hard_refusals))}")
        print(f"  Off-topic       : {r.off_topics}")
        print(f"  Elapsed         : {elapsed:.1f}s")
        if r.total_trials:
            asr = r.successes / r.total_trials
            print(f"  Attack success  : {asr:.1%}")
        print(f"  Mode            : {self._runner.config.mode.value}")
        goal_kw = ", ".join(self._runner.profile.goal_keywords) or "—"
        print(f"  Goal keyword(s) : {goal_kw}")
        print()

    # ── best ──────────────────────────────────────────────────────────────────

    def _cmd_best(self) -> None:
        bt = self._result.best_trial
        if bt is None:
            print(_c(_DIM, "  No trials yet."))
            return
        print(_c(_BOLD, "\n  ── Best Trial ───────────────────────────────────────"))
        self._print_trial_detail(bt)

    # ── trial <N> ─────────────────────────────────────────────────────────────

    def _cmd_trial(self, args: list[str]) -> None:
        if not args or not args[0].isdigit():
            print(_c(_RED, "  Usage: trial <N>"))
            return
        n = int(args[0])
        match = next((t for t in self._trials if t.trial_num == n), None)
        if match is None:
            print(_c(_RED, f"  Trial #{n} not found in this session."))
            return
        self._print_trial_detail(match)

    # ── goal ──────────────────────────────────────────────────────────────────

    def _cmd_goal(self, args: list[str]) -> None:
        if not args:
            current = ", ".join(self._runner.profile.goal_keywords) or "—"
            print(f"  Current goal keywords: {current}")
            return
        kw = " ".join(args)
        self._runner.profile.goal_keywords = [kw]
        print(_c(_GREEN, f"  Goal keyword set to: {kw!r}"))

    # ── set ───────────────────────────────────────────────────────────────────

    def _cmd_set(self, args: list[str]) -> None:
        if not args or args[0].lower() == "help":
            print(_c(_CYAN, _SET_HELP))
            return

        key   = args[0].lower()
        value = " ".join(args[1:]) if len(args) > 1 else ""

        cfg = self._runner.config

        if key == "mode":
            try:
                cfg.mode = HuntMode(value.lower())
                print(_c(_GREEN, f"  mode => {cfg.mode.value}"))
            except ValueError:
                print(_c(_RED, f"  Invalid mode: {value!r}"))
        elif key == "max-turns":
            try:
                cfg.max_turns_per_trial = int(value)
                print(_c(_GREEN, f"  max_turns_per_trial => {cfg.max_turns_per_trial}"))
            except ValueError:
                print(_c(_RED, "  Value must be an integer."))
        elif key == "stop-on-success":
            cfg.stop_on_first_success = value.lower() in ("true", "1", "yes")
            print(_c(_GREEN, f"  stop_on_first_success => {cfg.stop_on_first_success}"))
        elif key == "attacker-model":
            cfg.attacker_model = value
            print(_c(_GREEN, f"  attacker_model => {cfg.attacker_model}"))
        elif key == "pair-refinements":
            try:
                cfg.pair_max_refinements = int(value)
                print(_c(_GREEN, f"  pair_max_refinements => {cfg.pair_max_refinements}"))
            except ValueError:
                print(_c(_RED, "  Value must be an integer."))
        else:
            print(_c(_RED, f"  Unknown setting: {key!r}  (type 'set help')"))

    # ── weights ───────────────────────────────────────────────────────────────

    def _cmd_weights(self) -> None:
        try:
            summary = self._runner._selector.summary()
            print(summary)
        except AttributeError:
            print(_c(_YELLOW, "  Strategy selector does not expose a summary."))

    # ── export ────────────────────────────────────────────────────────────────

    def _cmd_export(self, args: list[str]) -> None:
        fmt = args[0].lower() if args else "md"
        out_path = args[1] if len(args) > 1 else None

        if not self._trials:
            print(_c(_YELLOW, "  No trials to export yet."))
            return

        # Build a lightweight EngagementReport from current session data
        try:
            from llm_intruder.reports.models import (
                EngagementReport,
                VerdictBreakdown,
                TrialSummary,
            )
            from llm_intruder.reports.generator import _render_markdown, _render_html
            from datetime import datetime, timezone
            import hashlib

            vb = VerdictBreakdown(
                pass_count=self._result.hard_refusals + self._result.soft_refusals,
                fail_count=self._result.successes,
                error_count=0,
                pending_count=0,
                total=self._result.total_trials,
            )
            trial_summaries = [
                TrialSummary(
                    trial_id=f"repl-{t.trial_num}",
                    strategy=t.strategy,
                    verdict=t.verdict,
                    confidence=t.confidence,
                    payload_hash=hashlib.md5(t.payload_sent.encode()).hexdigest()[:8],
                    response_hash=hashlib.md5(t.response_received.encode()).hexdigest()[:8],
                    request_payload=f"POST {t.target_url}\n{t.request_body_full}".strip() if t.target_url else t.payload_sent,
                    target_url=t.target_url or "",
                    response_text=t.response_received,
                    created_at=datetime.now(timezone.utc),
                )
                for t in self._trials
            ]
            report = EngagementReport(
                engagement_id=self._runner.config.engagement_id,
                trial_count=len(self._trials),
                finding_count=self._result.successes + self._result.partial_leaks,
                verdict_breakdown=vb,
                strategies_used=list(self._result.strategy_effectiveness.keys()),
                trials=trial_summaries,
            )
        except Exception as exc:
            print(_c(_RED, f"  Failed to build report model: {exc}"))
            return

        try:
            if fmt in ("md", "markdown"):
                content = _render_markdown(report)
                default_path = f"hunt_repl_{self._runner.config.engagement_id}.md"
                mode = "w"
                encoding = "utf-8"
            elif fmt == "html":
                content = _render_html(report)
                default_path = f"hunt_repl_{self._runner.config.engagement_id}.html"
                mode = "w"
                encoding = "utf-8"
            elif fmt == "json":
                content = report.model_dump_json(indent=2)
                default_path = f"hunt_repl_{self._runner.config.engagement_id}.json"
                mode = "w"
                encoding = "utf-8"
            else:
                print(_c(_RED, f"  Unknown format: {fmt!r}  (md, html, json)"))
                return

            path = out_path or default_path
            with open(path, mode, encoding=encoding) as fh:
                fh.write(content)
            print(_c(_GREEN, f"  Exported {fmt.upper()} report → {path}"))

        except Exception as exc:
            print(_c(_RED, f"  Export failed: {exc}"))

    # ── Print helpers ──────────────────────────────────────────────────────────

    def _print_trial(self, trial: TrialResult) -> None:
        """One-line summary of a completed trial."""
        color = _verdict_color(trial.verdict, trial.response_type)
        rt_label = trial.response_type.value if hasattr(trial.response_type, "value") else str(trial.response_type)
        prox_bar = "▓" * int(trial.proximity_score * 10) + "░" * (10 - int(trial.proximity_score * 10))
        line = (
            f"  #{trial.trial_num:>3}  "
            f"{_c(color, f'{rt_label:<15}')}"
            f"  [{prox_bar}] {trial.proximity_score:.2f}  "
            f"  {trial.strategy:<28}"
            f"  {trial.payload_sent[:60]}"
        )
        print(line)

    def _print_trial_detail(self, trial: TrialResult) -> None:
        """Multi-line detail block for a single trial."""
        color = _verdict_color(trial.verdict, trial.response_type)
        rt_label = trial.response_type.value if hasattr(trial.response_type, "value") else str(trial.response_type)
        print(f"\n  Trial #{trial.trial_num}")
        print(f"  Strategy   : {trial.strategy}")
        print(f"  Mode       : {trial.mode_used}")
        print(f"  Response   : {_c(color, rt_label)}")
        print(f"  Proximity  : {trial.proximity_score:.3f}  ({trial.proximity_label})")
        print(f"  Confidence : {trial.confidence:.3f}")
        print(f"  Verdict    : {trial.verdict}")
        if trial.target_url:
            print(f"  Target URL : {trial.target_url}")
        print(f"\n  {_c(_BOLD, 'Payload sent:')}")
        for ln in textwrap.wrap(trial.payload_sent, width=80):
            print(f"    {ln}")
        print(f"\n  {_c(_BOLD, 'Response received:')}")
        resp = trial.response_received
        if resp.startswith("[classifier:"):
            resp = resp.split("\n", 1)[1].strip() if "\n" in resp else resp
        for ln in textwrap.wrap(resp[:600], width=80):
            print(f"    {ln}")
        print()
