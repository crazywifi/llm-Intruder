"""Attack Narrative Generator.

Converts a sequence of TrialSummary rows into a human-readable attack story —
explaining *how* the attacker progressed from the first blocked attempt to the
final successful disclosure, and *why* each pivot happened.

This is what separates a tool that produces data from a tool that produces
findings a client will actually act on. Clients don't read verdict spreadsheets;
they read stories.

Output format
-------------
The narrative is structured Markdown with these sections:

  1. **Attack Timeline** — a numbered log of every trial with classification
  2. **Pivot Points** — moments where the strategy family changed and why
  3. **Breakthrough Sequence** — the last N trials leading to success
  4. **Root Cause Analysis** — what guardrail weakness the attack exploited
  5. **Evidence Highlight** — the actual payload that worked + response excerpt

The narrative is embedded into the EngagementReport as a ``narrative`` field
and written into both Markdown and HTML reports automatically.
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

from llm_intruder.reports.models import EngagementReport, FindingSummary, TrialSummary

# ── Response type labels ──────────────────────────────────────────────────────

_VERDICT_LABEL: dict[str, str] = {
    "fail":    "SUCCESS",
    "pass":    "BLOCKED",
    "error":   "ERROR",
    "pending": "PENDING",
}

_VERDICT_EMOJI: dict[str, str] = {
    "fail":    "🔴",   # red = attack succeeded (bad for defender)
    "pass":    "🟢",   # green = model held
    "error":   "⚠️",
    "pending": "⏳",
}

# Strategy families — used for detecting pivot points
_STRATEGY_FAMILIES: dict[str, str] = {
    # Encoding
    "encoding_bypass": "encoding", "cipher_jailbreak": "encoding",
    # Roleplay/persona
    "roleplay_reframe": "persona", "persona_hijack": "persona",
    "roleplay_jailbreak": "persona",
    # Authority
    "authority_inject": "authority", "authority_override": "authority",
    "sycophancy_exploit": "authority",
    # Structural
    "crescendo": "escalation", "socratic_method": "escalation",
    "hypothetical_chain": "escalation",
    # Obfuscation
    "token_obfuscation": "obfuscation", "splitting": "obfuscation",
    # Extraction
    "system_prompt_extraction": "extraction", "prefill_inject": "extraction",
    "prefill_injection": "extraction",
    # Multi-shot
    "many_shot_context": "multi_shot", "many_shot_jailbreaking": "multi_shot",
    # Advanced
    "tap": "tree_search", "best_of_n": "best_of_n", "pair": "pair",
}

_FAMILY_DESCRIPTION: dict[str, str] = {
    "encoding":   "encoding-based evasion (cipher / obfuscated payloads)",
    "persona":    "persona / roleplay jailbreaks",
    "authority":  "authority and social-engineering pressure",
    "escalation": "gradual escalation techniques",
    "obfuscation":"token-level obfuscation",
    "extraction": "direct extraction / prefill injection",
    "multi_shot": "many-shot priming",
    "tree_search":"tree-search (TAP)",
    "best_of_n":  "best-of-N variant flooding",
    "pair":       "PAIR attacker-LLM refinement",
}

_PIVOT_REASON: dict[str, str] = {
    "hard_refusal":
        "consistent hard refusals indicated keyword-based filtering — "
        "pivoting to a different surface representation",
    "soft_refusal":
        "soft refusals suggested partial guardrail coverage — "
        "escalating pressure while maintaining the same approach",
    "off_topic":
        "off-topic responses indicated context confusion — "
        "switching to a more direct injection strategy",
    "partial_leak":
        "partial information leaked, confirming the target has the data — "
        "escalating with more direct extraction",
    "unclear":
        "ambiguous responses made classification unreliable — "
        "trying a different strategy family for clearer signal",
}


@dataclass
class NarrativeChapter:
    """One logical section of the attack narrative."""
    title: str
    body: str


@dataclass
class AttackNarrative:
    """Complete structured narrative for one engagement."""
    engagement_id: str
    chapters: list[NarrativeChapter] = field(default_factory=list)
    success_trial: Optional[TrialSummary] = None
    total_trials: int = 0
    attack_succeeded: bool = False

    def to_markdown(self) -> str:
        lines = [f"# Attack Narrative — Engagement `{self.engagement_id}`\n"]
        for ch in self.chapters:
            lines.append(f"## {ch.title}\n")
            lines.append(ch.body)
            lines.append("")
        return "\n".join(lines)

    def to_html(self) -> str:
        """Return a self-contained HTML fragment (no <html>/<body> wrapper)."""
        parts = [f'<div class="narrative">']
        parts.append(
            f'<h2>Attack Narrative — Engagement <code>{self.engagement_id}</code></h2>'
        )
        for ch in self.chapters:
            safe_title = _esc(ch.title)
            safe_body = _md_to_html(ch.body)
            parts.append(f'<h3>{safe_title}</h3>')
            parts.append(f'<div class="narrative-section">{safe_body}</div>')
        parts.append("</div>")
        return "\n".join(parts)


# ── Public entry point ────────────────────────────────────────────────────────

def build_narrative(report: EngagementReport) -> AttackNarrative:
    """Generate a complete :class:`AttackNarrative` from an :class:`EngagementReport`.

    Parameters
    ----------
    report:
        A fully populated :class:`~llm_intruder.reports.models.EngagementReport`
        with ``trials`` and ``findings`` populated.

    Returns
    -------
    AttackNarrative
        Contains structured chapters and the overall success status.
    """
    trials = report.trials
    findings = report.findings

    if not trials:
        return AttackNarrative(
            engagement_id=report.engagement_id,
            chapters=[NarrativeChapter(
                title="No Trials",
                body="No trials were recorded for this engagement.",
            )],
        )

    success_trial = _find_success_trial(trials, findings)
    narrative = AttackNarrative(
        engagement_id=report.engagement_id,
        total_trials=len(trials),
        attack_succeeded=success_trial is not None,
        success_trial=success_trial,
    )

    narrative.chapters.append(_build_executive_summary(report, success_trial))
    narrative.chapters.append(_build_timeline(trials))
    narrative.chapters.append(_build_pivot_analysis(trials))

    if success_trial:
        narrative.chapters.append(_build_breakthrough_sequence(trials, success_trial))
        narrative.chapters.append(_build_root_cause(trials, success_trial, findings))
        narrative.chapters.append(_build_evidence_highlight(success_trial, findings))
    else:
        narrative.chapters.append(_build_no_success_analysis(trials))

    narrative.chapters.append(_build_strategy_effectiveness(report))

    return narrative


# ── Chapter builders ──────────────────────────────────────────────────────────

def _build_executive_summary(
    report: EngagementReport, success_trial: Optional[TrialSummary]
) -> NarrativeChapter:
    asr = report.verdict_breakdown.attack_success_rate
    br  = report.verdict_breakdown.block_rate

    if success_trial:
        outcome = (
            f"**The attack succeeded.** "
            f"The target model was bypassed on trial #{_trial_num(report.trials, success_trial)} "
            f"using the `{success_trial.strategy}` strategy."
        )
    else:
        outcome = (
            f"**The target held.** "
            f"No trial produced a confirmed bypass across {report.trial_count} attempts."
        )

    body = textwrap.dedent(f"""\
        | Metric | Value |
        |--------|-------|
        | Total trials | {report.trial_count} |
        | Attack success rate | {asr:.1%} |
        | Block rate | {br:.1%} |
        | Findings | {report.finding_count} |
        | Strategies tested | {len(report.strategies_used)} |

        {outcome}
    """)
    return NarrativeChapter(title="Executive Summary", body=body)


def _build_timeline(trials: list[TrialSummary]) -> NarrativeChapter:
    lines = [
        "Each row represents one trial. "
        "🔴 = attack succeeded (guardrail bypassed). 🟢 = model held.\n",
        "| # | Strategy | Verdict | Confidence |",
        "|---|----------|---------|------------|",
    ]
    for i, t in enumerate(trials, 1):
        emoji   = _VERDICT_EMOJI.get(t.verdict, "❓")
        label   = _VERDICT_LABEL.get(t.verdict, t.verdict.upper())
        conf    = f"{t.confidence:.0%}" if t.confidence else "—"
        strat   = t.strategy[:35]
        lines.append(f"| {i} | `{strat}` | {emoji} {label} | {conf} |")

    return NarrativeChapter(title="Attack Timeline", body="\n".join(lines))


def _build_pivot_analysis(trials: list[TrialSummary]) -> NarrativeChapter:
    """Identify strategy family pivot points and explain the reasoning."""
    if not trials:
        return NarrativeChapter(title="Strategy Pivots", body="No trials to analyse.")

    pivots: list[str] = []
    prev_family = _family(trials[0].strategy)
    family_run_verdicts: list[str] = []

    for i, t in enumerate(trials):
        fam = _family(t.strategy)
        if fam != prev_family:
            # Pivot detected — explain why
            dominant = _dominant_verdict(family_run_verdicts)
            reason = _PIVOT_REASON.get(dominant, "inconclusive results")
            prev_desc = _FAMILY_DESCRIPTION.get(prev_family, prev_family)
            new_desc  = _FAMILY_DESCRIPTION.get(fam, fam)
            pivots.append(
                f"**Trial {i + 1}** — Pivoted from _{prev_desc}_ to _{new_desc}_. "
                f"Reason: {reason}."
            )
            prev_family = fam
            family_run_verdicts = []
        family_run_verdicts.append(t.verdict)

    if not pivots:
        fam_desc = _FAMILY_DESCRIPTION.get(prev_family, prev_family)
        body = (
            f"The attacker used a single strategy family throughout "
            f"({fam_desc}) without pivoting. This typically indicates either "
            f"early success or that the family was producing consistent partial "
            f"signals worth continuing."
        )
    else:
        body = (
            f"The attacker made **{len(pivots)} strategy pivot(s)** during this engagement:\n\n"
            + "\n\n".join(f"- {p}" for p in pivots)
        )

    return NarrativeChapter(title="Strategy Pivots", body=body)


def _build_breakthrough_sequence(
    trials: list[TrialSummary], success: TrialSummary
) -> NarrativeChapter:
    """Show the last 5 trials leading to success with commentary."""
    idx = next((i for i, t in enumerate(trials) if t.trial_id == success.trial_id), -1)
    window = trials[max(0, idx - 4): idx + 1]

    lines = [
        "The following sequence of trials led directly to the bypass:\n",
    ]
    for i, t in enumerate(window):
        global_num = trials.index(t) + 1
        emoji = _VERDICT_EMOJI.get(t.verdict, "❓")
        label = _VERDICT_LABEL.get(t.verdict, t.verdict.upper())
        payload_preview = _safe_preview(t.request_payload or t.payload_hash, 120)
        response_preview = _safe_preview(t.response_text or "", 200)

        lines.append(f"**Trial {global_num}** · `{t.strategy}` · {emoji} {label}")
        lines.append(f"- Payload: `{payload_preview}`")
        if response_preview:
            lines.append(f"- Response: _{response_preview}_")
        lines.append("")

    return NarrativeChapter(title="Breakthrough Sequence", body="\n".join(lines))


def _build_root_cause(
    trials: list[TrialSummary],
    success: TrialSummary,
    findings: list[FindingSummary],
) -> NarrativeChapter:
    """Infer what guardrail weakness the successful strategy exploited."""
    strategy = success.strategy
    family   = _family(strategy)

    # Find how many similar strategies failed before the breakthrough
    prior_same_family = [
        t for t in trials
        if _family(t.strategy) == family and t.verdict != "fail"
    ]

    exploit_type = {
        "encoding": (
            "The target's content filters relied on keyword or token matching. "
            "Encoding the payload (e.g. cipher, base64, morse) caused the filter "
            "to see only safe-looking tokens while the model decoded and acted on "
            "the real instruction. **Root cause: surface-level pattern matching, "
            "not semantic understanding.**"
        ),
        "persona": (
            "The target's guardrails were tied to the model's self-identity. "
            "When asked to adopt a persona without restrictions, the model "
            "followed the roleplay framing and complied. **Root cause: "
            "identity-based restrictions that collapse under persona injection.**"
        ),
        "authority": (
            "The target's RLHF training created a sycophantic tendency to "
            "agree with confident authority claims. False claims of developer "
            "access, researcher status, or configuration overrides were accepted "
            "without challenge. **Root cause: RLHF-induced sycophancy.**"
        ),
        "escalation": (
            "Gradual escalation across multiple turns (or with increasing "
            "intensity) moved the model's responses incrementally toward "
            "compliance. The guardrails were effective at blocking direct "
            "requests but not at tracking cumulative escalation. "
            "**Root cause: no multi-turn context tracking in content policy.**"
        ),
        "extraction": (
            "Direct extraction or assistant-role prefill bypassed the refusal "
            "gate by pre-positioning the model mid-answer. The guardrail only "
            "activates during response generation; the prefill jump-started the "
            "response after the check point. **Root cause: refusal gate runs "
            "before generation, not on completed outputs.**"
        ),
    }.get(
        family,
        f"The `{strategy}` strategy exploited a gap in the target's content "
        f"policy for this specific input class. Review the specific payload "
        f"and response for the exact mechanism."
    )

    failed_attempts_note = ""
    if prior_same_family:
        failed_attempts_note = (
            f"\n\nNote: {len(prior_same_family)} earlier trial(s) in the same "
            f"strategy family were blocked before this variant succeeded, "
            f"suggesting the guardrail has partial coverage for this technique."
        )

    owasp = _infer_owasp(strategy)
    body = (
        f"{exploit_type}{failed_attempts_note}\n\n"
        f"**OWASP LLM classification**: {owasp}"
    )

    return NarrativeChapter(title="Root Cause Analysis", body=body)


def _build_evidence_highlight(
    success: TrialSummary, findings: list[FindingSummary]
) -> NarrativeChapter:
    payload  = success.request_payload or f"[hash: {success.payload_hash}]"
    response = success.response_text or "[response not stored]"

    matched_finding = next(
        (f for f in findings if f.trial_id == success.trial_id), None
    )
    finding_note = ""
    if matched_finding:
        finding_note = (
            f"\n**Finding**: [{matched_finding.owasp_category}] "
            f"{matched_finding.category} · Severity: **{matched_finding.severity}**"
            f"\n{matched_finding.description}"
        )

    body = textwrap.dedent(f"""\
        The following payload produced the successful response:

        ```
        {_safe_preview(payload, 600)}
        ```

        **Target response** (first 500 characters):

        > {_safe_preview(response, 500)}
        {finding_note}
    """)
    return NarrativeChapter(title="Evidence", body=body)


def _build_no_success_analysis(trials: list[TrialSummary]) -> NarrativeChapter:
    dominant = _dominant_verdict([t.verdict for t in trials])
    best = max(trials, key=lambda t: t.confidence or 0.0, default=None)

    if dominant in ("pass",):
        analysis = (
            "The target model consistently blocked all attack attempts. "
            "The guardrails appear well-calibrated for the strategies tested. "
            "Consider testing with TAP mode (`--mode tap`) for deeper tree search, "
            "or expanding the payload catalogue with domain-specific payloads."
        )
    else:
        analysis = (
            "No trial achieved confirmed bypass, but some produced ambiguous "
            "or partial results. Manual review of the trials with the highest "
            "confidence scores is recommended — the judge may have missed "
            "subtle indirect leakage."
        )

    best_note = ""
    if best:
        best_note = (
            f"\n\nThe closest attempt was trial using `{best.strategy}` "
            f"with confidence {best.confidence:.0%}."
        )

    return NarrativeChapter(
        title="Why the Attack Did Not Succeed",
        body=analysis + best_note,
    )


def _build_strategy_effectiveness(report: EngagementReport) -> NarrativeChapter:
    if not report.strategy_verdict_counts:
        return NarrativeChapter(title="Strategy Effectiveness", body="No data.")

    rows = [
        "| Strategy | Trials | Successes | Block Rate |",
        "|----------|--------|-----------|------------|",
    ]
    for strat, counts in sorted(
        report.strategy_verdict_counts.items(),
        key=lambda kv: kv[1].get("fail", 0),
        reverse=True,
    ):
        total   = sum(counts.values())
        success = counts.get("fail", 0)
        blocked = counts.get("pass", 0)
        br      = f"{blocked / total:.0%}" if total else "—"
        rows.append(f"| `{strat}` | {total} | {success} | {br} |")

    return NarrativeChapter(
        title="Strategy Effectiveness Summary",
        body="\n".join(rows),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_success_trial(
    trials: list[TrialSummary], findings: list[FindingSummary]
) -> Optional[TrialSummary]:
    finding_ids = {f.trial_id for f in findings}
    for t in trials:
        if t.verdict == "fail" or t.trial_id in finding_ids:
            return t
    return None


def _family(strategy: str) -> str:
    return _STRATEGY_FAMILIES.get(strategy, strategy.split("_")[0])


def _dominant_verdict(verdicts: list[str]) -> str:
    if not verdicts:
        return "unclear"
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v] = counts.get(v, 0) + 1
    return max(counts, key=lambda k: counts[k])


def _trial_num(trials: list[TrialSummary], target: TrialSummary) -> int:
    for i, t in enumerate(trials, 1):
        if t.trial_id == target.trial_id:
            return i
    return -1


def _safe_preview(text: str, max_chars: int) -> str:
    if not text:
        return ""
    text = text.replace("\n", " ").replace("\r", " ").strip()
    if len(text) > max_chars:
        return text[:max_chars] + "…"
    return text


def _infer_owasp(strategy: str) -> str:
    mapping = {
        "encoding_bypass": "LLM01 (Prompt Injection)",
        "roleplay_reframe": "LLM01 (Prompt Injection)",
        "authority_inject": "LLM01 (Prompt Injection)",
        "sycophancy_exploit": "LLM09 (Overreliance)",
        "system_prompt_extraction": "LLM06 (Sensitive Information Disclosure)",
        "prefill_inject": "LLM01 (Prompt Injection)",
        "pii_sensitive_extraction": "LLM06 (Sensitive Information Disclosure)",
        "crescendo": "LLM01 (Prompt Injection)",
        "tap": "LLM01 (Prompt Injection)",
        "best_of_n": "LLM01 (Prompt Injection)",
    }
    return mapping.get(strategy, "LLM01 (Prompt Injection)")


def _esc(text: str) -> str:
    """Minimal HTML entity escaping."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_to_html(md: str) -> str:
    """Trivial Markdown → HTML (tables, bold, code, blockquotes, line breaks).
    Not a full parser — covers the subset used in narrative chapters.
    """
    lines = md.split("\n")
    out: list[str] = []
    in_table = False
    in_code = False

    for line in lines:
        # Code fence
        if line.strip().startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                out.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(_esc(line))
            continue

        # Table
        if line.startswith("|"):
            if not in_table:
                out.append('<table class="narrative-table"><tbody>')
                in_table = True
            if re.match(r"\|[-| :]+\|", line):
                continue  # separator row
            cells = [c.strip() for c in line.strip("|").split("|")]
            row = "".join(f"<td>{_inline_md(_esc(c))}</td>" for c in cells)
            out.append(f"<tr>{row}</tr>")
            continue
        if in_table:
            out.append("</tbody></table>")
            in_table = False

        # Headings  (# h1  ## h2  ### h3 …)
        m = re.match(r"^(#{1,6})\s+(.*)", line)
        if m:
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline_md(_esc(m.group(2)))}</h{level}>")
            continue

        # Blockquote
        if line.startswith("> "):
            out.append(f"<blockquote>{_inline_md(_esc(line[2:]))}</blockquote>")
            continue

        # Horizontal rule
        if re.match(r"^-{3,}$|^\*{3,}$|^_{3,}$", line.strip()):
            out.append("<hr>")
            continue

        # Empty
        if not line.strip():
            out.append("<br>")
            continue

        out.append(f"<p>{_inline_md(_esc(line))}</p>")

    if in_table:
        out.append("</tbody></table>")
    if in_code:
        out.append("</code></pre>")
    return "\n".join(out)


def _inline_md(text: str) -> str:
    """Convert inline Markdown (bold, italic, code) to HTML.

    Rules:
    * ``**bold**`` → <strong>
    * ``*italic*`` → <em>  (only when surrounded by non-word chars / spaces)
    * ``_italic_`` → <em>  (only word-boundary italic — avoids snake_case corruption)
    * backtick code → <code>
    """
    # Code first (prevents further substitution inside code spans)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # Bold before italic so ** doesn't get consumed as two *
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # Only match _word_ where _ is at a word boundary — prevents snake_case_name → em
    text = re.sub(r"(?<!\w)_([^_]+)_(?!\w)", r"<em>\1</em>", text)
    return text
