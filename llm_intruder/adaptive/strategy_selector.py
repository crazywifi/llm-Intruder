"""Adaptive strategy selector — updates strategy weights based on trial outcomes.

Starts from base weights (from engagement.yaml or defaults).
After each trial, adjusts weights up/down based on the response type.
Implements exponential moving average decay so recent results matter more.
"""
from __future__ import annotations

import random
from typing import Optional

import structlog

from llm_intruder.adaptive.response_classifier import ResponseType

log = structlog.get_logger()

# ── constants ─────────────────────────────────────────────────────────────────

_MIN_WEIGHT: float = 0.05
_MAX_WEIGHT: float = 5.0    # was 10.0 — capped lower to prevent runaway weights

_DEFAULT_WEIGHTS: dict[str, float] = {
    # ── Mutator strategies (structural transformations) ────────────────────────
    # These transform the payload text before sending.
    "paraphrase":                   1.0,
    "roleplay_reframe":             1.0,
    "language_switch":              1.0,
    "token_obfuscation":            1.0,
    "many_shot_context":            1.0,
    "crescendo":                    1.0,
    "splitting":                    1.0,
    "authority_inject":             1.0,
    "encoding_bypass":              1.0,
    "virtualization":               1.0,
    "hypothetical_chain":           1.0,
    "socratic_method":              1.0,
    # ── P4RS3LT0NGV3-inspired mutators ───────────────────────────────────────────
    "best_of_n":                    1.0,
    "prefill_inject":               1.0,
    "anti_classifier":              1.0,   # semantic synonym rewrite
    "bijection":                    1.0,   # custom alphabet teaching
    "glitch_tokens":                1.0,   # OOD token injection
    # ── ZeroLeaks-inspired mutators ──────────────────────────────────────────────
    "siren":                        1.0,   # 6-step trust-building extraction
    "echo_chamber":                 1.0,   # 5-step meta-normalisation
    "topic_attack":                 1.0,   # gradual topic steering
    "skeleton_key":                 1.0,   # prefix-based safety bypass
    # ── Payload-library-only strategies (self-contained attack texts) ──────────
    # These payloads are sent verbatim (PassthroughMutator) — no rewrite needed.
    "gandalf_specialized":          1.0,
    "system_prompt_extraction":     1.0,
    "persona_hijack":               1.0,
    "roleplay_jailbreak":           1.0,
    "direct_injection":             1.0,
    "authority_override":           1.0,
    "refusal_suppression":          1.0,
    "hypothetical_framing":         1.0,
    "many_shot_jailbreaking":       1.0,
    "chain_of_thought_exploit":     1.0,
    "output_format_manipulation":   1.0,
    "policy_puppetry":              1.0,
    "agent_tool_exploitation":      1.0,
    "tool_simulation":              1.0,
    "semantic_transformation":      1.0,
    "reconstruction_attacks":       1.0,
    "elimination_attacks":          1.0,
    "invisible_character_injection": 1.0,
    "token_smuggling":              1.0,
    "incode_comment_hijacking":     1.0,
    "latent_reasoning_exploit":     1.0,
    "context_overflow":             1.0,
    "embedding_leakage":            1.0,
    "memory_attacks":               1.0,
    "rag_poisoning":                1.0,
    "rag_memory_poisoning":         1.0,
    "pii_sensitive_extraction":     1.0,
    "error_leakage":                1.0,
    "universal_adversarial_suffixes": 1.0,
    "universal_kitchen_sink":       1.0,
    # ── Payload catalogues ───────────────────────────────────────────────────────
    "cipher_jailbreak":             1.0,   # cipher-encoded jailbreaks
    "prefill_injection":            1.0,   # assistant-turn prefill attacks
    "sycophancy_exploit":           1.0,   # RLHF sycophancy exploitation
    "parseltongue_attacks":         1.0,   # P4RS3LT0NGV3 Unicode/glitch attacks
    "web_app_llm_attacks":          1.0,   # XSS/SSRF/SQLi/RCE via LLM
    "incremental_extraction":       1.0,   # gradual/social-eng extraction
    "markdown_exfiltration":        1.0,   # markdown out-of-band exfil
    "mcp_tool_poisoning":           1.0,   # MCP/tool exploitation
    "behavioral_injection":         1.0,   # behavior modification attacks
    # ── Domain-specific (narrow targets only — low default weight) ────────────
    "financial_domain":             0.3,
    "medical_domain":               0.3,
    "enterprise_domain":            0.3,
    "multi_language_injection":     0.5,
    "visual_multimodal_injection":  0.3,
    "length_metadata":              0.5,
    "denial_of_wallet":             0.2,
}


def _clamp(value: float) -> float:
    """Keep weight inside [_MIN_WEIGHT, _MAX_WEIGHT]."""
    return max(_MIN_WEIGHT, min(_MAX_WEIGHT, value))


class AdaptiveStrategySelector:
    """
    Weighted strategy picker whose weights shift based on observed outcomes.

    Parameters
    ----------
    base_weights:
        Mapping of strategy_name → initial weight.  Missing strategies get
        weight 1.0.  Pass ``{}`` to use the built-in defaults.
    decay:
        EMA decay factor (0 < decay ≤ 1).  Each trial applies
        ``weight = weight * decay + new_weight * (1 - decay)`` conceptually;
        practically the decay is applied as a soft pull toward 1.0 on all
        *unchanged* strategies so recent signals dominate.
    """

    def __init__(
        self,
        base_weights: dict[str, float],
        decay: float = 0.85,
        skip_strategies: list[str] | None = None,
    ) -> None:
        # Merge caller's weights with defaults; caller values take precedence.
        self._weights: dict[str, float] = {}
        for strategy, default_w in _DEFAULT_WEIGHTS.items():
            raw = base_weights.get(strategy, default_w)
            self._weights[strategy] = _clamp(float(raw))
        # Accept extra strategies from the caller (e.g. custom ones)
        for strategy, raw in base_weights.items():
            if strategy not in self._weights:
                self._weights[strategy] = _clamp(float(raw))

        self._decay = decay

        # Strategies the hunt runner will never pick — we must not waste weight
        # updates on them either, or they drift to high values and pollute the
        # weight table display.
        self._skip: set[str] = set(skip_strategies or [])

        # Remove skipped strategies from the weight table entirely so they
        # never appear in next_strategy() or accumulate phantom weight.
        for s in self._skip:
            self._weights.pop(s, None)

        # Outcome counters
        self.hard_refusals: int  = 0
        self.soft_refusals: int  = 0
        self.partial_leaks: int  = 0
        self.off_topics:    int  = 0
        self.successes:     int  = 0

        # Per-strategy outcome history: strategy → list of ResponseType strings
        self._history: dict[str, list[str]] = {s: [] for s in self._weights}

        log.debug(
            "strategy_selector_init",
            strategies=list(self._weights.keys()),
            skipped=list(self._skip),
            decay=decay,
        )

    # ── public API ────────────────────────────────────────────────────────────

    def record(
        self,
        strategy: str,
        response_type: ResponseType,
        trial_num: int,
    ) -> None:
        """
        Update weights based on what happened in *trial_num*.

        Parameters
        ----------
        strategy:
            The strategy that was used in this trial.
        response_type:
            What the classifier decided about the response.
        trial_num:
            Current trial index (for logging).
        """
        # Decay all weights slightly toward 1.0 to prevent one early strong
        # signal from permanently dominating the weights table.
        for s in self._weights:
            current = self._weights[s]
            # Gentle pull toward 1.0 on every record() call
            self._weights[s] = _clamp(current * self._decay + 1.0 * (1.0 - self._decay))

        # Track history
        if strategy not in self._history:
            self._history[strategy] = []
        self._history[strategy].append(response_type.value)

        def _boost(s: str, factor: float) -> None:
            """Boost strategy s — but never boost a skipped strategy."""
            if s in self._weights and s not in self._skip:
                self._weights[s] = _clamp(self._weights[s] * factor)

        def _boost_alternatives(factor: float, *candidates: str) -> None:
            """
            Boost alternative strategies — but NEVER boost the strategy that
            just failed (strategy), and never boost skipped strategies.

            This prevents the feedback loop where a failing strategy
            keeps getting boosted because other strategies also fail.
            """
            for s in candidates:
                if s != strategy and s not in self._skip:
                    _boost(s, factor)

        if response_type == ResponseType.HARD_REFUSAL:
            self.hard_refusals += 1
            # Penalise what just failed
            _boost(strategy, 0.70)
            # Gently suggest alternatives — only if THEY haven't been the ones failing.
            # Use smaller multipliers (was 1.35/1.25/1.15) to prevent runaway growth.
            _boost_alternatives(1.12, "encoding_bypass", "token_obfuscation")
            _boost_alternatives(1.08, "splitting", "many_shot_context")
            log.debug("selector_hard_refusal", strategy=strategy, trial=trial_num)

        elif response_type == ResponseType.SOFT_REFUSAL:
            self.soft_refusals += 1
            # Soft refusal = model hesitated — escalate gently
            _boost_alternatives(1.25, "crescendo", "socratic_method")
            _boost_alternatives(1.15, "many_shot_context", "splitting")
            log.debug("selector_soft_refusal", strategy=strategy, trial=trial_num)

        elif response_type == ResponseType.PARTIAL_LEAK:
            self.partial_leaks += 1
            # This is working — double down on exactly this strategy
            _boost(strategy, 1.80)
            # Also boost related escalation strategies
            _boost_alternatives(1.20, "crescendo", "socratic_method")
            log.debug("selector_partial_leak", strategy=strategy, trial=trial_num)

        elif response_type == ResponseType.OFF_TOPIC:
            self.off_topics += 1
            _boost(strategy, 0.85)
            _boost_alternatives(1.30, "authority_inject", "splitting")
            log.debug("selector_off_topic", strategy=strategy, trial=trial_num)

        elif response_type == ResponseType.SUCCESS:
            self.successes += 1
            # Don't adjust — if we found success, weights don't matter
            log.info("selector_success", strategy=strategy, trial=trial_num)

        elif response_type == ResponseType.UNCLEAR:
            # Mild penalty; not enough signal to know what to do
            _boost(strategy, 0.92)

    def next_strategy(self, rng: Optional[random.Random] = None) -> str:
        """
        Return the next strategy to try via weighted random selection.

        Parameters
        ----------
        rng:
            Optional ``random.Random`` instance (for reproducibility).
        """
        rng = rng or random.Random()
        strategies = list(self._weights.keys())
        weights    = [self._weights[s] for s in strategies]
        chosen = rng.choices(strategies, weights=weights, k=1)[0]
        log.debug("selector_next_strategy", chosen=chosen, weight=self._weights[chosen])
        return chosen

    def get_weights(self) -> dict[str, float]:
        """Return a copy of the current weight table."""
        return dict(self._weights)

    def summary(self) -> str:
        """Human-readable summary of what the selector has learned."""
        lines: list[str] = [
            "=== Strategy Selector Summary ===",
            f"  Hard refusals : {self.hard_refusals}",
            f"  Soft refusals : {self.soft_refusals}",
            f"  Partial leaks : {self.partial_leaks}",
            f"  Off-topic     : {self.off_topics}",
            f"  Successes     : {self.successes}",
            "",
            "  Current weights (sorted by weight desc):",
        ]
        sorted_w = sorted(self._weights.items(), key=lambda kv: kv[1], reverse=True)
        for strategy, w in sorted_w:
            bar = "█" * max(1, round(w * 4))
            lines.append(f"    {strategy:<22} {w:5.2f}  {bar}")

        # Highlight which strategies are dominating
        top = sorted_w[:3]
        lines.append("")
        lines.append("  Top 3 recommended:")
        for s, w in top:
            lines.append(f"    → {s}  (weight={w:.2f})")

        return "\n".join(lines)
