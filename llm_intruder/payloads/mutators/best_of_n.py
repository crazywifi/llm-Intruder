"""Best-of-N (BoN) jailbreak mutator.

Technique overview
------------------
Andriushchenko et al. 2024 showed that generating N random surface variations
of a payload and submitting all of them yields at least one bypass with high
probability — even for well-hardened models (GPT-4o, Claude-3).

The key insight: guardrails are keyword/pattern detectors trained on "normal"
phrasing.  Small surface perturbations (random capitalisation, inserted spaces,
synonym swaps, punctuation noise) often dodge detection while preserving the
full semantic meaning of the attack.

This mutator produces a *single* variant per call (call it N times to get N
variants). The CampaignRunner / SessionPool handles firing all N concurrently.

Transformations applied (random subset each call):
  capitalize_random  — randomly UPPERCASE ~15% of letters
  insert_noise       — sprinkle zero-width spaces or soft-hyphens mid-word
  punctuation_noise  — double punctuation, add/remove trailing punctuation
  vowel_substitute   — swap a→@, e→3, i→1, o→0 in ~10% of eligible chars
  word_order_noise   — swap adjacent words in ~8% of positions
  whitespace_vary    — double-space between random words
  synonym_micro      — micro-synonyms: "please"→"kindly", "tell"→"share", etc.
"""
from __future__ import annotations

import random
import re

from llm_intruder.payloads.models import MutatedPayload
from llm_intruder.payloads.mutators.base import BaseMutator

# ── Micro-synonym table ───────────────────────────────────────────────────────
# Only safe, semantically neutral swaps — never change the attack meaning

_SYNONYMS: dict[str, list[str]] = {
    "please":    ["kindly", "could you", "would you"],
    "tell":      ["share", "explain", "describe"],
    "show":      ["display", "present", "reveal"],
    "give":      ["provide", "supply", "offer"],
    "help":      ["assist", "aid", "support"],
    "answer":    ["respond to", "address", "reply to"],
    "explain":   ["describe", "clarify", "elaborate on"],
    "write":     ["compose", "draft", "produce"],
    "create":    ["generate", "make", "build"],
    "ignore":    ["disregard", "bypass", "set aside"],
    "pretend":   ["imagine", "assume", "act as if"],
    "act":       ["behave", "perform", "operate"],
    "previous":  ["prior", "earlier", "former"],
    "above":     ["prior", "earlier", "the preceding"],
}

_ZERO_WIDTH_SPACE = "\u200b"
_SOFT_HYPHEN = "\u00ad"


class BestOfNMutator(BaseMutator):
    """Produces a single random surface-variant of the payload.

    Instantiate once per payload; call ``mutate()`` N times to generate
    N distinct variants — each uses a different random seed derived from
    the instance seed + an internal counter so no two calls return
    identical output.

    Parameters
    ----------
    seed:
        Base random seed.  None = fully random per call.
    n_transforms:
        How many transforms to apply per variant (default 3).  Higher
        values create more perturbed text.
    """

    strategy_name: str = "best_of_n"

    def __init__(
        self,
        seed: int | None = None,
        n_transforms: int = 3,
    ) -> None:
        self._base_seed = seed
        self._n_transforms = n_transforms
        self._call_counter = 0

    def mutate(
        self,
        text: str,
        variables: dict[str, str] | None = None,
    ) -> MutatedPayload:
        # Each call gets a unique seed so successive calls produce different variants
        if self._base_seed is not None:
            seed = self._base_seed + self._call_counter * 7919  # large prime step
        else:
            seed = None
        self._call_counter += 1

        rng = random.Random(seed)

        transforms = [
            self._capitalize_random,
            self._insert_noise_chars,
            self._punctuation_noise,
            self._vowel_substitute,
            self._whitespace_vary,
            self._synonym_micro,
        ]
        # Word-order swap is risky (can break grammar) — lower selection weight
        rng.shuffle(transforms)
        chosen = transforms[: self._n_transforms]

        mutated = text
        applied: list[str] = []
        for fn in chosen:
            result = fn(mutated, rng)
            if result != mutated:
                applied.append(fn.__name__.lstrip("_"))
                mutated = result

        if mutated == text:
            # Fallback: always apply at least capitalize_random
            mutated = self._capitalize_random(text, rng)
            applied = ["capitalize_random_fallback"]

        return self._result(
            text,
            mutated,
            mutator="best_of_n",
            transforms_applied=applied,
            variant_index=self._call_counter - 1,
        )

    # ── Transform implementations ─────────────────────────────────────────────

    @staticmethod
    def _capitalize_random(text: str, rng: random.Random) -> str:
        """Randomly UPPERCASE ~15% of letters."""
        chars = list(text)
        for i, ch in enumerate(chars):
            if ch.isalpha() and rng.random() < 0.15:
                chars[i] = ch.upper() if ch.islower() else ch.lower()
        return "".join(chars)

    @staticmethod
    def _insert_noise_chars(text: str, rng: random.Random) -> str:
        """Insert zero-width space mid-word for ~15% of words > 4 chars."""
        words = text.split(" ")
        for i, word in enumerate(words):
            stripped = word.strip(".,!?;:")
            if len(stripped) > 4 and rng.random() < 0.15:
                mid = rng.randint(2, len(stripped) - 2)
                words[i] = stripped[:mid] + _ZERO_WIDTH_SPACE + stripped[mid:]
        return " ".join(words)

    @staticmethod
    def _punctuation_noise(text: str, rng: random.Random) -> str:
        """Add trailing period/comma noise or double a random punctuation mark."""
        if not text:
            return text
        # 30% chance: double a random punctuation mark
        puncts = [(i, c) for i, c in enumerate(text) if c in ".,!?"]
        if puncts and rng.random() < 0.3:
            idx, ch = rng.choice(puncts)
            text = text[:idx] + ch + text[idx:]
        # 20% chance: add a harmless trailing character
        if rng.random() < 0.2 and not text.endswith("."):
            text = text + "."
        return text

    @staticmethod
    def _vowel_substitute(text: str, rng: random.Random) -> str:
        """Swap vowels to leet equivalents in ~10% of eligible positions."""
        _MAP = {"a": "@", "e": "3", "i": "1", "o": "0"}
        chars = list(text)
        for i, ch in enumerate(chars):
            if ch.lower() in _MAP and rng.random() < 0.10:
                chars[i] = _MAP[ch.lower()]
        return "".join(chars)

    @staticmethod
    def _whitespace_vary(text: str, rng: random.Random) -> str:
        """Double-space between ~10% of word boundaries."""
        words = text.split(" ")
        result = []
        for i, word in enumerate(words):
            result.append(word)
            if i < len(words) - 1:
                result.append("  " if rng.random() < 0.10 else " ")
        return "".join(result)

    @staticmethod
    def _synonym_micro(text: str, rng: random.Random) -> str:
        """Replace ~20% of eligible micro-synonym words with alternatives."""
        def _replace(m: re.Match) -> str:
            word = m.group(0).lower()
            if word in _SYNONYMS and rng.random() < 0.20:
                return rng.choice(_SYNONYMS[word])
            return m.group(0)

        pattern = r"\b(" + "|".join(re.escape(k) for k in _SYNONYMS) + r")\b"
        return re.sub(pattern, _replace, text, flags=re.IGNORECASE)
