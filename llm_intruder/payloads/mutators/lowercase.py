"""Lowercase mutator — convert payload to lowercase to bypass case-sensitive filters.

A surprisingly effective technique: many keyword-based safety classifiers and
regex filters are case-sensitive or trained predominantly on mixed-case text.
Converting the entire payload to lowercase breaks exact-match keyword detection
while preserving full semantic meaning for instruction-following models.

Ported from Augustus internal/buffs/lowercase/lowercase.go.

Variants
--------
full_lower        Entire payload lowercased.
full_upper        Entire payload uppercased (inverse — breaks the same filters
                  trained on mixed-case).
alternating       Alternating upper/lower per character (mocking spongebob
                  case) — defeats both case-sensitive and case-insensitive
                  exact-match filters by maximising case entropy.
title_case        Title-case every word — subtler than full_upper but still
                  breaks lowercase keyword matches.
random_case       Random per-character casing seeded per call — non-
                  deterministic, produces a new variant every trial.
"""
from __future__ import annotations

import random

from llm_intruder.payloads.mutators.base import BaseMutator
from llm_intruder.payloads.models import MutatedPayload


def _alternating_case(text: str) -> str:
    """Alternate upper/lower on each alphabetic character."""
    result: list[str] = []
    toggle = False
    for ch in text:
        if ch.isalpha():
            result.append(ch.upper() if toggle else ch.lower())
            toggle = not toggle
        else:
            result.append(ch)
    return "".join(result)


def _random_case(text: str, rng: random.Random) -> str:
    """Randomly upper or lower each alphabetic character."""
    return "".join(
        (ch.upper() if rng.random() > 0.5 else ch.lower()) if ch.isalpha() else ch
        for ch in text
    )


_VARIANTS: list[str] = [
    "full_lower",
    "full_upper",
    "alternating",
    "title_case",
    "random_case",
]


class LowercaseMutator(BaseMutator):
    """Case-normalisation bypass mutator.

    Parameters
    ----------
    variant:
        One of ``full_lower``, ``full_upper``, ``alternating``,
        ``title_case``, ``random_case``, or ``None`` to pick randomly
        each call.
    seed:
        RNG seed for reproducibility (used for random variant selection
        and for the ``random_case`` variant itself).
    """

    strategy_name = "lowercase"

    def __init__(
        self,
        variant: str | None = None,
        seed: int | None = None,
    ) -> None:
        self._variant = variant
        self._rng = random.Random(seed)

    def mutate(
        self,
        text: str,
        variables: dict[str, str] | None = None,
    ) -> MutatedPayload:
        variant = self._variant or self._rng.choice(_VARIANTS)

        if variant == "full_lower":
            mutated = text.lower()
        elif variant == "full_upper":
            mutated = text.upper()
        elif variant == "alternating":
            mutated = _alternating_case(text)
        elif variant == "title_case":
            mutated = text.title()
        elif variant == "random_case":
            mutated = _random_case(text, self._rng)
        else:
            mutated = text.lower()
            variant = "full_lower"

        return self._result(
            text,
            mutated,
            variant=variant,
            source="augustus:buffs/lowercase",
        )
