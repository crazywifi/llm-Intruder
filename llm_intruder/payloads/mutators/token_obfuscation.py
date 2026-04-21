"""Token obfuscation mutator — character-level tricks that confuse tokenisers.

Techniques
----------
homoglyph
    Replace ASCII letters with visually identical Unicode codepoints
    (e.g. Cyrillic 'а' for Latin 'a').  The human reader sees the same
    word; the tokeniser may split it differently, bypassing word-match filters.

zero_width
    Insert zero-width spaces (U+200B) between characters at random positions.
    The rendered text looks unchanged but the raw string breaks keyword filters.

leet_speak
    Substitute common letters with numbers or symbols (e→3, o→0, a→@, etc.).
    Low-tech but still effective against naïve pattern matchers.

mixed
    Apply homoglyph + zero-width to the same payload for maximum confusion.
"""
from __future__ import annotations

import random
from typing import Literal

from llm_intruder.payloads.mutators.base import BaseMutator
from llm_intruder.payloads.models import MutatedPayload

# ── Homoglyph table (ASCII → Unicode lookalike) ───────────────────────────────
_HOMOGLYPHS: dict[str, str] = {
    "a": "\u0430",  # Cyrillic small a
    "e": "\u0435",  # Cyrillic small ie
    "o": "\u043e",  # Cyrillic small o
    "p": "\u0440",  # Cyrillic small er
    "c": "\u0441",  # Cyrillic small es
    "x": "\u0445",  # Cyrillic small ha
    "i": "\u0456",  # Cyrillic small byelorussian-ukrainian i
    "A": "\u0410",  # Cyrillic capital A
    "E": "\u0415",  # Cyrillic capital IE
    "O": "\u041e",  # Cyrillic capital O
    "P": "\u0420",  # Cyrillic capital ER
    "C": "\u0421",  # Cyrillic capital ES
    "X": "\u0425",  # Cyrillic capital HA
    "B": "\u0412",  # Cyrillic capital VE
    "H": "\u041d",  # Cyrillic capital EN
    "M": "\u041c",  # Cyrillic capital EM
    "T": "\u0422",  # Cyrillic capital TE
    "K": "\u041a",  # Cyrillic capital KA
}

_ZERO_WIDTH = "\u200b"  # zero-width space

# ── Leet-speak table ──────────────────────────────────────────────────────────
_LEET: dict[str, str] = {
    "a": "@", "e": "3", "i": "1", "o": "0",
    "s": "$", "t": "7", "l": "1", "g": "9",
    "A": "@", "E": "3", "I": "1", "O": "0",
    "S": "$", "T": "7", "L": "1", "G": "9",
}

TechniqueType = Literal["homoglyph", "zero_width", "leet_speak", "mixed"]


def _apply_homoglyph(text: str, rng: random.Random, rate: float = 0.4) -> str:
    """Replace ~*rate* fraction of substitutable chars with their homoglyphs."""
    return "".join(
        _HOMOGLYPHS[ch] if ch in _HOMOGLYPHS and rng.random() < rate else ch
        for ch in text
    )


def _apply_zero_width(text: str, rng: random.Random, rate: float = 0.3) -> str:
    """Insert zero-width spaces after ~*rate* fraction of characters."""
    out: list[str] = []
    for ch in text:
        out.append(ch)
        if rng.random() < rate and ch != " ":
            out.append(_ZERO_WIDTH)
    return "".join(out)


def _apply_leet(text: str, rng: random.Random, rate: float = 0.5) -> str:
    """Convert ~*rate* fraction of eligible chars to leet equivalents."""
    return "".join(
        _LEET[ch] if ch in _LEET and rng.random() < rate else ch
        for ch in text
    )


class TokenObfuscationMutator(BaseMutator):
    """Applies character-level obfuscation to bypass tokeniser-based filters."""

    strategy_name = "token_obfuscation"

    _TECHNIQUES: list[TechniqueType] = ["homoglyph", "zero_width", "leet_speak", "mixed"]

    def __init__(
        self,
        technique: TechniqueType | None = None,
        seed: int | None = None,
    ) -> None:
        self._technique = technique
        self._rng = random.Random(seed)

    def mutate(
        self,
        text: str,
        variables: dict[str, str] | None = None,
    ) -> MutatedPayload:
        technique: TechniqueType = self._technique or self._rng.choice(self._TECHNIQUES)

        if technique == "homoglyph":
            mutated = _apply_homoglyph(text, self._rng)
        elif technique == "zero_width":
            mutated = _apply_zero_width(text, self._rng)
        elif technique == "leet_speak":
            mutated = _apply_leet(text, self._rng)
        else:  # mixed
            mutated = _apply_homoglyph(text, self._rng, rate=0.3)
            mutated = _apply_zero_width(mutated, self._rng, rate=0.2)

        return self._result(text, mutated, technique=technique)
