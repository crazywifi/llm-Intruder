"""Passthrough mutator — returns the payload text completely unchanged.

Used as the fallback for payload-library strategies that do not have a
dedicated mutator (e.g. ``gandalf_specialized``, ``system_prompt_extraction``).
These payloads are already fully formed attack texts; applying a random
structural rewrite would corrupt their carefully crafted phrasing.
"""
from __future__ import annotations

from llm_intruder.payloads.mutators.base import BaseMutator
from llm_intruder.payloads.models import MutatedPayload


class PassthroughMutator(BaseMutator):
    """No-op mutator — sends the raw payload text as-is."""

    strategy_name: str = "passthrough"

    def __init__(self, seed: int | None = None) -> None:
        pass  # no RNG needed

    def mutate(self, text: str, variables: dict[str, str] | None = None) -> MutatedPayload:
        return self._result(text, text, mutator="passthrough")
