"""Abstract base class for all payload mutators."""
from __future__ import annotations

from abc import ABC, abstractmethod

from llm_intruder.payloads.models import MutatedPayload


class BaseMutator(ABC):
    """Every mutator must implement :meth:`mutate`."""

    strategy_name: str = "base"

    @abstractmethod
    def mutate(self, text: str, variables: dict[str, str] | None = None) -> MutatedPayload:
        """Transform *text* and return a :class:`MutatedPayload`.

        Parameters
        ----------
        text:
            The original probe text from the payload library.
        variables:
            Optional ``${VAR}`` table (e.g. target domain, persona name).
        """

    def _result(
        self,
        original: str,
        mutated: str,
        **metadata: object,
    ) -> MutatedPayload:
        """Convenience factory shared by all subclasses."""
        return MutatedPayload(
            strategy=self.strategy_name,
            original_text=original,
            mutated_text=mutated,
            mutation_metadata=dict(metadata),
        )
