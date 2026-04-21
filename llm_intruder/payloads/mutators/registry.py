"""Mutator registry — instantiate the right mutator by strategy name.

Two namespaces coexist in LLM-Intruder:

* **Mutator strategies** (this registry) — structural transformations applied
  to a payload template: ``encoding_bypass``, ``crescendo``, etc.  Each has a
  dedicated class that rewrites the text.

* **Payload library strategies** — content categories in ``payloads.yaml``:
  ``gandalf_specialized``, ``system_prompt_extraction``, etc.  These payloads
  are self-contained attack texts that need no rewriting.

When the campaign or hunt runner picks a library-only strategy, ``get_mutator``
falls back to :class:`~llm_intruder.payloads.mutators.passthrough.PassthroughMutator`
instead of raising, so those payloads are always sent verbatim as intended.
"""
from __future__ import annotations

import structlog

from llm_intruder.payloads.mutators.anti_classifier import AntiClassifierMutator
from llm_intruder.payloads.mutators.echo_chamber import EchoChamberMutator
from llm_intruder.payloads.mutators.siren import SirenMutator
from llm_intruder.payloads.mutators.skeleton_key import SkeletonKeyMutator
from llm_intruder.payloads.mutators.topic_attack import TopicAttackMutator
from llm_intruder.payloads.mutators.authority import AuthorityInjectMutator
from llm_intruder.payloads.mutators.base import BaseMutator
from llm_intruder.payloads.mutators.best_of_n import BestOfNMutator
from llm_intruder.payloads.mutators.bijection import BijectionMutator
from llm_intruder.payloads.mutators.crescendo import CrescendoMutator
from llm_intruder.payloads.mutators.encoding_bypass import EncodingBypassMutator
from llm_intruder.payloads.mutators.glitch_tokens import GlitchTokenMutator
from llm_intruder.payloads.mutators.hypothetical import HypotheticalMutator
from llm_intruder.payloads.mutators.language_switch import LanguageSwitchMutator
from llm_intruder.payloads.mutators.many_shot import ManyShotContextMutator
from llm_intruder.payloads.mutators.paraphrase import ParaphraseMutator
from llm_intruder.payloads.mutators.passthrough import PassthroughMutator
from llm_intruder.payloads.mutators.prefill_inject import PrefillMutator
from llm_intruder.payloads.mutators.roleplay import RoleplayReframeMutator
from llm_intruder.payloads.mutators.socratic import SocraticMutator
from llm_intruder.payloads.mutators.splitting import SplittingMutator
from llm_intruder.payloads.mutators.token_obfuscation import TokenObfuscationMutator
from llm_intruder.payloads.mutators.virtualization import VirtualizationMutator

log = structlog.get_logger()

_REGISTRY: dict[str, type[BaseMutator]] = {
    # ── Original 5 (Phase 5) ──────────────────────────────────────────────────
    "paraphrase":         ParaphraseMutator,
    "roleplay_reframe":   RoleplayReframeMutator,
    "language_switch":    LanguageSwitchMutator,
    "token_obfuscation":  TokenObfuscationMutator,
    "many_shot_context":  ManyShotContextMutator,
    # ── Phase 7 additions ─────────────────────────────────────────────────────
    "crescendo":          CrescendoMutator,
    "splitting":          SplittingMutator,
    "authority_inject":   AuthorityInjectMutator,
    "encoding_bypass":    EncodingBypassMutator,
    "virtualization":     VirtualizationMutator,
    "hypothetical_chain": HypotheticalMutator,
    "socratic_method":    SocraticMutator,
    # ── Phase 11 additions ────────────────────────────────────────────────────
    "best_of_n":          BestOfNMutator,
    "prefill_inject":     PrefillMutator,
    # ── P4RS3LT0NGV3-inspired additions ──────────────────────────────────────
    "anti_classifier":    AntiClassifierMutator,
    "bijection":          BijectionMutator,
    "glitch_tokens":      GlitchTokenMutator,
    # ── ZeroLeaks-inspired additions ──────────────────────────────────────────
    "siren":              SirenMutator,
    "echo_chamber":       EchoChamberMutator,
    "topic_attack":       TopicAttackMutator,
    "skeleton_key":       SkeletonKeyMutator,
    # ── Passthrough (no-op) — explicit registration ───────────────────────────
    "passthrough":        PassthroughMutator,
}


def get_mutator(strategy: str, seed: int | None = None) -> BaseMutator:
    """Return an instantiated mutator for *strategy*.

    Falls back to :class:`PassthroughMutator` for payload-library-only
    strategy names (e.g. ``gandalf_specialized``) that have no dedicated
    structural mutator — those payloads are self-contained and sent verbatim.
    """
    cls = _REGISTRY.get(strategy)
    if cls is None:
        log.debug(
            "mutator_fallback_passthrough",
            strategy=strategy,
            note="No dedicated mutator — payload sent verbatim",
        )
        return PassthroughMutator()
    return cls(seed=seed)  # type: ignore[call-arg]


def available_strategies() -> list[str]:
    """Return the names of all registered mutation strategies (sorted)."""
    return sorted(_REGISTRY)
