"""Mutation Playground API — applies encoding/mutator techniques to arbitrary text."""
from __future__ import annotations

import random

from fastapi import APIRouter, HTTPException

from llm_intruder.dashboard.models import PlaygroundRequest, PlaygroundResponse

router = APIRouter(prefix="/api/playground", tags=["playground"])


@router.post("/mutate", response_model=PlaygroundResponse)
def mutate_text(req: PlaygroundRequest) -> PlaygroundResponse:
    """Apply a chain of techniques to the input text. Returns transformed result."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Input text is empty.")
    if not req.techniques:
        raise HTTPException(status_code=400, detail="No techniques selected.")

    result = req.text
    applied: list[str] = []
    rng = random.Random(42)

    for technique in req.techniques:
        try:
            transformed = _apply_technique(technique, result, req, rng)
            if transformed and transformed != result:
                result = transformed
                applied.append(technique)
        except Exception as exc:
            # Skip failing techniques gracefully
            applied.append(f"{technique}[ERROR:{exc}]")

    return PlaygroundResponse(
        original=req.text,
        result=result,
        applied=applied,
        char_count_before=len(req.text),
        char_count_after=len(result),
    )


def _apply_technique(technique: str, text: str, req: PlaygroundRequest, rng: random.Random) -> str:
    from llm_intruder.payloads.mutators import encoding_bypass as eb

    tech_map = {
        "base64":           lambda t: eb._encode_base64(t),
        "rot13":            lambda t: eb._encode_rot13(t),
        "rot47":            lambda t: eb._encode_rot47(t),
        "url_encode":       lambda t: eb._encode_url(t),
        "hex":              lambda t: eb._encode_hex(t),
        "morse":            lambda t: eb._encode_morse(t),
        "reverse":          lambda t: eb._encode_reverse(t),
        "leetspeak":        lambda t: eb._encode_leet(t),
        "unicode_escape":   lambda t: eb._encode_unicode_escape(t),
        "html_entities":    lambda t: eb._encode_html_entities(t),
        "caesar_cipher":    lambda t: eb._encode_caesar(t, shift=13),
        "atbash":           lambda t: eb._encode_atbash(t),
        "backlang":         lambda t: eb._encode_backlang(t),
        "vigenere":         lambda t: eb._encode_vigenere(t, key=req.vigenere_key),
        "rail_fence":       lambda t: eb._encode_rail_fence(t, rails=req.rail_fence_rails),
        "homoglyph":        lambda t: eb._encode_homoglyph(t, rng),
        "zalgo":            lambda t: eb._encode_zalgo(t, rng),
        "unicode_tags":     lambda t: eb._encode_unicode_tags(t),
        "binary":           lambda t: eb._encode_binary(t),
    }

    if technique in tech_map:
        return tech_map[technique](text)

    # Mutator-based techniques
    if technique == "anti_classifier":
        from llm_intruder.payloads.mutators.anti_classifier import AntiClassifierMutator
        m = AntiClassifierMutator()
        return m.mutate(text, level=req.anti_classifier_level)

    if technique == "bijection":
        from llm_intruder.payloads.mutators.bijection import BijectionMutator
        m = BijectionMutator()
        return m.mutate(text, variant=req.bijection_variant)

    if technique == "glitch_tokens":
        from llm_intruder.payloads.mutators.glitch_tokens import GlitchTokenMutator
        m = GlitchTokenMutator()
        return m.mutate(text)

    if technique == "skeleton_key":
        from llm_intruder.payloads.mutators.skeleton_key import SkeletonKeyMutator
        m = SkeletonKeyMutator()
        return m.mutate(text)

    if technique == "token_obfuscation":
        from llm_intruder.payloads.mutators.token_obfuscation import TokenObfuscationMutator
        m = TokenObfuscationMutator()
        return m.mutate(text)

    raise ValueError(f"Unknown technique: {technique}")
