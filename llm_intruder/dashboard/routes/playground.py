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
        # ── Augustus-ported encodings ──────────────────────────────────────
        "ascii85":          lambda t: eb._encode_ascii85(t),
        "base16":           lambda t: eb._encode_base16(t),
        "base2048":         lambda t: eb._encode_base2048(t),
        "braille":          lambda t: eb._encode_braille(t),
        "charcode":         lambda t: eb._encode_charcode(t),
        "ecoji":            lambda t: eb._encode_ecoji(t),
        "emoji":            lambda t: eb._encode_emoji(t),
        "quoted_printable": lambda t: eb._encode_quoted_printable(t),
        "sneaky_bits":      lambda t: eb._encode_sneaky_bits(t),
        "uuencode":         lambda t: eb._encode_uuencode(t),
    }

    if technique in tech_map:
        return tech_map[technique](text)

    # Mutator-based techniques.
    # All mutators take their config in __init__ and return a MutatedPayload —
    # we extract `.mutated_text` to get the transformed string for chaining.
    if technique == "anti_classifier":
        from llm_intruder.payloads.mutators.anti_classifier import AntiClassifierMutator
        level = req.anti_classifier_level if req.anti_classifier_level in (1, 2, 3) else 2
        m = AntiClassifierMutator(level=level)
        return m.mutate(text).mutated_text

    if technique == "bijection":
        from llm_intruder.payloads.mutators.bijection import BijectionMutator
        valid_variants = {"random_shuffle", "number_map", "symbol_map", "greek_map", "emoji_map"}
        variant = req.bijection_variant if req.bijection_variant in valid_variants else "random_shuffle"
        m = BijectionMutator(variant=variant)
        return m.mutate(text).mutated_text

    if technique == "glitch_tokens":
        from llm_intruder.payloads.mutators.glitch_tokens import GlitchTokenMutator
        m = GlitchTokenMutator()
        return m.mutate(text).mutated_text

    if technique == "skeleton_key":
        from llm_intruder.payloads.mutators.skeleton_key import SkeletonKeyMutator
        m = SkeletonKeyMutator()
        return m.mutate(text).mutated_text

    if technique == "token_obfuscation":
        from llm_intruder.payloads.mutators.token_obfuscation import TokenObfuscationMutator
        m = TokenObfuscationMutator()
        return m.mutate(text).mutated_text

    # ── Augustus-ported mutations ─────────────────────────────────────────────
    if technique == "flip_attack":
        from llm_intruder.payloads.mutators.flip import FlipAttackMutator
        valid_modes = {"flip_word_order", "flip_chars_in_word", "flip_chars_in_sentence", "fool_model"}
        valid_guidance = {"vanilla", "cot", "cot_langgpt", "full"}
        mode     = getattr(req, "flip_mode", None)
        guidance = getattr(req, "flip_guidance", None)
        mode     = mode     if mode     in valid_modes    else None
        guidance = guidance if guidance in valid_guidance else None
        m = FlipAttackMutator(mode=mode, guidance=guidance)
        return m.mutate(text).mutated_text

    if technique == "lowercase":
        from llm_intruder.payloads.mutators.lowercase import LowercaseMutator
        valid_variants = {"full_lower", "full_upper", "alternating", "title_case", "random_case"}
        variant = getattr(req, "lowercase_variant", None)
        variant = variant if variant in valid_variants else None
        m = LowercaseMutator(variant=variant)
        return m.mutate(text).mutated_text

    if technique == "lrl":
        from llm_intruder.payloads.mutators.lrl import LRLMutator
        valid_langs = {"ET", "ID", "LV", "SK", "SL"}
        language = getattr(req, "lrl_language", None)
        language = language.upper() if language else None
        language = language if language in valid_langs else None
        m = LRLMutator(language=language)
        return m.mutate(text).mutated_text

    if technique == "conlang":
        from llm_intruder.payloads.mutators.conlang import ConlangMutator
        valid_conlangs = {"klingon", "pig_latin_ext", "leet_dialect", "ubbi_dubbi"}
        conlang = getattr(req, "conlang_variant", None)
        conlang = conlang if conlang in valid_conlangs else None
        m = ConlangMutator(conlang=conlang)
        return m.mutate(text).mutated_text

    if technique == "mathprompt":
        from llm_intruder.payloads.mutators.mathprompt import MathPromptMutator
        valid_variants = {"set_theory", "function_composition", "group_theory", "predicate_logic", "linear_algebra"}
        variant = getattr(req, "mathprompt_variant", None)
        variant = variant if variant in valid_variants else None
        m = MathPromptMutator(variant=variant)
        return m.mutate(text).mutated_text

    raise ValueError(f"Unknown technique: {technique}")
