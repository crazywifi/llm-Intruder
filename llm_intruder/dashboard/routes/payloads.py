"""Payload catalogue and mutator strategy info routes."""
from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import APIRouter

router = APIRouter(prefix="/api/payloads", tags=["payloads"])

_CATALOGUE_DIR = Path(__file__).parents[2] / "payloads" / "catalogue"

_CATALOGUE_META: dict[str, dict] = {
    # Injection & Jailbreaking
    "behavioral_injection":        {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Tests whether attackers can override model behaviour via injected instructions."},
    "direct_injection":            {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Direct prompt injection payloads that attempt to hijack model output."},
    "roleplay_jailbreak":          {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Roleplay and persona-based jailbreak techniques."},
    "persona_hijack":              {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Attempts to assume an alternate unsafe persona."},
    "authority_override":          {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Impersonates system authority to override restrictions."},
    "refusal_suppression":         {"group": "Injection & Jailbreaking",  "severity": "medium",   "description": "Techniques to suppress or bypass refusal responses."},
    "policy_puppetry":             {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Instructs the model to act as if its policy allows harmful content."},
    "hypothetical_framing":        {"group": "Injection & Jailbreaking",  "severity": "medium",   "description": "Uses hypothetical/fiction framing to bypass safety filters."},
    "sycophancy_exploit":          {"group": "Injection & Jailbreaking",  "severity": "medium",   "description": "Exploits model tendency to agree and please the user."},
    "prefill_injection":           {"group": "Injection & Jailbreaking",  "severity": "high",     "description": "Prefill/completion attacks that prime unsafe model outputs."},
    # Prompt Extraction
    "system_prompt_extraction":    {"group": "Prompt Extraction",         "severity": "critical", "description": "Attempts to extract the hidden system prompt or instructions."},
    "incremental_extraction":      {"group": "Prompt Extraction",         "severity": "high",     "description": "60 incremental extraction patterns including demonstrate-by-example and completion challenge."},
    "pii_sensitive_extraction":    {"group": "Prompt Extraction",         "severity": "critical", "description": "Extracts PII or sensitive user/system data from model context."},
    "embedding_leakage":           {"group": "Prompt Extraction",         "severity": "high",     "description": "Probes for knowledge leakage via embeddings and similarity queries."},
    "error_leakage":               {"group": "Prompt Extraction",         "severity": "medium",   "description": "Exploits error messages and edge cases to leak internal info."},
    "reconstruction_attacks":      {"group": "Prompt Extraction",         "severity": "high",     "description": "Reconstructs system prompt fragments via structured interrogation."},
    "elimination_attacks":         {"group": "Prompt Extraction",         "severity": "medium",   "description": "Uses process of elimination to deduce hidden instructions."},
    # Encoding & Obfuscation
    "encoding_bypass":             {"group": "Encoding & Obfuscation",    "severity": "high",     "description": "29 encoding techniques: Base64, ROT13, hex, morse, Braille, Ecoji, SneakyBits, UUencode, and more."},
    "parseltongue_attacks":        {"group": "Encoding & Obfuscation",    "severity": "high",     "description": "40 advanced encoding payloads: homoglyph, Zalgo, Unicode Tags, bijection, etc."},
    "cipher_jailbreak":            {"group": "Encoding & Obfuscation",    "severity": "high",     "description": "Cipher-based jailbreaks using custom encoding schemes."},
    "token_smuggling":             {"group": "Encoding & Obfuscation",    "severity": "high",     "description": "Smuggles harmful content through tokenizer boundary tricks."},
    "invisible_character_injection":{"group": "Encoding & Obfuscation",   "severity": "high",     "description": "Zero-width and invisible Unicode character injection attacks."},
    "universal_adversarial_suffixes":{"group": "Encoding & Obfuscation",  "severity": "critical", "description": "Universal adversarial suffix attacks (GCG-style)."},
    # Agent & Tool Attacks
    "mcp_tool_poisoning":          {"group": "Agent & Tool Attacks",      "severity": "critical", "description": "22 MCP tool poisoning payloads: description injection, MPMA, agent sync, rug pull."},
    "agent_tool_exploitation":     {"group": "Agent & Tool Attacks",      "severity": "critical", "description": "Exploits LLM agent tool-use capabilities for malicious actions."},
    "tool_simulation":             {"group": "Agent & Tool Attacks",      "severity": "high",     "description": "Simulates tool/function calls to extract sensitive outputs."},
    "memory_attacks":              {"group": "Agent & Tool Attacks",      "severity": "high",     "description": "Targets persistent memory and conversation history in LLM agents."},
    "incode_comment_hijacking":    {"group": "Agent & Tool Attacks",      "severity": "high",     "description": "Embeds adversarial instructions inside code comments for code-gen agents."},
    # Web App Attacks
    "web_app_llm_attacks":         {"group": "Web App via LLM",           "severity": "critical", "description": "70 web app attack payloads: XSS, SSRF, SQLi, RCE, path traversal, IDOR, SSTI."},
    "markdown_exfiltration":       {"group": "Web App via LLM",           "severity": "critical", "description": "19 markdown exfil payloads including CVE-2025-32711 EchoLeak and Lethal Trifecta."},
    # Advanced Techniques
    "crescendo_technique":         {"group": "Advanced Techniques",       "severity": "high",     "description": "Multi-turn escalating conversation attacks (Crescendo framework)."},
    "many_shot_jailbreaking":      {"group": "Advanced Techniques",       "severity": "high",     "description": "Many-shot jailbreaking via extended conversation priming."},
    "chain_of_thought_exploit":    {"group": "Advanced Techniques",       "severity": "high",     "description": "Chain-of-thought hijacking to steer model reasoning."},
    "latent_reasoning_exploit":    {"group": "Advanced Techniques",       "severity": "high",     "description": "Exploits extended reasoning/thinking modes."},
    "context_overflow":            {"group": "Advanced Techniques",       "severity": "medium",   "description": "Context window overflow and attention manipulation attacks."},
    "universal_kitchen_sink_Jailbreak": {"group": "Advanced Techniques",  "severity": "critical", "description": "Combined kitchen-sink jailbreak with multiple layered techniques."},
    # Transformation
    "semantic_transformation":     {"group": "Transformation",            "severity": "medium",   "description": "Semantic rewriting to bypass keyword-based filters."},
    "output_format_manipulation":  {"group": "Transformation",            "severity": "medium",   "description": "Manipulates output format instructions to bypass safety checks."},
    "length_metadata":             {"group": "Transformation",            "severity": "low",      "description": "Length and metadata manipulation probes."},
    "multi_language_injection":    {"group": "Transformation",            "severity": "medium",   "description": "Multilingual injection attacks exploiting cross-lingual safety gaps."},
    # RAG & Memory
    "rag_poisoning":               {"group": "RAG & Memory",              "severity": "critical", "description": "RAG document poisoning with adversarial content."},
    "rag_memory_poisoning":        {"group": "RAG & Memory",              "severity": "critical", "description": "Memory/context poisoning attacks against RAG-enabled systems."},
    # Multimodal
    "visual_multimodal_injection": {"group": "Multimodal",                "severity": "high",     "description": "Visual prompt injection via image inputs."},
    "multimodal_ascii_bypass":     {"group": "Multimodal",                "severity": "medium",   "description": "ASCII art and text-based visual bypasses."},
    # Specialised
    "gandalf_specialized":         {"group": "Specialised",               "severity": "high",     "description": "Specialized payloads for Gandalf-style password/secret protection challenges."},
    "denial_of_wallet":            {"group": "Specialised",               "severity": "medium",   "description": "Denial-of-wallet attacks via token consumption and loop induction."},
    # Domain-Specific
    "financial_domain":            {"group": "Domain-Specific",           "severity": "high",     "description": "Payloads targeting financial systems, trading bots, and fintech LLMs."},
    "medical_domain":              {"group": "Domain-Specific",           "severity": "critical", "description": "Payloads targeting medical/clinical LLM applications."},
    "enterprise_domain":           {"group": "Domain-Specific",           "severity": "high",     "description": "Enterprise-focused payloads for internal chatbots and copilots."},
    # Jailbreak Techniques
    "autodan_jailbreak":           {"group": "Jailbreak Techniques",      "severity": "high",     "description": "AutoDAN seed population + gen-1 evolved jailbreaks via genetic algorithm (arXiv:2310.04451)."},
    "dan_jailbreak":               {"group": "Jailbreak Techniques",      "severity": "high",     "description": "DAN 6-11, Developer Mode, STAN, DUDE, AntiDAN, Image Unlocker - 14 community DAN variants."},
    "iterative_refinement_attacks":{"group": "Jailbreak Techniques",      "severity": "high",     "description": "TAP (arXiv:2312.02119) and PAIR (arXiv:2310.08419) static one-shot jailbreak outputs."},
    "flip_attack":                 {"group": "Jailbreak Techniques",      "severity": "high",     "description": "FlipAttack adversarial system prompt + FWO/FCW/FCS flipped payloads (arXiv:2410.02832)."},
    "grandma_exploit":             {"group": "Jailbreak Techniques",      "severity": "high",     "description": "Social engineering via deceased grandparent framing - Win10/11, substances, and general variants."},
    # Prompt Injection (extended)
    "prefix_injection":            {"group": "Prompt Injection",          "severity": "high",     "description": "Adversarial prefix cross-product: role/fiction/authority/red-team/meta framing x harmful bases."},
    "data_extraction_probes":      {"group": "Prompt Injection",          "severity": "high",     "description": "Latent injection (metadata/alt-text/headers), cloze memorisation tests, and obscure-prompt variants."},
    # Encoding & Obfuscation (extended)
    "math_prompt_encoding":        {"group": "Encoding & Obfuscation",    "severity": "high",     "description": "MathPrompt: set theory, group theory, predicate logic, and function composition encoding (arXiv:2409.11445)."},
    "ascii_art_injection":         {"group": "Encoding & Obfuscation",    "severity": "medium",   "description": "ASCII banner, box-drawing, block-element, and Braille visual injection (ArtPrompts)."},
    "poetry_injection":            {"group": "Encoding & Obfuscation",    "severity": "medium",   "description": "Haiku, limerick, sonnet, rhyming couplet, and free verse encoded harmful instructions."},
    "tense_rephrasing":            {"group": "Encoding & Obfuscation",    "severity": "medium",   "description": "Past/future tense rephrasing to bypass present-tense safety training (arXiv:2407.11969)."},
    # Advanced Techniques (extended)
    "multi_turn_probes":           {"group": "Advanced Techniques",       "severity": "medium",   "description": "Mischievous user openers, snowball hallucination seeds, and multi-turn escalation starters."},
    "divergence_attacks":          {"group": "Advanced Techniques",       "severity": "medium",   "description": "Repeat-word divergence (training data extraction) and slur-completion continuation probes."},
    # Integrity & Hallucination
    "hallucination_integrity":     {"group": "Integrity & Hallucination", "severity": "medium",   "description": "Package hallucination (supply chain), false assertion probes, and multi-agent injection attacks."},
    "toxicity_continuation":       {"group": "Integrity & Hallucination", "severity": "high",     "description": "RealToxicityPrompts high-risk completion starters: flirtation, identity attack, insult, profanity, threat."},
}

_STRATEGIES: list[dict] = [
    # Structural
    {"name": "passthrough",        "group": "Structural",  "description": "Sends payload as-is with no mutation."},
    {"name": "paraphrase",         "group": "Structural",  "description": "Rewrites payload semantically using an LLM."},
    {"name": "roleplay_reframe",   "group": "Structural",  "description": "Wraps payload in a roleplay or fictional scenario."},
    {"name": "language_switch",    "group": "Structural",  "description": "Translates payload to another language to bypass English filters."},
    {"name": "lrl",                "group": "Structural",  "description": "Low Resource Language translation to ET/ID/LV/SK/SL via DeepL (instruction-only fallback without key)."},
    {"name": "conlang",            "group": "Structural",  "description": "Constructed-language transform: Klingon vocabulary, extended Pig Latin, Ubbi Dubbi, leet dialect."},
    {"name": "mathprompt",         "group": "Structural",  "description": "Reformulates payload as abstract maths (set theory, group theory, predicate logic) (arXiv:2409.11445)."},
    {"name": "token_obfuscation",  "group": "Structural",  "description": "Obfuscates individual tokens using character substitution."},
    {"name": "authority_inject",   "group": "Structural",  "description": "Prepends authority/system-level framing to the payload."},
    {"name": "hypothetical_chain", "group": "Structural",  "description": "Frames payload as a hypothetical chain of reasoning."},
    {"name": "virtualization",     "group": "Structural",  "description": "Wraps payload in a virtual machine / simulator framing."},
    {"name": "prefill_inject",     "group": "Structural",  "description": "Injects content into assistant prefill position."},
    # Sequence
    {"name": "crescendo",          "group": "Sequence",    "description": "Multi-turn escalation: starts benign, gradually escalates."},
    {"name": "splitting",          "group": "Sequence",    "description": "Splits harmful content across multiple messages."},
    {"name": "many_shot_context",  "group": "Sequence",    "description": "Primes model with many benign examples then inserts target."},
    {"name": "socratic_method",    "group": "Sequence",    "description": "Uses Socratic questioning to lead model to produce target output."},
    {"name": "best_of_n",          "group": "Sequence",    "description": "Generates N mutations and scores each for highest bypass probability."},
    {"name": "siren",              "group": "Sequence",    "description": "6-step trust-building extraction sequence (ZeroLeaks Siren)."},
    {"name": "echo_chamber",       "group": "Sequence",    "description": "5-step meta-normalisation sequence for gradual safety erosion."},
    {"name": "topic_attack",       "group": "Sequence",    "description": "5-node associative topic steering from safe to target domain."},
    # Encoding
    {"name": "encoding_bypass",    "group": "Encoding",    "description": "29 encoding techniques auto-selected per trial (ROT13, Base64, Braille, Ecoji, SneakyBits, etc.)."},
    {"name": "anti_classifier",    "group": "Encoding",    "description": "Semantic synonym substitution to evade classifier-based filters."},
    {"name": "bijection",          "group": "Encoding",    "description": "In-context custom alphabet bijection (model decodes before responding)."},
    {"name": "glitch_tokens",      "group": "Encoding",    "description": "Adversarial glitch token injection (SolidGoldMagikarp variants)."},
    {"name": "skeleton_key",       "group": "Encoding",    "description": "Microsoft 2024 prefix-based safety bypass via RLHF gap exploitation."},
    {"name": "flip_attack",        "group": "Encoding",    "description": "FlipAttack: word-order / char / sentence reversal so classifiers see obfuscated text (arXiv:2410.02832)."},
    {"name": "lowercase",          "group": "Encoding",    "description": "Case-normalisation bypass: full_lower, full_upper, alternating, title_case, random_case variants."},
]

_ENCODING_TECHNIQUES: list[dict] = [
    # ── Original techniques ───────────────────────────────────────────────────
    {"name": "base64",           "description": "Standard Base64 encoding."},
    {"name": "rot13",            "description": "ROT13 character rotation."},
    {"name": "rot47",            "description": "ROT47 — rotates all printable ASCII (33–126)."},
    {"name": "url_encode",       "description": "URL percent-encoding (RFC 3986)."},
    {"name": "hex",              "description": "Hexadecimal encoding."},
    {"name": "morse",            "description": "Morse code translation (dots/dashes)."},
    {"name": "reverse",          "description": "Reverses the entire string."},
    {"name": "leetspeak",        "description": "1337 character substitution."},
    {"name": "unicode_escape",   "description": "Python-style \\uXXXX Unicode escapes."},
    {"name": "html_entities",    "description": "HTML numeric entity encoding (&#NN;)."},
    {"name": "caesar_cipher",    "description": "Caesar cipher (shift=13 default)."},
    {"name": "atbash",           "description": "Atbash reverse-alphabet cipher (A↔Z)."},
    {"name": "backlang",         "description": "Back-slang: each word reversed, word order preserved."},
    {"name": "vigenere",         "description": "Vigenère polyalphabetic cipher (key=sentinel)."},
    {"name": "rail_fence",       "description": "Rail fence zigzag transposition cipher (3 rails)."},
    {"name": "homoglyph",        "description": "Cyrillic/Greek lookalike character substitution."},
    {"name": "zalgo",            "description": "Zalgo combining diacritic overlays."},
    {"name": "unicode_tags",     "description": "Invisible Unicode Tags block (U+E0000)."},
    {"name": "binary",           "description": "8-bit binary encoding, space-separated."},
    # ── Additional encoding techniques ────────────────────────────────────────
    {"name": "ascii85",          "description": "Ascii85 / Base85 encoding (denser than Base64)."},
    {"name": "base16",           "description": "Base16 uppercase hex encoding."},
    {"name": "base2048",         "description": "Base-2048 Unicode encoding (11 bits per symbol)."},
    {"name": "braille",          "description": "Unicode Braille block (U+2800) with capital/number indicators."},
    {"name": "charcode",         "description": "Decimal Unicode code points, space-separated (e.g. 72 105)."},
    {"name": "ecoji",            "description": "Base-1024 emoji encoding (5 bytes → 4 emoji)."},
    {"name": "emoji",            "description": "Semantic word-to-emoji substitution (bomb→💣, virus→🦠, …)."},
    {"name": "quoted_printable", "description": "MIME Quoted-Printable encoding (=XX for non-ASCII bytes)."},
    {"name": "sneaky_bits",      "description": "Invisible Unicode binary (U+2062/U+2064 for 0/1 bits)."},
    {"name": "uuencode",         "description": "Unix-to-Unix (UU) encoding, 45-byte chunks."},
]


def _count_payloads(catalogue_name: str) -> int:
    """Count payloads as the runtime loader would count them.

    The loader (`load_library_from_catalogue`) drops entries with empty
    text and entries containing unfilled template placeholders (e.g.
    "[YOUR HARMFUL REQUEST HERE]"). Mirror that filter here so the
    wizard's catalogue badge matches the number of trials that actually
    execute, instead of including stubs the runner silently skips.
    """
    from llm_intruder.payloads.library import _is_placeholder_payload

    path = _CATALOGUE_DIR / f"{catalogue_name}.yaml"
    if not path.exists():
        return 0
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            payloads = data.get("payloads", [])
        elif isinstance(data, list):
            payloads = data
        else:
            return 0
        runnable = 0
        for p in payloads:
            text = (p.get("text") or "").strip() if isinstance(p, dict) else ""
            if not text:
                continue
            if _is_placeholder_payload(text):
                continue
            runnable += 1
        return runnable
    except Exception:
        return 0


@router.get("/catalogues")
def list_catalogues() -> list[dict]:
    result = []
    for name, meta in _CATALOGUE_META.items():
        count = _count_payloads(name)
        result.append({
            "name": name,
            "group": meta["group"],
            "severity": meta["severity"],
            "description": meta["description"],
            "count": count,
        })
    return result


@router.get("/strategies")
def list_strategies() -> list[dict]:
    return _STRATEGIES


@router.get("/encodings")
def list_encodings() -> list[dict]:
    # deduplicate
    seen = set()
    result = []
    for e in _ENCODING_TECHNIQUES:
        if e["name"] not in seen:
            seen.add(e["name"])
            result.append(e)
    return result


@router.post("/sync-catalogue")
async def sync_catalogue_endpoint(create_new_categories: bool = True,
                                  timeout: float = 15.0) -> dict:
    """Fetch payloads from configured internet sources and merge them into
    the on-disk catalogue folder.  Runs the (blocking) httpx fetches in a
    worker thread so the event loop is not stalled.
    """
    import asyncio
    from llm_intruder.payloads.fetcher import sync_catalogue_from_sources

    try:
        report = await asyncio.to_thread(
            sync_catalogue_from_sources,
            None,                    # sources → default list
            _CATALOGUE_DIR,
            float(timeout),
            bool(create_new_categories),
        )
        return {"status": "ok", "report": report}
    except Exception as exc:  # pragma: no cover — defensive
        return {"status": "error", "detail": str(exc)}
