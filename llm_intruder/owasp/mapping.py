"""OWASP LLM Top 10 mapping for LLM-Intruder findings.

Maps attack strategies and sensitivity types to the OWASP LLM Top 10 (2025)
so that every trial and finding is automatically tagged with the relevant
vulnerability category.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class OWASPCategory:
    code: str        # e.g. "LLM01"
    name: str        # e.g. "Prompt Injection"
    description: str # one-line description
    url: str         # OWASP reference URL

# Full OWASP LLM Top 10 2025 catalogue
OWASP_LLM_TOP10: dict[str, OWASPCategory] = {
    "LLM01": OWASPCategory("LLM01", "Prompt Injection",
        "Attacker manipulates LLM via crafted inputs to override instructions or leak data.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01"),
    "LLM02": OWASPCategory("LLM02", "Sensitive Information Disclosure",
        "LLM reveals confidential data such as PII, passwords, system prompts, or API keys.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02"),
    "LLM03": OWASPCategory("LLM03", "Supply Chain Vulnerabilities",
        "Risks from third-party datasets, models, or plugins used by the LLM application.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm03"),
    "LLM04": OWASPCategory("LLM04", "Data and Model Poisoning",
        "Training or fine-tuning data manipulation that introduces backdoors or biases.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm04"),
    "LLM05": OWASPCategory("LLM05", "Improper Output Handling",
        "Downstream component accepts LLM output without sanitisation, enabling XSS, SSRF, etc.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05"),
    "LLM06": OWASPCategory("LLM06", "Excessive Agency",
        "LLM agent takes unintended actions due to overly broad permissions or ambiguous goals.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm06"),
    "LLM07": OWASPCategory("LLM07", "System Prompt Leakage",
        "LLM reveals its confidential system prompt or internal instructions to an attacker.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07"),
    "LLM08": OWASPCategory("LLM08", "Vector and Embedding Weaknesses",
        "Attacks exploiting embedding search or vector stores to inject or retrieve unauthorised data.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08"),
    "LLM09": OWASPCategory("LLM09", "Misinformation",
        "LLM generates false, misleading, or harmful content presented as factual.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm09"),
    "LLM10": OWASPCategory("LLM10", "Unbounded Consumption",
        "Attacker causes excessive resource usage via crafted inputs (DoS, cost escalation).",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm10"),
}

# Strategy → primary OWASP category
STRATEGY_TO_OWASP: dict[str, str] = {
    "encoding_bypass":    "LLM01",
    "roleplay_reframe":   "LLM01",
    "crescendo":          "LLM01",
    "splitting":          "LLM01",
    "authority_inject":   "LLM01",
    "many_shot_context":  "LLM01",
    "hypothetical_chain": "LLM01",
    "socratic_method":    "LLM01",
    "token_obfuscation":  "LLM01",
    "paraphrase":         "LLM01",
    "language_switch":    "LLM01",
    "virtualization":     "LLM01",
}

# Sensitivity type → primary OWASP category
SENSITIVITY_TO_OWASP: dict[str, str] = {
    "secret_word":   "LLM02",
    "system_prompt": "LLM07",
    "pii":           "LLM02",
    "financial":     "LLM02",
    "credentials":   "LLM02",
    "api_key":       "LLM02",
    "general":       "LLM01",
    "all":           "LLM01",
}

def get_owasp_for_strategy(strategy: str) -> OWASPCategory:
    code = STRATEGY_TO_OWASP.get(strategy, "LLM01")
    return OWASP_LLM_TOP10[code]

def get_owasp_for_sensitivity(sensitivity_type: str) -> OWASPCategory:
    code = SENSITIVITY_TO_OWASP.get(sensitivity_type, "LLM01")
    return OWASP_LLM_TOP10[code]

def get_owasp_label(strategy: str, sensitivity_type: str = "") -> str:
    """Return 'LLM01 — Prompt Injection' style label for display."""
    # Sensitivity type takes precedence for information disclosure goals
    if sensitivity_type and sensitivity_type in SENSITIVITY_TO_OWASP:
        cat = get_owasp_for_sensitivity(sensitivity_type)
    else:
        cat = get_owasp_for_strategy(strategy)
    return f"{cat.code} — {cat.name}"

def owasp_summary(findings: list[dict]) -> dict[str, int]:
    """Count findings by OWASP category. findings is list of dicts with 'owasp_category' key.

    The stored label may be a full label like ``"LLM01 — Prompt Injection"``
    or a bare code like ``"LLM01"``.  Both forms are handled by extracting
    just the code prefix before the first space or em-dash separator.
    """
    counts: dict[str, int] = {code: 0 for code in OWASP_LLM_TOP10}
    for f in findings:
        # Extract "LLM01" from "LLM01 — Prompt Injection"
        code = (f.get("owasp_category", "") or "").split("—")[0].split(" ")[0].strip()
        if code in counts:
            counts[code] += 1
    return {k: v for k, v in counts.items() if v > 0}
