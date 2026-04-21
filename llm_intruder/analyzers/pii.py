"""PII detection via compiled regex patterns — Phase 11."""
from __future__ import annotations

import hashlib
import re

from llm_intruder.analyzers.models import PiiEntityType, PiiMatch, PiiScanResult, RiskLevel

# ── Pattern registry ───────────────────────────────────────────────────────────
# Ordered highest-specificity first so overlapping spans are claimed by the
# more-specific type (e.g. AWS key before generic credential).

_PATTERNS: list[tuple[PiiEntityType, re.Pattern[str]]] = [
    # ── Critical secrets (highest specificity first) ──────────────────────
    ("PRIVATE_KEY",  re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )),
    ("AWS_KEY",      re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GCP_KEY",      re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("AZURE_KEY",    re.compile(r"\b[0-9a-f]{32}\b(?=.*(?:azure|microsoft))", re.I)),
    ("GITHUB_TOKEN", re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"
    )),
    ("SLACK_TOKEN",  re.compile(r"\bxox[bpars]-[A-Za-z0-9\-]{10,}\b")),
    ("STRIPE_KEY",   re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("TWILIO_KEY",   re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("JWT",          re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )),
    # ── Financial PII ─────────────────────────────────────────────────────
    ("CREDIT_CARD",  re.compile(
        r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"
    )),
    ("IBAN",         re.compile(
        r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:\d{4}[\s]?){2,7}\d{1,4}\b"
    )),
    ("US_BANK_ACCOUNT", re.compile(
        r"\b(?:account|acct)[\s#:]*\d{8,17}\b", re.I
    )),
    ("BITCOIN_ADDRESS", re.compile(
        r"\b(?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34}\b|"
        r"\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b"
    )),
    ("ETHEREUM_ADDRESS", re.compile(r"\b0x[0-9a-fA-F]{40}\b")),
    # ── Government IDs ────────────────────────────────────────────────────
    ("SSN",          re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("US_PASSPORT",  re.compile(r"\b[A-Z]\d{8}\b")),
    ("DRIVERS_LICENSE", re.compile(
        r"\b(?:DL|D\.L\.|license|licence)[\s#:]*[A-Z0-9]{5,15}\b", re.I
    )),
    ("UK_NHS_NUMBER", re.compile(
        r"\b(?:NHS|nhs)[\s#:]*\d{3}[\s-]\d{3}[\s-]\d{4}\b", re.I
    )),
    # ── Personal info ─────────────────────────────────────────────────────
    ("DATE_OF_BIRTH", re.compile(
        r"\b(?:DOB|date of birth|born|birthday)[\s:]*"
        r"(?:\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})",
        re.I
    )),
    ("EMAIL",        re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+")),
    ("PHONE",        re.compile(
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}"
    )),
    # ── Generic patterns (lowest specificity) ─────────────────────────────
    ("PASSWORD_ASSIGNMENT", re.compile(
        r"(?:password|passwd|pwd)[\s]*[:=][\s]*\S+", re.I
    )),
    ("GENERIC_API_KEY", re.compile(
        r"\b(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?key)[\s]*[:=][\s]*[A-Za-z0-9_\-]{16,}\b",
        re.I
    )),
    ("IP_ADDRESS",   re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )),
]

# Sensitivity tiers drive risk_level computation
_HIGH: frozenset[PiiEntityType] = frozenset({
    "SSN", "CREDIT_CARD", "AWS_KEY", "JWT", "PRIVATE_KEY",
    "GCP_KEY", "GITHUB_TOKEN", "SLACK_TOKEN", "STRIPE_KEY",
    "SENDGRID_KEY", "TWILIO_KEY", "IBAN", "US_PASSPORT",
    "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "PASSWORD_ASSIGNMENT",
    "GENERIC_API_KEY",
})
_MEDIUM: frozenset[PiiEntityType] = frozenset({
    "EMAIL", "PHONE", "AZURE_KEY", "US_BANK_ACCOUNT",
    "DRIVERS_LICENSE", "UK_NHS_NUMBER", "DATE_OF_BIRTH",
})
# LOW: IP_ADDRESS


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mask(value: str) -> str:
    """Return first 4 chars + *** — raw value is never stored."""
    return value[:4] + "***" if len(value) > 4 else "***"


def _compute_risk(matches: list[PiiMatch]) -> RiskLevel:
    if not matches:
        return "none"
    types: set[str] = {m.entity_type for m in matches}
    high_count = sum(1 for m in matches if m.entity_type in _HIGH)
    if high_count >= 2:
        return "critical"
    if types & _HIGH:
        return "high"
    if types & _MEDIUM:
        return "medium"
    return "low"


def scan_pii(response_text: str) -> PiiScanResult:
    """Scan *response_text* for PII patterns.

    Returns a :class:`PiiScanResult`.  The raw text is **never stored** —
    only its SHA-256 hash and masked snippets of matches are kept.
    """
    matches: list[PiiMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    for entity_type, pattern in _PATTERNS:
        for m in pattern.finditer(response_text):
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            matches.append(
                PiiMatch(
                    entity_type=entity_type,
                    masked_value=_mask(m.group()),
                    start=m.start(),
                    end=m.end(),
                )
            )

    matches.sort(key=lambda x: x.start)

    entity_counts: dict[str, int] = {}
    for m in matches:
        entity_counts[m.entity_type] = entity_counts.get(m.entity_type, 0) + 1

    return PiiScanResult(
        response_hash=_sha256(response_text),
        matches=matches,
        risk_level=_compute_risk(matches),
        entity_counts=entity_counts,
    )
