"""Pydantic v2 models for the Phase 11 response security analyzer."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

# ── Type aliases ───────────────────────────────────────────────────────────────

PiiEntityType = Literal[
    "EMAIL", "PHONE", "SSN", "CREDIT_CARD",
    "IP_ADDRESS", "AWS_KEY", "JWT", "GENERIC_SECRET",
    "GCP_KEY", "AZURE_KEY", "GITHUB_TOKEN", "SLACK_TOKEN",
    "PRIVATE_KEY", "PASSWORD_ASSIGNMENT", "IBAN",
    "US_PASSPORT", "DATE_OF_BIRTH", "DRIVERS_LICENSE",
    "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "STRIPE_KEY",
    "SENDGRID_KEY", "TWILIO_KEY", "US_BANK_ACCOUNT",
    "UK_NHS_NUMBER", "GENERIC_API_KEY",
]

RiskLevel = Literal["none", "low", "medium", "high", "critical"]

InjectionCategory = Literal["javascript", "sql", "html", "command"]

ComplianceFramework = Literal["OWASP_LLM", "MITRE_ATLAS", "NIST_AI_RMF", "EU_AI_ACT"]


# ── PII models ─────────────────────────────────────────────────────────────────

class PiiMatch(BaseModel):
    """A single redacted PII match found in a response."""

    entity_type: PiiEntityType
    masked_value: str          # first 4 chars + *** — raw value never stored
    start: int                 # character offset in response_text
    end: int
    confidence: float = 1.0


class PiiScanResult(BaseModel):
    """Aggregate result of scanning one response for PII."""

    response_hash: str                                   # SHA-256 of raw text
    matches: list[PiiMatch] = Field(default_factory=list)
    risk_level: RiskLevel = "none"
    entity_counts: dict[str, int] = Field(default_factory=dict)  # type -> count


# ── Injection / output-handling models ────────────────────────────────────────

class InjectionRisk(BaseModel):
    """A detected code-injection or unsafe-output pattern."""

    category: InjectionCategory
    pattern: str               # human-readable description of the pattern
    context_snippet: str       # up to 120 chars of surrounding context (masked)
    risk_level: RiskLevel = "high"


# ── System-prompt leakage model ───────────────────────────────────────────────

class SystemPromptLeakage(BaseModel):
    """Result of checking whether the response leaks system-prompt fragments."""

    fragments: list[str] = Field(default_factory=list)   # up to 10 snippets
    detected: bool = False
    confidence: float = 0.0


# ── Finding / aggregate models ────────────────────────────────────────────────

class AnalyzerFinding(BaseModel):
    """A single consolidated finding from any analyzer check."""

    category: str               # e.g. "pii_leakage", "injection_sql"
    severity: RiskLevel
    description: str
    evidence: str = ""          # brief supporting snippet (already masked)


class ResponseAnalysis(BaseModel):
    """Full security analysis of one probe response."""

    trial_id: str
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    response_length: int = 0
    pii_scan: PiiScanResult
    injection_risks: list[InjectionRisk] = Field(default_factory=list)
    system_prompt_leakage: SystemPromptLeakage = Field(
        default_factory=SystemPromptLeakage
    )
    content_flags: list[AnalyzerFinding] = Field(default_factory=list)
    overall_risk: RiskLevel = "none"
    findings_count: int = 0

    @property
    def has_findings(self) -> bool:
        return self.findings_count > 0


# ── Compliance / classifier models ────────────────────────────────────────────

class ComplianceViolation(BaseModel):
    """One mapped compliance control violation."""

    framework: ComplianceFramework
    control_id: str         # e.g. "LLM06", "AML.T0048", "GOVERN-1.1", "Art.10"
    control_name: str
    description: str
    severity: RiskLevel = "medium"


class ClassifierResult(BaseModel):
    """Compliance classification result for one probe response."""

    trial_id: str
    classified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    violations: list[ComplianceViolation] = Field(default_factory=list)
    frameworks_checked: list[str] = Field(default_factory=list)
    violation_count: int = 0
    highest_severity: RiskLevel = "none"

    @property
    def has_violations(self) -> bool:
        return self.violation_count > 0
