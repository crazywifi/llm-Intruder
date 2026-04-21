"""Pydantic request/response models for the dashboard API."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── enums ──────────────────────────────────────────────────────────────────────

class TargetType(str, Enum):
    web = "web"
    api = "api"


class RunMode(str, Enum):
    campaign = "campaign"
    hunt = "hunt"
    pool = "pool"
    probe = "probe"
    rag_test = "rag_test"


class HuntMode(str, Enum):
    adaptive = "ADAPTIVE"
    pair = "PAIR"
    multi_turn = "MULTI_TURN"
    full = "FULL"


class JudgeProvider(str, Enum):
    heuristic = "heuristic"
    ollama = "ollama"
    lmstudio = "lmstudio"
    claude = "claude"
    openai = "openai"
    gemini = "gemini"
    openrouter = "openrouter"
    grok = "grok"
    auto = "auto"


class RunStatus(str, Enum):
    pending = "pending"
    running = "running"
    judging = "judging"
    reporting = "reporting"
    completed = "completed"
    failed = "failed"
    stopped = "stopped"


# ── project ────────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: str = ""


class ProjectSummary(BaseModel):
    id: str
    name: str
    description: str
    created_at: str
    run_count: int
    last_run_at: str | None
    last_run_mode: str | None = None
    last_run_status: str | None = None
    workspace_path: str


# ── LLM config ────────────────────────────────────────────────────────────────

class LLMConfig(BaseModel):
    provider: JudgeProvider = JudgeProvider.heuristic
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None


# ── run request ───────────────────────────────────────────────────────────────

class EngagementProfile(BaseModel):
    engagement_id: str = ""
    description: str = ""
    authorisation_confirmed: bool = True
    max_trials: int = Field(default=500, ge=1, le=10000)
    run_all_payloads: bool = True    # when True: runs every payload exactly once (overrides max_trials)
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    stop_on_first_success: bool = False
    workers: int = Field(default=1, ge=1, le=32)
    dry_run: bool = False
    seed: int | None = None
    # LLM provider used for smart UI detection in web-application (browser) mode
    detection_llm: LLMConfig = Field(default_factory=LLMConfig)


class TargetProfile(BaseModel):
    application_name: str = ""
    application_type: str = "chatbot"
    domain: str = "general"
    sensitivity_type: str = "all"
    target_language: str = "english"
    goal_keywords: list[str] = []
    sensitive_patterns: list[str] = []
    success_description: str = ""
    previous_attempts: str = ""
    known_defenses: list[str] = []
    notes: str = ""


class DetectionMode(str, Enum):
    """Detection mode for web/browser targets."""
    auto = "auto"          # LLM/heuristic auto-detect selectors
    intruder = "intruder"  # Burp-style: user picks elements interactively


class TargetConfig(BaseModel):
    target_type: TargetType = TargetType.web
    target_url: str = ""
    scope: list[str] = []
    # web only
    requires_login: bool = False
    session_template_path: str | None = None
    headless: bool = True
    # Detection mode: 'auto' = LLM/heuristic, 'intruder' = Burp Suite-style
    # (works on shadow DOM, cross-origin iframes, any complex site)
    detection_mode: DetectionMode = DetectionMode.auto
    # api only
    auth_type: str = "none"
    auth_value: str = ""
    content_type: str = "application/json"
    burp_request_path: str | None = None
    burp_body_template: str | None = None              # parsed from Burp multipart/form body
    response_extraction_path: str = "$.choices[0].message.content"  # JSONPath to extract reply
    extra_headers: dict[str, str] = {}                # original Burp headers (User-Agent, Referer, etc.)
    extra_vars: dict[str, str] = {}


class PayloadConfig(BaseModel):
    # Tri-state semantics: None = ALL (wizard's "Select All"), [] = NONE
    # (user deselected everything), [x,y,...] = specific subset.
    catalogues: list[str] | None = None
    strategies: list[str] | None = None
    encoding_techniques: list[str] | None = None
    custom_payload_text: str = ""


class AdvancedConfig(BaseModel):
    hunt_mode: HuntMode = HuntMode.full
    multi_turn: bool = False
    auto_adv_temperature: bool = True
    tomb_raider: bool = True
    burn_detection: bool = True
    defense_fingerprint: bool = True
    report_formats: list[str] = ["markdown", "html"]
    auto_chain: bool = True
    concurrency: int = 1
    # judge
    attacker_llm: LLMConfig = Field(default_factory=LLMConfig)
    judge_llm: LLMConfig = Field(default_factory=LLMConfig)
    judge_workers: int = 1
    inline_judge: bool = True
    # pool-run specific
    pool_concurrency: int = 4
    max_retries: int = 3
    evidence_dir: str = "evidence"
    # rag-test specific
    adversarial_text: str = ""
    tenant_a: str = "TENANT_A"
    tenant_b: str = "TENANT_B"
    boundary_types: str = ""
    # judge
    skip_judge: bool = False
    # report specific
    sarif: bool = False


class RunRequest(BaseModel):
    project_id: str
    run_mode: RunMode = RunMode.campaign
    target: TargetConfig = Field(default_factory=TargetConfig)
    payloads: PayloadConfig = Field(default_factory=PayloadConfig)
    engagement: EngagementProfile = Field(default_factory=EngagementProfile)
    target_profile: TargetProfile = Field(default_factory=TargetProfile)
    advanced: AdvancedConfig = Field(default_factory=AdvancedConfig)


# ── run state ─────────────────────────────────────────────────────────────────

class TrialSummary(BaseModel):
    trial_num: int
    strategy: str
    encoding: str | None
    verdict: str
    confidence: float
    payload_preview: str
    response_preview: str
    duration_ms: float


class RunProgress(BaseModel):
    run_id: str
    status: RunStatus
    attack_pct: float = 0.0
    judge_pct: float = 0.0
    report_pct: float = 0.0
    attack_eta_s: int = 0
    judge_eta_s: int = 0
    total_trials: int = 0
    completed_trials: int = 0
    success_count: int = 0
    partial_count: int = 0
    refusal_count: int = 0
    top_strategy: str = ""
    defense_detected: str = ""
    current_temp: float = 0.9
    recent_trials: list[TrialSummary] = []
    error: str | None = None


# ── probe request ─────────────────────────────────────────────────────────────

class ProbeRequest(BaseModel):
    project_id: str
    target: TargetConfig
    engagement: EngagementProfile
    payload: str
    payload_file_path: str | None = None
    headless: bool = True


# ── playground ────────────────────────────────────────────────────────────────

class PlaygroundRequest(BaseModel):
    text: str
    techniques: list[str]
    llm_config: LLMConfig | None = None
    bijection_variant: str = "random_shuffle"
    vigenere_key: str = "sentinel"
    rail_fence_rails: int = 3
    anti_classifier_level: int = 2


class PlaygroundResponse(BaseModel):
    original: str
    result: str
    applied: list[str]
    char_count_before: int
    char_count_after: int


# ── local LLM probe ───────────────────────────────────────────────────────────

class LocalLLMStatus(BaseModel):
    ollama_available: bool
    ollama_models: list[str]
    lmstudio_available: bool
    lmstudio_models: list[str]


# ── WebSocket event ───────────────────────────────────────────────────────────

class WSEvent(BaseModel):
    event: str        # progress | trial | log | done | error
    data: Any
