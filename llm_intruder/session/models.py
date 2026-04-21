"""Pydantic v2 models for session recording templates."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ── Action primitives ─────────────────────────────────────────────────────────

class NavigateAction(BaseModel):
    type: Literal["navigate"]
    url: str
    wait_for: str = "networkidle"


class FillAction(BaseModel):
    type: Literal["fill"]
    selector: str
    value: str  # may contain ${VARIABLE} placeholders


class ClickAction(BaseModel):
    type: Literal["click"]
    selector: str
    wait_for: str | None = None  # navigation | networkidle | None


class WaitForSelectorAction(BaseModel):
    type: Literal["wait_for_selector"]
    selector: str
    timeout: int = 15000


class PauseAction(BaseModel):
    """Pause campaign execution and wait for the operator (e.g. MFA entry)."""
    type: Literal["pause"]
    message: str
    resume_on_selector: str
    timeout: int = 120_000


class ConditionalAction(BaseModel):
    """Execute *then* actions only when *if_selector* is present on the page."""
    type: Literal["conditional"]
    if_selector: str
    then: list[SessionAction] = Field(default_factory=list)


# Forward-ref resolved after all action types are defined
SessionAction = (
    NavigateAction
    | FillAction
    | ClickAction
    | WaitForSelectorAction
    | PauseAction
    | ConditionalAction
)

ConditionalAction.model_rebuild()


# ── Artifact capture ──────────────────────────────────────────────────────────

class CookieArtifact(BaseModel):
    name: str
    domain: str


class LocalStorageKey(BaseModel):
    key: str


class SessionArtifacts(BaseModel):
    cookies: list[CookieArtifact] = Field(default_factory=list)
    local_storage: list[LocalStorageKey] = Field(default_factory=list)


# ── Logout detection ──────────────────────────────────────────────────────────

class LogoutTrigger(BaseModel):
    type: Literal[
        "http_status",
        "url_redirect",
        "dom_element",
        "cookie_missing",
        "response_body",
    ]
    codes: list[int] | None = None          # http_status
    patterns: list[str] | None = None       # url_redirect, response_body
    selectors: list[str] | None = None      # dom_element
    names: list[str] | None = None          # cookie_missing


class LogoutDetection(BaseModel):
    triggers: list[LogoutTrigger] = Field(default_factory=list)


# ── Success validation ────────────────────────────────────────────────────────

class SuccessCheck(BaseModel):
    type: Literal["url_not_contains", "cookie_exists", "dom_element_exists"]
    patterns: list[str] | None = None   # url_not_contains
    names: list[str] | None = None      # cookie_exists
    selector: str | None = None         # dom_element_exists


# ── Replay settings ───────────────────────────────────────────────────────────

class ReplaySettings(BaseModel):
    max_retries: int = 3
    retry_delay_seconds: int = 5
    slow_mo_ms: int = 100
    on_failure: Literal["pause_campaign", "abort", "notify"] = "pause_campaign"


# ── Top-level template ────────────────────────────────────────────────────────

class SessionTemplateData(BaseModel):
    name: str
    recorded_at: datetime
    target_url: str
    actions: list[SessionAction] = Field(default_factory=list)
    session_artifacts: SessionArtifacts = Field(default_factory=SessionArtifacts)
    logout_detection: LogoutDetection = Field(default_factory=LogoutDetection)
    success_validation: list[SuccessCheck] = Field(default_factory=list)
    replay_settings: ReplaySettings = Field(default_factory=ReplaySettings)


class SessionTemplate(BaseModel):
    """Root wrapper — matches the YAML top-level key ``session_template``."""
    session_template: SessionTemplateData
