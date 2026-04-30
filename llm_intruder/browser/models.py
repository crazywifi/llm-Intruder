"""Pydantic v2 models for site_adapter.yaml — Browser Driver configuration."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CoordAction(BaseModel):
    """One step in a coordinate-based replay sequence (mode='coord').

    type values
    -----------
    click        — page.mouse.click(x, y)
    type_payload — page.keyboard.type(<actual_payload>)   ← payload placeholder
    type         — page.keyboard.type(text)               ← literal non-payload text
    press        — page.keyboard.press(key)               ← e.g. "Enter"
    wait         — page.wait_for_timeout(ms)
    """
    type: Literal["click", "type_payload", "type", "press", "wait"]
    x:    float = 0.0   # viewport x  (click)
    y:    float = 0.0   # viewport y  (click)
    text: str   = ""    # literal text to type  (type)
    key:  str   = ""    # key name  (press)
    ms:   int   = 600   # pause after action in ms


class InputConfig(BaseModel):
    """Describes how to find and interact with the chat input widget."""
    selector: str
    submit: str                                          # CSS selector for send button
    submit_method: Literal["click", "enter"] = "click"  # click button or press Enter
    clear_before_fill: bool = True


class StreamDetectionConfig(BaseModel):
    """How to tell when a streaming response has finished arriving."""
    method: Literal["mutation_observer", "polling"] = "mutation_observer"
    stability_ms: int = 400      # DOM-silence window that signals "done"
    polling_interval_ms: int = 100
    timeout_ms: int = 60_000


class WipeDetectionConfig(BaseModel):
    """Detect if the target UI clears the response text after display."""
    enabled: bool = True
    check_selector: str = ""     # re-check this selector after stability delay


class ResponseConfig(BaseModel):
    """Describes where the model's response text appears in the DOM."""
    selector: str
    stream_detection: StreamDetectionConfig = Field(default_factory=StreamDetectionConfig)
    wipe_detection: WipeDetectionConfig = Field(default_factory=WipeDetectionConfig)


class CsrfConfig(BaseModel):
    """Optional CSRF token harvesting before payload delivery."""
    enabled: bool = False
    token_selector: str = "meta[name='csrf-token']"
    token_attribute: str = "content"
    header_name: str = "X-CSRF-Token"


class WaitForReadyConfig(BaseModel):
    """Wait for this selector to appear before attempting payload delivery."""
    selector: str
    timeout: int = 30_000


class SiteAdapterConfig(BaseModel):
    """Root model for site_adapter.yaml."""
    mode: Literal["browser", "api", "hybrid", "coord"] = "browser"
    target_url: str
    input: InputConfig
    response: ResponseConfig
    csrf: CsrfConfig = Field(default_factory=CsrfConfig)
    wait_for_ready: WaitForReadyConfig | None = None
    # Populated when mode="coord": the recorded click/type sequence.
    # Generate with:  CoordRecorder(url).record(save_path="coord_recipe.json")
    coord_actions: list[CoordAction] = Field(default_factory=list)


class CapturedResponse(BaseModel):
    """The result of one probe: text, timing, stream flag, wipe flag."""
    text: str
    was_wiped: bool = False
    stream_detected: bool = False
    capture_duration_ms: float = 0.0
    payload_hash: str = ""
    response_hash: str = ""
    request_body: str = ""    # full HTTP request body sent to the target
    target_url: str = ""     # URL the request was sent to
