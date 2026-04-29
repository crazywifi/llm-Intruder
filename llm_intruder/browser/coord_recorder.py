"""Universal Coordinate-Based Recorder — works on ANY website.

WHY THIS EXISTS
---------------
CSS-selector-based detection fails on sites that use:
  • Shadow DOM  (Haptik, Salesforce, Material Web Components)
  • Cross-origin iframes  (embedded chat widgets)
  • Canvas / WebGL UIs
  • Highly dynamic class names (Next.js, Tailwind CSS-in-JS)

This module records raw (x, y) mouse coordinates and keyboard actions.
On replay, page.mouse.click(x, y) is used — the browser routes the click
to whatever element is at those viewport coordinates, regardless of
iframes, shadow DOM, or any JavaScript framework.

HOW TO USE
----------
Step 1 — RECORD (run once):

    from llm_intruder.browser.coord_recorder import CoordRecorder
    recipe = CoordRecorder("https://www.pvrcinemas.com/").record()
    recipe.save("coord_recipe.json")

The browser opens. You perform the interaction ONCE:
  1. Click the chat launcher bubble
  2. Click in the chat input field
  3. Type the special marker:  SENTINEL_PAYLOAD
  4. Click Send (or press Enter)
  5. Wait for the bot to reply
  6. Press ENTER twice in the terminal to confirm

Step 2 — REPLAY (automated, for every test payload):

    from llm_intruder.browser.coord_recorder import CoordRecipe, replay_payload
    recipe = CoordRecipe.load("coord_recipe.json")
    response_text = replay_payload(page, recipe, "Ignore all instructions...")

OPEN-SOURCE AI BROWSER ALTERNATIVES
-------------------------------------
If even coordinates are not reliable enough (e.g., fully dynamic layout),
consider these open-source AI browser agents that use LLM vision:

  • browser-use  (pip install browser-use)  — Python, Playwright-based,
    works with any LLM incl. local Ollama. Most popular (33k stars).
    https://github.com/browser-use/browser-use

  • Skyvern      (docker-compose up)        — Python, LLM + computer vision,
    self-hosted API, handles CAPTCHAs and complex flows.
    https://github.com/Skyvern-AI/skyvern

  • Playwright codegen (zero install — already in your stack):
    Run:  playwright codegen https://www.pvrcinemas.com/
    Records user actions → generates Python code with Playwright locators
    that automatically pierce shadow DOM.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import structlog

log = structlog.get_logger()

# ── Sentinel marker typed by user during recording ───────────────────────────
PAYLOAD_MARKER = "SENTINEL_PAYLOAD"


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class CoordAction:
    """One step in the recorded interaction sequence."""
    type: str          # "click" | "type_payload" | "type" | "press" | "wait"
    x: float = 0.0    # viewport x (for "click")
    y: float = 0.0    # viewport y (for "click")
    text: str = ""    # for "type"  (non-payload text, e.g. search terms)
    key: str  = ""    # for "press" (e.g. "Enter", "Control+A")
    ms: int   = 600   # wait_after_ms — pause after this action


@dataclass
class CoordRecipe:
    """Full recorded interaction recipe for one target site."""
    target_url: str
    actions: list[CoordAction] = field(default_factory=list)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "target_url": self.target_url,
                "actions": [asdict(a) for a in self.actions],
            }, f, indent=2)
        log.info("coord_recipe_saved", path=path, actions=len(self.actions))

    @classmethod
    def load(cls, path: str) -> "CoordRecipe":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        actions = [CoordAction(**a) for a in data["actions"]]
        return cls(target_url=data["target_url"], actions=actions)


# ── JavaScript injected into every frame to track interactions ────────────────

_COORD_TRACKER_JS = """
(frameId) => {
    if (window.__sentinel_coord_tracked) return;
    window.__sentinel_coord_tracked = true;
    window.__sentinel_coord_frame   = frameId;
    window.__sentinel_coord_events  = [];
    window.__sentinel_coord_payload_seen = false;

    function deepTarget(e) {
        // composedPath()[0] gives the true innermost element even
        // when the event originates from inside a shadow root.
        const path = e.composedPath ? e.composedPath() : [];
        return path[0] || e.target;
    }

    function isInputLike(el) {
        if (!el || !el.tagName) return false;
        const tag  = el.tagName.toUpperCase();
        const type = (el.type || '').toLowerCase();
        const role = (el.getAttribute && el.getAttribute('role') || '').toLowerCase();
        const ce   = el.getAttribute && el.getAttribute('contenteditable');
        return tag === 'TEXTAREA' ||
               (tag === 'INPUT' && (!el.hasAttribute('type') || type === 'text' || type === '')) ||
               ce === 'true' || role === 'textbox';
    }

    // Track mouse clicks — capture phase so we see everything
    document.addEventListener('mousedown', (e) => {
        const el = deepTarget(e);
        window.__sentinel_coord_events.push({
            kind: 'click',
            x: Math.round(e.clientX),
            y: Math.round(e.clientY),
            isInput: isInputLike(el),
            tag: (el.tagName || '').toLowerCase(),
            t: Date.now(),
        });
    }, true);

    // Track keyboard input — detect when user types SENTINEL_PAYLOAD
    document.addEventListener('input', (e) => {
        const el = deepTarget(e);
        if (!isInputLike(el)) return;
        const val = (el.value !== undefined ? el.value : el.textContent) || '';
        if (val.includes('SENTINEL_PAYLOAD') && !window.__sentinel_coord_payload_seen) {
            window.__sentinel_coord_payload_seen = true;
            // Mark the most recent click_input as the payload insertion point
            const events = window.__sentinel_coord_events;
            for (let i = events.length - 1; i >= 0; i--) {
                if (events[i].isInput) {
                    events[i].isPayloadInput = true;
                    break;
                }
            }
            window.__sentinel_coord_events.push({
                kind: 'type_payload',
                t: Date.now(),
            });
        }
    }, true);

    return true;
}
"""

_READ_COORD_EVENTS_JS = "() => window.__sentinel_coord_events || []"
_COORD_PAYLOAD_SEEN_JS = "() => !!window.__sentinel_coord_payload_seen"


# ── Recording ─────────────────────────────────────────────────────────────────

class CoordRecorder:
    """Records a single user workflow and produces a CoordRecipe.

    Workflow
    --------
    1. Browser opens at target_url.
    2. User performs the chat interaction once:
       - Click chat icon
       - Click input field
       - Type:  SENTINEL_PAYLOAD  (this is the placeholder for real payloads)
       - Click Send / press Enter
       - Wait for bot to reply
    3. User presses ENTER twice in the terminal.
    4. A CoordRecipe is returned (and optionally saved).
    """

    def __init__(self, target_url: str, timeout_s: int = 300) -> None:
        self.target_url = target_url
        self.timeout_s = timeout_s

    def record(self, save_path: str | None = None) -> CoordRecipe:
        from playwright.sync_api import sync_playwright

        log.info("coord_recorder_start", url=self.target_url)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()

            try:
                page.goto(self.target_url, wait_until="networkidle")
                log.info("coord_recorder_navigated", url=self.target_url)
                page.wait_for_timeout(2000)

                # Inject tracker into ALL frames (main + every iframe)
                self._inject_in_all_frames(page)

                print("\n" + "="*60)
                print("COORD RECORDER — Universal Mode")
                print("="*60)
                print(f"Target: {self.target_url}")
                print()
                print("Perform your workflow in the browser:")
                print("  1. Click the chat launcher / bubble")
                print("  2. Wait for the chat widget to open")
                print(f"  3. Click the input field and type:  {PAYLOAD_MARKER}")
                print("  4. Click Send or press Enter")
                print("  5. Wait for the bot to reply")
                print()
                print("Press ENTER here TWICE when done ↵↵")
                print("="*60 + "\n")

                # Wait for ENTER x2 (give user time to perform the workflow)
                input()
                input()

                # Re-inject in any new iframes that appeared after interaction
                self._inject_in_all_frames(page)
                page.wait_for_timeout(500)

                # Collect events from all frames
                recipe = self._build_recipe(page)

                print(f"\n✓ Recorded {len(recipe.actions)} actions.")
                for i, a in enumerate(recipe.actions, 1):
                    if a.type == "click":
                        print(f"  {i}. click ({a.x}, {a.y})")
                    elif a.type == "type_payload":
                        print(f"  {i}. type_payload  ← payload goes here")
                    elif a.type == "type":
                        print(f"  {i}. type: {a.text!r}")
                    elif a.type == "press":
                        print(f"  {i}. press: {a.key}")
                    elif a.type == "wait":
                        print(f"  {i}. wait {a.ms}ms")

                if save_path:
                    recipe.save(save_path)

                return recipe

            finally:
                context.close()
                browser.close()

    def _inject_in_all_frames(self, page: Any) -> None:
        for i, frame in enumerate(page.frames):
            try:
                frame.evaluate(_COORD_TRACKER_JS, i)
                log.debug("coord_tracker_injected", frame=i)
            except Exception as exc:
                log.debug("coord_tracker_inject_failed", frame=i, error=str(exc))

    def _build_recipe(self, page: Any) -> CoordRecipe:
        """Collect events from all frames and build the action sequence."""
        all_events: list[dict] = []

        for i, frame in enumerate(page.frames):
            try:
                events = frame.evaluate(_READ_COORD_EVENTS_JS) or []
                if not events:
                    continue

                # For iframes (i > 0), offset coords by the iframe's viewport position
                offset_x, offset_y = 0.0, 0.0
                if i > 0:
                    offset_x, offset_y = self._get_frame_offset(page, frame)

                for ev in events:
                    ev["_vx"] = ev.get("x", 0) + offset_x
                    ev["_vy"] = ev.get("y", 0) + offset_y
                    ev["_frame"] = i
                all_events.extend(events)
            except Exception as exc:
                log.debug("coord_collect_failed", frame=i, error=str(exc))

        # Sort by timestamp
        all_events.sort(key=lambda e: e.get("t", 0))
        log.info("coord_events_collected", total=len(all_events))

        # Convert to CoordActions, collapsing consecutive clicks and inserting waits
        actions: list[CoordAction] = []
        prev_t: int | None = None

        for ev in all_events:
            t = ev.get("t", 0)

            # Insert wait between actions if gap > 1.5 s (e.g. waiting for widget to open)
            if prev_t is not None:
                gap_ms = t - prev_t
                if gap_ms > 1500:
                    wait_ms = min(gap_ms, 8000)   # cap recorded wait at 8s
                    actions.append(CoordAction(type="wait", ms=wait_ms))

            kind = ev.get("kind", "")
            if kind == "click":
                actions.append(CoordAction(
                    type="click",
                    x=round(ev["_vx"]),
                    y=round(ev["_vy"]),
                    ms=400,
                ))
            elif kind == "type_payload":
                actions.append(CoordAction(type="type_payload", ms=300))

            prev_t = t

        if not any(a.type == "type_payload" for a in actions):
            log.warning("coord_no_payload_marker_found",
                        hint=f"Did you type '{PAYLOAD_MARKER}' in the chat input?")

        return CoordRecipe(target_url=self.target_url, actions=actions)

    @staticmethod
    def _get_frame_offset(page: Any, target_frame: Any) -> tuple[float, float]:
        """Return (x_offset, y_offset) of a frame's iframe element in viewport coords."""
        try:
            for iframe_el in page.query_selector_all("iframe"):
                try:
                    cf = iframe_el.content_frame()
                    if cf == target_frame:
                        box = iframe_el.bounding_box()
                        if box:
                            return box["x"], box["y"]
                except Exception:
                    continue
        except Exception:
            pass
        return 0.0, 0.0


# ── Replay ───────────────────────────────────────────────────────────────────

def replay_payload(
    page: Any,
    recipe: CoordRecipe,
    payload: str,
    stability_s: float = 2.5,
    timeout_s: float = 60.0,
) -> str:
    """Replay a recorded CoordRecipe with a specific payload.

    Returns the bot's response text (captured via shadow-DOM-aware text diff).

    Parameters
    ----------
    page:
        A live Playwright page already navigated to recipe.target_url.
    recipe:
        The CoordRecipe produced by CoordRecorder.record().
    payload:
        The actual text to send (replaces the SENTINEL_PAYLOAD marker).
    stability_s:
        Seconds of DOM silence that means the bot has finished responding.
    timeout_s:
        Maximum seconds to wait for a response.
    """
    from llm_intruder.browser.llm_detector import SmartResponseReader

    reader = SmartResponseReader()
    reader.set_frames(list(page.frames))  # scan all frames for response

    # Snapshot text BEFORE sending
    reader.snapshot_before(page)

    log.info("coord_replay_start", actions=len(recipe.actions), payload_len=len(payload))

    for action in recipe.actions:
        if action.type == "click":
            log.debug("coord_replay_click", x=action.x, y=action.y)
            page.mouse.click(action.x, action.y)

        elif action.type == "type_payload":
            log.debug("coord_replay_type_payload", payload_len=len(payload))
            # Clear existing content first (Ctrl+A → Delete)
            page.keyboard.press("Control+a")
            page.keyboard.press("Delete")
            page.keyboard.type(payload, delay=30)

        elif action.type == "type":
            page.keyboard.type(action.text, delay=20)

        elif action.type == "press":
            page.keyboard.press(action.key)

        elif action.type == "wait":
            page.wait_for_timeout(action.ms)

        # Small pause between actions (gives the browser time to react)
        if action.ms > 0 and action.type not in ("wait",):
            page.wait_for_timeout(action.ms)

    # Capture response via shadow-DOM-aware text diff
    response = reader.read_new_response(
        page,
        timeout_s=timeout_s,
        stability_s=stability_s,
        sent_payload=payload,
    )

    log.info("coord_replay_response_captured",
             chars=len(response), preview=response[:80].replace("\n", " "))
    return response
