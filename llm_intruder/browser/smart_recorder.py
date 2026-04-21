"""Smart Browser Interaction Recorder — Burp-style macro recording for LLM UIs.

Opens a headed browser, watches the user interact ONCE (type payload, click send),
auto-detects the input field selector, submit button selector, and response area,
then generates a SiteAdapterConfig ready for automated replay.

The browser stays open until the user confirms in the terminal that the recording
looks correct — it does NOT auto-close.

FIXES IN THIS VERSION
---------------------
1. Recorder JS is injected into ALL frames (main page + every iframe) so that
   chatbots embedded in iframes (Haptik/PVR, Intercom, Zendesk, Drift) are
   detected correctly.

2. Before injecting the recorder, we attempt to click any chat launcher
   button (floating chat bubble) using _try_open_chat_launcher() from
   llm_detector. This ensures the iframe/input is visible before we start.

3. SmartResponseReader.set_frames() is called with all frames so the
   verification test-probe captures responses from iframes too.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from llm_intruder.browser.models import (
    CsrfConfig,
    InputConfig,
    ResponseConfig,
    SiteAdapterConfig,
    StreamDetectionConfig,
    WaitForReadyConfig,
    WipeDetectionConfig,
)

log = structlog.get_logger()

_AUTO_RESPONSE_SELECTOR = "__AUTO__"
_DIFF_RESPONSE_SELECTOR = "__DIFF__"

# ---------------------------------------------------------------------------
# JavaScript injected into the page (and every iframe) to observe user interactions
# ---------------------------------------------------------------------------

_RECORDER_JS = """
() => {
  // Guard against double-injection
  if (window.__sentinel_recorder) return;

  const rec = {
    phase: "waiting",
    inputSelector: null,
    submitSelector: null,
    responseSelector: null,
    inputTag: null,
    preSubmitSnapshot: null,
    responseText: null,
    error: null,
    candidates: [],
  };
  window.__sentinel_recorder = rec;

  // uniqueSelector: prefer stable attribute selectors.
  // Playwright auto-pierces shadow DOM, so [placeholder="..."] works even
  // when the element lives inside a shadow root — no path needed.
  function uniqueSelector(el) {
    if (!el || !el.tagName) return null;
    if (el === document.body || el === document.documentElement) return null;
    if (el.id) return "#" + CSS.escape(el.id);
    for (const attr of ["data-testid", "name", "aria-label", "placeholder"]) {
      const v = el.getAttribute && el.getAttribute(attr);
      if (v) return el.tagName.toLowerCase() + "[" + attr + "=" + JSON.stringify(v) + "]";
    }
    if (el.classList && el.classList.length > 0) {
      const classSelector = el.tagName.toLowerCase() + "." + Array.from(el.classList).slice(0,3).join(".");
      try { if (document.querySelectorAll(classSelector).length === 1) return classSelector; } catch(e) {}
    }
    const parts = [];
    let cur = el;
    while (cur && cur.tagName) {
      let seg = cur.tagName.toLowerCase();
      if (cur.id) {
        seg = "#" + CSS.escape(cur.id);
        parts.unshift(seg);
        break;
      }
      const parent = cur.parentElement;
      if (!parent) break;  // shadow-root boundary
      const siblings = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
      if (siblings.length > 1) seg += ":nth-of-type(" + (siblings.indexOf(cur) + 1) + ")";
      parts.unshift(seg);
      cur = parent;
    }
    if (parts.length === 0) return null;
    return parts.join(" > ");
  }

  function isInsideInputArea(el) {
    let cur = el;
    while (cur && cur !== document.body) {
      if (cur.tagName === "FORM") return true;
      if (cur.tagName === "TEXTAREA" || cur.tagName === "INPUT") return true;
      if (cur === rec._inputElement) return true;
      cur = cur.parentElement;
    }
    return false;
  }

  // Phase 1: detect input
  // KEY FIX: Use composedPath()[0] instead of e.target.
  // e.target is RETARGETED at shadow-root boundaries — it becomes the
  // shadow host, not the actual <input> inside the shadow DOM.
  // composedPath()[0] always gives the true innermost target element.
  document.addEventListener("input", (e) => {
    if (rec.phase !== "waiting" && rec.phase !== "input_detected") return;
    const el = (e.composedPath && e.composedPath()[0]) || e.target;
    const tag = (el.tagName || "").toUpperCase();
    if (tag === "INPUT" || tag === "TEXTAREA" || el.isContentEditable ||
        (el.getAttribute && el.getAttribute("role") === "textbox")) {
      rec.inputSelector = uniqueSelector(el);
      rec.inputTag = tag;
      rec._inputElement = el;
      rec.phase = "input_detected";
    }
  }, true);

  document.addEventListener("focus", (e) => {
    if (rec.phase !== "waiting") return;
    const el = (e.composedPath && e.composedPath()[0]) || e.target;
    const tag = (el.tagName || "").toUpperCase();
    if (tag === "TEXTAREA" || (tag === "INPUT" && (!el.type || el.type === "text")) ||
        el.isContentEditable || (el.getAttribute && el.getAttribute("role") === "textbox")) {
      rec.inputSelector = uniqueSelector(el);
      rec.inputTag = tag;
      rec._inputElement = el;
      rec.phase = "input_detected";
    }
  }, true);

  // Phase 2: detect submit
  document.addEventListener("click", (e) => {
    if (rec.phase !== "input_detected") return;
    let btn = (e.composedPath && e.composedPath()[0]) || e.target;
    for (let i = 0; i < 3 && btn && btn.tagName; i++) {
      const tag = btn.tagName;
      if (tag === "BUTTON" || tag === "A" ||
          (tag === "INPUT" && (btn.type === "submit" || btn.type === "button")) ||
          btn.getAttribute("role") === "button") {
        break;
      }
      btn = btn.parentElement;
    }
    if (!btn || btn === document.body) btn = e.target;
    if (btn === rec._inputElement) return;

    rec.submitSelector = uniqueSelector(btn);
    rec._submitElement = btn;
    rec.phase = "submit_detected";
    rec.preSubmitSnapshot = document.body.innerText;
    startResponseDetection();
  }, true);

  document.addEventListener("keydown", (e) => {
    if (rec.phase !== "input_detected") return;
    if (e.key === "Enter" && !e.shiftKey) {
      rec.submitSelector = "__ENTER_KEY__";
      rec.phase = "submit_detected";
      rec.preSubmitSnapshot = document.body.innerText;
      startResponseDetection();
    }
  }, true);

  function startResponseDetection() {
    rec.phase = "capturing";
    const candidates = new Map();

    const observer = new MutationObserver((mutations) => {
      for (const mut of mutations) {
        let target = mut.target;
        if (target.nodeType === Node.TEXT_NODE) target = target.parentElement;
        if (!target || target === document.body) continue;

        let container = target;
        for (let i = 0; i < 6 && container && container !== document.body; i++) {
          const tag = container.tagName;
          if (tag === "DIV" || tag === "SECTION" || tag === "ARTICLE" ||
              tag === "MAIN" || tag === "P" || tag === "PRE") {
            const text = (container.innerText || "").trim();
            if (text.length > 5 && text.length < 50000) break;
          }
          container = container.parentElement;
        }
        if (!container || container === document.body) continue;
        if (container === rec._inputElement) continue;
        if (container === rec._submitElement) continue;

        const sel = uniqueSelector(container);
        if (!sel) continue;
        if (sel === rec.inputSelector || sel === rec.submitSelector) continue;

        if (!candidates.has(sel)) {
          candidates.set(sel, {
            el: container,
            initialText: (container.innerText || "").trim(),
            changeCount: 0,
            firstSeen: Date.now(),
          });
        }
        candidates.get(sel).changeCount++;
      }
    });

    observer.observe(document.body, {
      childList: true,
      characterData: true,
      subtree: true,
    });

    let checkCount = 0;
    let lastBestText = "";
    let stableTextCount = 0;

    const checker = setInterval(() => {
      checkCount++;
      let best = null;
      let bestScore = 0;
      const debugList = [];

      for (const [sel, c] of candidates) {
        const currentText = (c.el.innerText || "").trim();
        if (currentText.length < 5) continue;
        if (isInsideInputArea(c.el)) continue;
        const newTextLen = Math.max(0, currentText.length - c.initialText.length);
        const score = c.changeCount * Math.max(newTextLen, 1);
        debugList.push({ sel, score, textLen: currentText.length, changes: c.changeCount });
        if (score > bestScore) {
          bestScore = score;
          best = { sel, text: currentText, changes: c.changeCount, el: c.el };
        }
      }

      if (best && best.text === lastBestText) {
        stableTextCount++;
      } else {
        stableTextCount = 0;
      }
      lastBestText = best ? best.text : "";

      const textStable = best && best.text.length > 10 && stableTextCount >= 6;
      const timedOut = checkCount >= 60;

      if (textStable || timedOut) {
        observer.disconnect();
        clearInterval(checker);
        rec.candidates = debugList.sort((a, b) => b.score - a.score).slice(0, 5);
        if (best) {
          rec.responseSelector = best.sel;
          rec.responseText = best.text;
          rec.phase = "recorded";
        } else {
          rec.error = "No response detected within 30 seconds.";
          rec.phase = "recorded";
        }
      }
    }, 500);
  }
}
"""

_READ_STATE_JS = """() => {
  const r = window.__sentinel_recorder || {};
  return JSON.stringify({
    phase:            r.phase            || "waiting",
    inputSelector:    r.inputSelector    || null,
    submitSelector:   r.submitSelector   || null,
    responseSelector: r.responseSelector || null,
    inputTag:         r.inputTag         || null,
    responseText:     r.responseText     || null,
    error:            r.error            || null,
    candidates: (r.candidates || []).map(function(c) {
      return { sel: c.sel, score: c.score, textLen: c.textLen, changes: c.changes };
    }),
  });
}"""


def _dismiss_consent(page, retries: int = 3) -> None:
    """Dismiss cookie/consent banners."""
    import time as _time

    CONSENT_SELECTORS = [
        "button.call-to-action",
        "#onetrust-accept-btn-handler",
        ".onetrust-accept-btn-handler",
        "button[id*='accept']",
        "button[class*='accept']",
        "button[aria-label*='accept' i]",
        "button[aria-label*='agree' i]",
        "button[data-testid='cookie-accept']",
        ".cc-accept",
        ".cc-btn.cc-allow",
        "[class*='privacy'] button",
        "[class*='cookie'] button",
        "[id*='cookie'] button",
        "[class*='consent'] button",
    ]

    for attempt in range(retries):
        for sel in CONSENT_SELECTORS:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.click()
                    page.wait_for_timeout(1000)
                    return
            except Exception:
                continue

        found = page.evaluate("""() => {
            const keywords = ['accept', 'agree', 'allow', 'i understand', 'got it'];
            const candidates = document.querySelectorAll(
                'button, [role="button"], a.btn, a.button, input[type="button"], input[type="submit"]'
            );
            for (const el of candidates) {
                const text = (el.innerText || el.value || el.textContent || '').trim().toLowerCase();
                if (keywords.some(k => text === k || text === k + ' all')) {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) {
                        el.click();
                        return true;
                    }
                }
            }
            return false;
        }""")
        if found:
            page.wait_for_timeout(1000)
            return

        if attempt < retries - 1:
            _time.sleep(1.5)


def _inject_recorder_in_all_frames(page: Any) -> None:
    """Inject _RECORDER_JS into the main page and every accessible iframe.

    This is the key fix for embedded chatbots: by injecting into all frames,
    we capture user interactions that happen inside iframes (Haptik, Intercom, etc.).
    """
    # Main page
    try:
        page.evaluate(_RECORDER_JS)
        log.debug("recorder_js_injected_main_page")
    except Exception as exc:
        log.warning("recorder_js_inject_failed_main", error=str(exc))

    # Each sub-frame
    try:
        frames = page.frames
    except Exception:
        frames = []

    for i, frame in enumerate(frames):
        if i == 0:
            continue  # frame 0 is always the main frame — already done
        try:
            frame.evaluate(_RECORDER_JS)
            frame_url = ""
            try:
                frame_url = frame.url or ""
            except Exception:
                pass
            log.debug("recorder_js_injected_iframe", frame=i, url=frame_url[:60])
        except Exception as exc:
            log.debug("recorder_js_inject_iframe_failed", frame=i, error=str(exc))


def _read_recorder_state_from_all_frames(page: Any) -> dict:
    """Read recorder state from main page AND all iframes.

    Returns the first frame that has progressed past "waiting".
    """
    import json

    # Try main page first
    try:
        raw = page.evaluate(_READ_STATE_JS)
        state = json.loads(raw) if raw else {}
        if state.get("phase", "waiting") not in ("waiting", ""):
            return state
    except Exception:
        pass

    # Try sub-frames
    try:
        frames = page.frames
    except Exception:
        frames = []

    for i, frame in enumerate(frames):
        if i == 0:
            continue
        try:
            raw = frame.evaluate(_READ_STATE_JS)
            state = json.loads(raw) if raw else {}
            if state.get("phase", "waiting") not in ("waiting", ""):
                log.info("recorder_state_from_iframe", frame=i,
                         phase=state.get("phase"))
                return state
        except Exception:
            continue

    # Return whatever main page has (even if "waiting")
    try:
        raw = page.evaluate(_READ_STATE_JS)
        return json.loads(raw) if raw else {"phase": "waiting"}
    except Exception:
        return {"phase": "waiting"}


class SmartRecorder:
    """Records a single user interaction and produces a SiteAdapterConfig.

    The browser stays open until the user confirms in the terminal.
    """

    def __init__(self, target_url: str, timeout_s: int = 180) -> None:
        self.target_url = target_url
        self.timeout_s = timeout_s

    def record(
        self,
        confirm_callback: Any = None,
        llm_provider: str = "heuristic",
        llm_model: str | None = None,
        llm_base_url: str | None = None,
        llm_api_key: str | None = None,
    ) -> SiteAdapterConfig:
        """
        Open a headed browser, auto-detect UI selectors using LLM/heuristics,
        confirm with user, and return a SiteAdapterConfig ready for replay.
        """
        from playwright.sync_api import sync_playwright
        from llm_intruder.browser.llm_detector import (
            LLMSmartDetector,
            _try_open_chat_launcher,
        )

        log.info("recorder_start", url=self.target_url, llm_provider=llm_provider)

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()

            try:
                # domcontentloaded — networkidle hangs on SPAs with
                # WebSockets / long-poll (Meraki, enterprise dashboards).
                page.goto(self.target_url, wait_until="domcontentloaded", timeout=45_000)
                log.info("recorder_navigated", url=self.target_url)

                try:
                    page.wait_for_timeout(2000)
                except Exception:
                    pass
                _dismiss_consent(page, retries=4)
                try:
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

                # ── PRE-DETECTION: open any chat launcher FIRST ────────────────
                # Chat widgets like Haptik/PVR require a launcher click before
                # the input field exists. If we detect first, we find the site's
                # main search box instead of the chat input.
                log.info("pre_detection_launcher_attempt")
                _try_open_chat_launcher(page)
                try:
                    page.wait_for_timeout(3000)   # wait for widget animation
                except Exception:
                    pass
                # Wait for any iframe to appear and load its content
                try:
                    page.wait_for_selector("iframe", timeout=5000)
                    page.wait_for_timeout(1500)   # extra for iframe DOM render
                except Exception:
                    pass

                # ── Phase 1: LLM/heuristic auto-detection ─────────────────────
                # browser-use provider: uses AI agent for complex sites
                if llm_provider == "browser-use":
                    try:
                        from llm_intruder.browser.browser_use_provider import (
                            detect_with_browser_use, check_browser_use_available,
                        )
                        if not check_browser_use_available():
                            raise ImportError(
                                "browser-use not installed. "
                                "Run: pip install browser-use langchain-openai"
                            )
                        bu_result = detect_with_browser_use(
                            target_url=self.target_url,
                            llm_api_key=llm_api_key,
                            llm_model=llm_model,
                            llm_base_url=llm_base_url,
                        )
                        detected = {
                            "input_selector": bu_result.get("input_selector", ""),
                            "submit_selector": bu_result.get("submit_selector", "__ENTER_KEY__"),
                            "response_selector": "__DIFF__",
                            "submit_method": bu_result.get("submit_method", "enter"),
                            "confidence": bu_result.get("confidence", 0.5),
                            "provider_used": "browser-use",
                            "reasoning": bu_result.get("raw_output", "")[:500],
                        }
                    except Exception as bu_err:
                        log.warning("browser_use_failed_falling_back_to_heuristic",
                                    error=str(bu_err)[:200])
                        detected = {
                            "input_selector": "textarea, input[type='text']",
                            "submit_selector": "__ENTER_KEY__",
                            "response_selector": "__DIFF__",
                            "submit_method": "enter",
                            "confidence": 0.1,
                            "provider_used": "browser-use/fallback",
                            "reasoning": f"browser-use failed: {bu_err}",
                        }
                else:
                    detector = LLMSmartDetector(
                        provider=llm_provider,
                        model=llm_model,
                        base_url=llm_base_url,
                        api_key=llm_api_key,
                    )
                    detected = detector.detect(page, self.target_url)

                confidence = detected.get("confidence", 0.0)
                provider_used = detected.get("provider_used", "unknown")
                # diff_frames captures which frames have the chatbot
                if llm_provider != "browser-use":
                    diff_frames = detector._diff_frames if detector._diff_frames else [page]
                else:
                    diff_frames = [page]

                log.info(
                    "auto_detection_complete",
                    confidence=confidence,
                    provider=provider_used,
                    input=detected.get("input_selector"),
                    submit=detected.get("submit_selector"),
                    response=detected.get("response_selector"),
                    in_iframe=detected.get("_active_frame_is_iframe", False),
                )

                state = {
                    "phase": "recorded",
                    "inputSelector": detected.get("input_selector"),
                    "submitSelector": detected.get("submit_selector"),
                    "responseSelector": detected.get("response_selector"),
                    "inputTag": "textarea",
                    "responseText": None,
                    "error": None,
                    "confidence": confidence,
                    "provider_used": provider_used,
                    "reasoning": detected.get("reasoning", ""),
                    "_diff_frames": diff_frames,
                    "_active_frame": detector._detected_frame if llm_provider != "browser-use" else page,
                }

                # ── Phase 2: Optional manual recording for low-confidence ──────
                needs_manual = confidence < 0.5 and llm_provider == "heuristic"

                if needs_manual:
                    log.info("low_confidence_falling_back_to_manual_recording")
                    # Launcher was already clicked pre-detection; just inject recorder
                    # Inject recorder into ALL frames
                    _inject_recorder_in_all_frames(page)
                    manual_state = self._wait_for_recording(page)
                    if manual_state.get("inputSelector"):
                        state.update({
                            "inputSelector": manual_state.get("inputSelector"),
                            "submitSelector": manual_state.get("submitSelector"),
                            "responseSelector": manual_state.get("responseSelector") or state["responseSelector"],
                            "responseText": manual_state.get("responseText"),
                        })

                if confirm_callback:
                    accepted = confirm_callback(state, page)
                    if not accepted:
                        log.info("user_rejected_auto_detection_entering_manual_mode")
                        state["manual_mode"] = True
                        state["rejection_count"] = 1
                        while True:
                            accepted = confirm_callback(state, page)
                            if accepted:
                                break
                            try:
                                import click as _click
                                abort = _click.prompt(
                                    "  Abort browser-test entirely? [y/n]",
                                    type=_click.Choice(["y", "n"], case_sensitive=False),
                                    default="n",
                                )
                            except Exception:
                                abort = "y"
                            if abort.lower() == "y":
                                raise RuntimeError("Recording aborted by user.")
                            state["rejection_count"] = state.get("rejection_count", 1) + 1

                return self._build_adapter(state)

            finally:
                context.close()
                browser.close()

    def _wait_for_recording(self, page: Any) -> dict:
        """Poll the injected JS recorder (in main page + all frames) until 'recorded'."""
        start = time.monotonic()
        last_phase = ""

        while (time.monotonic() - start) < self.timeout_s:
            state = _read_recorder_state_from_all_frames(page)
            phase = state.get("phase", "waiting")

            if phase != last_phase:
                log.info("recorder_phase", phase=phase)
                last_phase = phase

            if phase in ("recorded", "done"):
                return state

            time.sleep(0.5)

        raise TimeoutError(
            f"Recording timed out after {self.timeout_s}s. "
            "Please type a payload and click send within the time limit."
        )

    def _build_adapter(self, state: dict) -> SiteAdapterConfig:
        """Convert recorded selectors into a SiteAdapterConfig."""
        input_sel = state.get("inputSelector")
        submit_sel = state.get("submitSelector")
        response_sel = state.get("responseSelector")
        error = state.get("error")

        if error:
            raise RuntimeError(f"Recording failed: {error}")

        if not input_sel:
            raise RuntimeError(
                "Could not detect the input field. "
                "Please ensure you typed into a visible input."
            )

        submit_method: str = "click"
        submit_selector: str = submit_sel or ""
        if submit_sel == "__ENTER_KEY__":
            submit_method = "enter"
            submit_selector = input_sel
        elif submit_selector and not any(
            token in submit_selector.lower() for token in ("button", "input", "[role", "__")
        ):
            submit_method = "enter"
            submit_selector = input_sel

        if response_sel in (None, "", _DIFF_RESPONSE_SELECTOR):
            response_sel = _AUTO_RESPONSE_SELECTOR

        log.info(
            "recorder_result",
            input=input_sel,
            submit=submit_selector,
            submit_method=submit_method,
            response=response_sel,
        )

        return SiteAdapterConfig(
            mode="browser",
            target_url=self.target_url,
            input=InputConfig(
                selector=input_sel,
                submit=submit_selector,
                submit_method=submit_method,
                clear_before_fill=True,
            ),
            response=ResponseConfig(
                selector=response_sel,
                stream_detection=StreamDetectionConfig(
                    method="mutation_observer",
                    stability_ms=1500,
                    polling_interval_ms=300,
                    timeout_ms=60_000,
                ),
                wipe_detection=WipeDetectionConfig(enabled=True, check_selector=response_sel),
            ),
            csrf=CsrfConfig(enabled=False),
            wait_for_ready=WaitForReadyConfig(selector=input_sel, timeout=30_000),
        )


def record_and_build_adapter(target_url: str, timeout_s: int = 180) -> SiteAdapterConfig:
    """Convenience function: record one interaction and return a SiteAdapterConfig."""
    recorder = SmartRecorder(target_url=target_url, timeout_s=timeout_s)
    return recorder.record()
