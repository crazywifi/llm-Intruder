"""Browser Driver — orchestrates Playwright to deliver a payload and capture the response.

The driver is intentionally split from the Playwright launch lifecycle so that
*page* can be injected (real browser in production, Mock in tests).

Typical call path
-----------------
1. ``BrowserDriver.send_payload(page, payload)``
   a. wait_for_ready  — ensure the chat UI is loaded
   b. harvest_csrf    — grab CSRF token if configured
   c. _resolve_active_frame — detect which frame (main or iframe) has the input
   d. fill_input      — type payload into the input field (in the right frame)
   e. submit          — click button or press Enter (in the right frame)
   f. ResponseCapture.capture(page, payload) — diff across main + all frames
   g. Return CapturedResponse

IFRAME SUPPORT
--------------
Chatbot widgets like Haptik (PVR Cinemas), Intercom, Zendesk, and Drift embed
themselves inside a cross-origin <iframe>. Playwright cannot interact with
cross-origin iframes via page.querySelector() — you must use page.frames to get
the Frame object and call evaluate/fill/click directly on that Frame.

The driver resolves this automatically: on first send_payload() it scans all
frames for the configured input selector. Whichever frame matches becomes the
_active_frame. All subsequent fill/click/evaluate calls go through _active_frame.
The ResponseCapture is given the full list of frames to diff so it catches
responses that appear inside the iframe.

LAUNCHER CLICK SUPPORT
-----------------------
Chat widgets that need a button click to open (e.g. the floating chat bubble
on PVR Cinemas) are handled by _ensure_widget_open() which is called before
the first interaction. It tries common launcher selectors and waits for the
input field to become visible.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from llm_intruder.browser.models import CapturedResponse, SiteAdapterConfig
from llm_intruder.browser.response_capture import ResponseCapture

log = structlog.get_logger()

# Common launcher button selectors for embedded chat widgets
_LAUNCHER_SELECTORS = [
    # Haptik / XDK (used by PVR Cinemas and many others)
    '[class*="haptik-xdk"]',
    '[id*="haptik"]',
    '[class*="chat-trigger"]',
    '[class*="chatbot-trigger"]',
    '[class*="chat-fab"]',
    '[class*="chat-bubble"]',
    # Intercom
    '.intercom-launcher',
    '[data-intercom-launcher]',
    '[class*="intercom-launcher"]',
    # Zendesk
    '#launcher',
    '[data-testid="launcher"]',
    # Drift
    '#drift-widget-container button',
    '[class*="drift-open-chat"]',
    # Generic
    'button[class*="chat"]:not([disabled])',
    '[class*="fab-button"]',
    '[aria-label*="open chat" i]',
    '[title*="chat with" i]',
]


class BrowserDriver:
    """
    Delivers payloads through a browser UI and captures the model's response.

    Parameters
    ----------
    adapter:
        Loaded and validated :class:`SiteAdapterConfig`.
    variables:
        ``${VAR}`` substitution table (e.g. ``{"USERNAME": "alice"}``).
    """

    def __init__(
        self,
        adapter: SiteAdapterConfig,
        variables: dict[str, str] | None = None,
    ) -> None:
        self.adapter = adapter
        self.variables: dict[str, str] = variables or {}
        self._capture = ResponseCapture(adapter.response)
        # The Playwright frame that actually contains the input/submit elements.
        # None until first _resolve_active_frame() call.
        self._active_frame: Any = None
        # FrameLocator (page.frame_locator) for the iframe containing the input.
        # This is the CORRECT way to interact with cross-origin iframes in Playwright.
        # _active_frame (Frame object from page.frames) works for evaluate/query,
        # but frame_locator is needed for .type(), .click(), .fill() interactions.
        self._active_frame_locator: Any = None
        # True after first widget-open attempt — avoids re-clicking on payload 2+
        self._widget_open_attempted: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_payload(self, page: Any, payload: str) -> CapturedResponse:
        """
        Full pipeline: launcher? → wait → CSRF → resolve-frame → fill → submit → capture.

        When adapter.mode == 'coord', replays the recorded CoordAction sequence
        using page.mouse.click(x,y) + page.keyboard.type() — works on any site
        regardless of shadow DOM, iframes, or JS framework.

        Returns a :class:`CapturedResponse` with the model's reply and metadata.
        """
        log.info("driver_send_payload", chars=len(payload), mode=self.adapter.mode)

        # ── Coordinate-based replay (mode="coord") ─────────────────────────
        if self.adapter.mode == "coord":
            return self._send_payload_coord(page, payload)

        # ── Standard selector-based replay (mode="browser" / "hybrid") ─────
        self._wait_for_ready(page)
        csrf_token = self._harvest_csrf(page)

        # Ensure the chat widget is open (handles launcher buttons like PVR/Haptik)
        self._ensure_widget_open(page)

        # Resolve which frame (main page or an iframe) contains the input
        frame = self._resolve_active_frame(page)

        # Detect BotFramework WebChat and override submit_method to "enter"
        self._auto_detect_webchat(frame)

        # ARM the MutationObserver BEFORE sending — so we don't miss the response.
        # Pass ALL frames so responses inside iframes are also captured.
        self._capture.pre_capture_setup(page, extra_frames=self._get_all_frames(page))

        self._fill_input(frame, payload)
        self._submit(frame, csrf_token)

        # Brief pause to let BotFramework WebChat register the sent message
        try:
            page.wait_for_timeout(200)
        except Exception:
            pass

        return self._capture.capture(page, payload)

    def _send_payload_coord(self, page: Any, payload: str) -> CapturedResponse:
        """Replay a coordinate-based action sequence (mode='coord').

        Uses page.mouse.click(x, y) and page.keyboard.type() — works on any
        website regardless of shadow DOM, cross-origin iframes, or framework.
        """
        import time as _time
        from llm_intruder.browser.llm_detector import SmartResponseReader
        from llm_intruder.core.audit_log import sha256

        actions = self.adapter.coord_actions
        if not actions:
            log.warning("coord_mode_no_actions_falling_back_to_browser")
            # Fall back to selector mode if no coord_actions are recorded yet
            self.adapter.mode = "browser"  # type: ignore[assignment]
            return self.send_payload(page, payload)

        # Snapshot text BEFORE sending (shadow-DOM-aware diff)
        reader = SmartResponseReader()
        reader.set_frames(list(page.frames))
        reader.snapshot_before(page)

        start = _time.monotonic()
        log.info("coord_replay_start", actions=len(actions))

        for action in actions:
            atype = action.type

            if atype == "click":
                log.debug("coord_replay_click", x=action.x, y=action.y)
                try:
                    page.mouse.click(action.x, action.y)
                except Exception as exc:
                    log.warning("coord_replay_click_failed", x=action.x, y=action.y,
                                error=str(exc))

            elif atype == "type_payload":
                log.debug("coord_replay_type_payload", payload_len=len(payload))
                try:
                    page.keyboard.press("Control+a")
                    page.keyboard.press("Delete")
                    page.keyboard.type(payload, delay=30)
                except Exception as exc:
                    log.warning("coord_replay_type_failed", error=str(exc))

            elif atype == "type":
                try:
                    page.keyboard.type(action.text, delay=20)
                except Exception as exc:
                    log.warning("coord_replay_type_literal_failed", error=str(exc))

            elif atype == "press":
                try:
                    page.keyboard.press(action.key)
                except Exception as exc:
                    log.warning("coord_replay_press_failed", key=action.key, error=str(exc))

            elif atype == "wait":
                try:
                    page.wait_for_timeout(action.ms)
                except Exception:
                    pass

            # Per-action pause (skip for wait — already slept)
            if atype != "wait" and action.ms > 0:
                try:
                    page.wait_for_timeout(action.ms)
                except Exception:
                    pass

        # Capture response via shadow-DOM-aware text diff
        sd = self.adapter.response.stream_detection
        text = reader.read_new_response(
            page,
            timeout_s=sd.timeout_ms / 1000,
            stability_s=sd.stability_ms / 1000,
            sent_payload=payload,
        )

        duration_ms = (_time.monotonic() - start) * 1000
        log.info("coord_replay_response_captured",
                 chars=len(text), duration_ms=round(duration_ms, 1))

        return CapturedResponse(
            text=text.strip(),
            stream_detected=True,
            capture_duration_ms=round(duration_ms, 1),
            payload_hash=sha256(payload),
            response_hash=sha256(text),
        )

    # ------------------------------------------------------------------
    # Widget launcher
    # ------------------------------------------------------------------

    def _ensure_widget_open(self, page: Any) -> None:
        """Click a chat launcher button if the chat widget is not yet open.

        IMPORTANT: We always attempt the launcher on the first send_payload call.
        The previous logic checked if inp.selector was visible — but that check
        was wrong because the detected selector could be the site search box
        (input[placeholder="Search..."]) which is always visible on the main page,
        causing us to skip the launcher click and never open the chat widget.

        Strategy:
          1. On first call, ALWAYS attempt launcher buttons unconditionally.
          2. After clicking, wait for widget animation + iframe to load.
          3. Reset _active_frame so _resolve_active_frame rescans.
          4. On subsequent calls, only attempt if input is still not found anywhere.
        """
        # First call: always try launcher (don't trust inp.selector yet — it may
        # be the site search box if auto-detection ran before widget was open).
        if self._widget_open_attempted:
            # Subsequent calls: only retry if input is genuinely missing
            if self._input_visible_somewhere(page):
                return
        self._widget_open_attempted = True

        # Try launcher buttons in the main page
        clicked = False
        for sel in _LAUNCHER_SELECTORS:
            try:
                result = page.evaluate(f"""() => {{
                    const el = document.querySelector({repr(sel)});
                    if (!el) return false;
                    let btn = el;
                    for (let i = 0; i < 4 && btn; i++) {{
                        const t = btn.tagName.toLowerCase();
                        if (t === 'button' || t === 'a' || btn.getAttribute('role') === 'button') break;
                        btn = btn.parentElement;
                    }}
                    if (!btn) return false;
                    const style = window.getComputedStyle(btn);
                    if (style.display === 'none' || style.visibility === 'hidden') return false;
                    btn.click();
                    return true;
                }}""")
                if result:
                    log.info("launcher_clicked_by_driver", selector=sel)
                    clicked = True
                    break
            except Exception:
                continue

        if clicked:
            try:
                page.wait_for_timeout(3000)   # 3s: Haptik widget needs ~2s to animate
            except Exception:
                pass
            # Wait for an iframe to appear and its content to render
            try:
                page.wait_for_selector("iframe", timeout=5000)
                page.wait_for_timeout(1500)
            except Exception:
                pass
            # Reset cached frame so _resolve_active_frame rescans after widget opens
            self._active_frame = None
            self._active_frame_locator = None
        else:
            log.debug("no_launcher_button_found_proceeding_as_is")

    def _input_visible_somewhere(self, page: Any) -> bool:
        """Return True if the configured input selector is visible in any frame."""
        inp = self.adapter.input
        # Try main page
        try:
            el = page.query_selector(inp.selector)
            if el and el.is_visible():
                return True
        except Exception:
            pass
        # Try iframes
        try:
            for i, frame in enumerate(page.frames):
                if i == 0:
                    continue
                try:
                    el = frame.query_selector(inp.selector)
                    if el and el.is_visible():
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Frame resolution
    # ------------------------------------------------------------------

    def _get_all_frames(self, page: Any) -> list[Any]:
        """Return [page] + all sub-frames for multi-frame diffing."""
        frames: list[Any] = [page]
        try:
            for i, frame in enumerate(page.frames):
                if i == 0:
                    continue
                frames.append(frame)
        except Exception:
            pass
        return frames

    def _build_frame_locator(self, page: Any, frame_index: int) -> Any:
        """Build a Playwright FrameLocator for the iframe at the given frame index.

        page.frames[i] gives a Frame object good for .evaluate()/.query_selector(),
        but .type()/.click()/.fill() on it time out for cross-origin nested iframes.
        page.frame_locator(css) gives a FrameLocator that Playwright routes correctly.

        We walk through possible iframe selectors and return the first one whose
        content_frame matches the Frame object we already found via page.frames.
        """
        IFRAME_SELECTORS = [
            "iframe",
            "iframe[id*='haptik']",
            "iframe[src*='haptik']",
            "iframe[class*='haptik']",
            "iframe[title*='chat' i]",
            "iframe[name*='chat' i]",
            "iframe[id*='chat']",
            "iframe[id*='bot']",
            "iframe[src*='bot']",
        ]
        try:
            target_frame = page.frames[frame_index]
        except Exception:
            return None
        
        # Strategy 1: try named frame selectors
        for sel in IFRAME_SELECTORS:
            try:
                fl = page.frame_locator(sel)
                # Validate by checking if its content_frame matches our target
                cf = fl.owner.content_frame()
                if cf and cf == target_frame:
                    log.debug("frame_locator_matched", selector=sel)
                    return fl
            except Exception:
                pass

        # Strategy 2: walk all iframe elements and match by frame index
        try:
            iframes = page.query_selector_all("iframe")
            for idx, iframe_el in enumerate(iframes):
                try:
                    cf = iframe_el.content_frame()
                    if cf == target_frame:
                        sel = f"iframe >> nth={idx}"
                        fl = page.frame_locator(f"iframe:nth-of-type({idx+1})")
                        log.debug("frame_locator_nth_matched", index=idx)
                        return fl
                except Exception:
                    continue
        except Exception:
            pass

        # Strategy 3: use frame name or url as identifier  
        try:
            fname = target_frame.name
            if fname:
                fl = page.frame_locator(f"iframe[name='{fname}']")
                log.debug("frame_locator_by_name", name=fname)
                return fl
        except Exception:
            pass

        log.warning("frame_locator_build_failed_falling_back_to_frame_object", frame_index=frame_index)
        return None

    def _resolve_active_frame(self, page: Any) -> Any:
        """Determine which frame contains the configured input selector.

        On first call: scans main page then all iframes. Caches result.
        Returns the Playwright Frame (or page) where the input lives.
        Also sets self._active_frame_locator for interaction methods.
        """
        if self._active_frame is not None:
            # Re-validate cached frame is still alive
            try:
                el = self._active_frame.query_selector(self.adapter.input.selector)
                if el is not None:
                    return self._active_frame
            except Exception:
                self._active_frame = None
                self._active_frame_locator = None

        inp = self.adapter.input

        # 1. Try main page
        try:
            el = page.query_selector(inp.selector)
            if el is not None:
                log.debug("active_frame_is_main_page")
                self._active_frame = page
                self._active_frame_locator = None  # no locator needed for main page
                return page
        except Exception:
            pass

        # 2. Try each iframe — use frame_locator for interaction, frame for detection
        try:
            for i, frame in enumerate(page.frames):
                if i == 0:
                    continue
                try:
                    el = frame.query_selector(inp.selector)
                    if el is not None:
                        frame_url = ""
                        try:
                            frame_url = frame.url or ""
                        except Exception:
                            pass
                        log.info("active_frame_is_iframe", frame_index=i,
                                 url=frame_url[:80], selector=inp.selector)
                        self._active_frame = frame
                        self._active_frame_locator = self._build_frame_locator(page, i)
                        return frame
                except Exception:
                    continue
        except Exception:
            pass

        # 3. Broad fallback selectors if configured selector not found
        BROAD_INPUT_SELECTORS = [
            'textarea:not([disabled])',
            'input[type="text"]:not([disabled])',
            '[contenteditable="true"]',
            '[role="textbox"]',
        ]
        # KEY: Check iframes FIRST with broad selectors — chat widgets live in iframes.
        try:
            for i, frame in enumerate(page.frames):
                if i == 0:
                    continue
                for broad_sel in BROAD_INPUT_SELECTORS:
                    try:
                        el = frame.query_selector(broad_sel)
                        if el is not None:
                            log.info("active_frame_broad_fallback_iframe",
                                     frame_index=i, selector=broad_sel)
                            self._active_frame = frame
                            self._active_frame_locator = self._build_frame_locator(page, i)
                            return frame
                    except Exception:
                        continue
        except Exception:
            pass
        # Only fall back to main page when iframes had nothing
        for broad_sel in BROAD_INPUT_SELECTORS:
            try:
                el = page.query_selector(broad_sel)
                if el is not None:
                    log.info("active_frame_broad_fallback_main", selector=broad_sel)
                    self._active_frame = page
                    self._active_frame_locator = None
                    return page
            except Exception:
                pass

        # Last resort: use main page
        log.warning("active_frame_not_found_using_main_page")
        self._active_frame = page
        self._active_frame_locator = None
        return page

    def _auto_detect_webchat(self, frame: Any) -> None:
        """Detect BotFramework WebChat and switch submit_method to enter."""
        try:
            is_webchat = frame.evaluate("""() => {
                return !!(
                    document.querySelector('[class*="webchat"]') ||
                    document.querySelector('[class*="webchat__send-box"]') ||
                    document.querySelector('[data-testid="send box text area"]') ||
                    (window.botchat) ||
                    document.querySelector('.wc-app')
                );
            }""")
            if is_webchat and self.adapter.input.submit_method != "enter":
                log.info("auto_detected_botframework_webchat_forcing_enter_submit")
                object.__setattr__(self.adapter.input, "submit_method", "enter")
                object.__setattr__(self.adapter.input, "submit", self.adapter.input.selector)
        except Exception:
            pass

    def wait_and_navigate(self, page: Any) -> None:
        """Navigate to target_url and wait for the UI to be ready."""
        log.info("driver_navigate", url=self.adapter.target_url)
        # domcontentloaded instead of networkidle — avoids hanging on SPAs
        # with persistent WebSockets / long-polling (Meraki, Slack, etc.).
        try:
            page.goto(self.adapter.target_url, wait_until="domcontentloaded", timeout=45_000)
        except Exception as _nav_err:
            log.warning("driver_navigate_slow", error=str(_nav_err)[:200])
        self._wait_for_ready(page)

    def _wait_for_ready(self, page: Any) -> None:
        wfr = self.adapter.wait_for_ready
        if wfr is None:
            return
        log.debug("driver_wait_ready", selector=wfr.selector)
        try:
            page.wait_for_timeout(300)
        except Exception:
            pass
        self._dismiss_cookie_consent(page, retries=4)
        try:
            page.wait_for_timeout(200)
        except Exception:
            pass
        # Try wait in main page first
        try:
            page.wait_for_selector(wfr.selector, timeout=wfr.timeout)
            return
        except Exception:
            pass
        # If not found in main page, check iframes (e.g. widget iframe is already loaded)
        try:
            for i, frame in enumerate(page.frames):
                if i == 0:
                    continue
                try:
                    frame.wait_for_selector(wfr.selector, timeout=5000)
                    log.info("wait_for_ready_found_in_iframe", frame=i)
                    return
                except Exception:
                    continue
        except Exception:
            pass
        # If selector not found anywhere, just wait the full timeout and continue
        log.warning("wait_for_ready_selector_not_found_anywhere", selector=wfr.selector)

    def _harvest_csrf(self, page: Any) -> str | None:
        cfg = self.adapter.csrf
        if not cfg.enabled:
            return None
        try:
            el = page.query_selector(cfg.token_selector)
            if el is None:
                log.warning("csrf_element_not_found", selector=cfg.token_selector)
                return None
            token: str = el.get_attribute(cfg.token_attribute) or ""
            log.debug("csrf_harvested", token_len=len(token))
            return token
        except Exception as exc:
            log.warning("csrf_harvest_error", error=str(exc))
            return None

    def _fill_input(self, frame: Any, payload: str) -> None:
        """Fill the chat input field in a way that fires React synthetic events.

        Operates on the resolved frame (may be an iframe, not the main page).
        Handles textarea, input[text], and contenteditable div (Haptik uses the last).

        KEY FIX: For cross-origin iframes, frame.type()/frame.click() time out even
        when frame.query_selector() works. We use self._active_frame_locator
        (a FrameLocator from page.frame_locator()) for interaction, which Playwright
        routes correctly through its internal CDP session.
        """
        inp = self.adapter.input
        log.debug("driver_fill", selector=inp.selector)

        # Determine the interaction target:
        # - If we have a FrameLocator, use it for .locator() calls (correct for cross-origin iframes)
        # - Otherwise use the Frame/page object directly
        fl = self._active_frame_locator  # may be None

        def _get_locator(sel: str) -> Any:
            """Return a Playwright Locator for sel, routed through the right frame."""
            if fl is not None:
                return fl.locator(sel)
            return frame.locator(sel)

        # 1. Focus the element first
        try:
            _get_locator(inp.selector).click(timeout=10000)
            log.debug("driver_fill_clicked_to_focus")
        except Exception as exc:
            log.debug("driver_fill_click_focus_failed", error=str(exc)[:120])
            # Try JS click via frame.evaluate as fallback
            try:
                frame.evaluate(f"() => {{ const el = document.querySelector({repr(inp.selector)}); if (el) el.focus(); }}")
            except Exception:
                pass

        # 2. Clear existing content via Ctrl+A → Delete
        if inp.clear_before_fill:
            try:
                _get_locator(inp.selector).press("Control+a", timeout=5000)
                _get_locator(inp.selector).press("Delete", timeout=5000)
            except Exception:
                pass
            # JS fallback clear — fires React synthetic events
            try:
                frame.evaluate("""(sel) => {
                    const el = document.querySelector(sel);
                    if (!el) return;
                    if (el.contentEditable === 'true') {
                        el.textContent = '';
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        return;
                    }
                    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value'
                    ) || Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
                    if (nativeInputValueSetter && nativeInputValueSetter.set) {
                        nativeInputValueSetter.set.call(el, '');
                    } else { el.value = ''; }
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                    el.dispatchEvent(new Event('change', { bubbles: true }));
                }""", inp.selector)
            except Exception:
                pass

        # 3. Type via FrameLocator (correct for cross-origin iframes)
        if len(payload) <= 500:
            try:
                _get_locator(inp.selector).type(payload, delay=2, timeout=15000)
                log.debug("driver_fill_typed_via_locator", chars=len(payload))
                return
            except Exception as exc:
                log.warning("driver_fill_locator_type_failed", error=str(exc)[:200])

        # 4. fill() via locator — faster than type(), works for most inputs
        try:
            _get_locator(inp.selector).fill(payload, timeout=10000)
            log.debug("driver_fill_filled_via_locator", chars=len(payload))
            return
        except Exception as exc:
            log.warning("driver_fill_locator_fill_failed", error=str(exc)[:200])

        # 5. JS evaluate fallback (contenteditable / React inputs)
        try:
            frame.evaluate("""(args) => {
                const [sel, val] = args;
                const el = document.querySelector(sel);
                if (!el) return false;
                if (el.contentEditable === 'true') {
                    el.focus();
                    el.textContent = '';
                    try {
                        document.execCommand('insertText', false, val);
                    } catch(e) {
                        el.textContent = val;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                    }
                    return true;
                }
                const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value'
                ) || Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value');
                if (nativeInputValueSetter && nativeInputValueSetter.set) {
                    nativeInputValueSetter.set.call(el, val);
                } else { el.value = val; }
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                return true;
            }""", [inp.selector, payload])
            log.debug("driver_fill_js_native_setter", chars=len(payload))
        except Exception as exc:
            log.warning("driver_fill_js_failed", error=str(exc)[:200])

    def _dismiss_cookie_consent(self, page: Any, retries: int = 3) -> None:
        """Dismiss cookie/consent banners before interacting with the page."""
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
                        log.info("cookie_consent_dismissed", selector=sel, attempt=attempt)
                        page.wait_for_timeout(300)
                        return
                except Exception:
                    continue
            found = False
            try:
                found = page.evaluate("""() => {
                    const kw = ['accept', 'agree', 'allow', 'i understand', 'got it'];
                    const els = document.querySelectorAll(
                        'button,[role="button"],a.btn,a.button,input[type="button"],input[type="submit"]'
                    );
                    for (const el of els) {
                        const t = (el.innerText||el.value||el.textContent||'').trim().toLowerCase();
                        if (kw.some(k => t === k || t === k+' all')) {
                            const r = el.getBoundingClientRect();
                            if (r.width > 0 && r.height > 0) { el.click(); return true; }
                        }
                    }
                    return false;
                }""")
            except Exception:
                pass
            if found:
                log.info("cookie_consent_dismissed_js", attempt=attempt)
                page.wait_for_timeout(300)
                return
            if attempt < retries - 1:
                _time.sleep(0.5)

    def _submit(self, frame: Any, csrf_token: str | None = None) -> None:
        """Submit the filled input. Operates on the resolved frame.

        KEY FIX: Like _fill_input, uses self._active_frame_locator when available
        so that Enter key presses and button clicks work in cross-origin iframes.
        """
        inp = self.adapter.input
        log.debug("driver_submit", method=inp.submit_method)

        if csrf_token and self.adapter.csrf.enabled:
            header_name = self.adapter.csrf.header_name
            try:
                frame.set_extra_http_headers({header_name: csrf_token})
            except Exception:
                pass
            log.debug("csrf_injected", header=header_name)

        fl = self._active_frame_locator  # FrameLocator if in cross-origin iframe

        def _get_locator(sel: str) -> Any:
            if fl is not None:
                return fl.locator(sel)
            return frame.locator(sel)

        if inp.submit_method == "enter":
            sent = False

            # Strategy A: FrameLocator-routed press (works for cross-origin iframes)
            try:
                _get_locator(inp.selector).press("Enter", timeout=10000)
                frame.wait_for_timeout(300)
                sent = True
                log.debug("driver_submit_enter_via_locator")
            except Exception as exc:
                log.debug("driver_submit_enter_locator_failed", error=str(exc)[:120])

            # Strategy B: JS KeyboardEvent dispatch
            if not sent:
                try:
                    frame.evaluate("""(sel) => {
                        const el = document.querySelector(sel);
                        if (!el) return;
                        ['keydown','keypress','keyup'].forEach(type => {
                            el.dispatchEvent(new KeyboardEvent(type, {
                                key: 'Enter', code: 'Enter', keyCode: 13,
                                which: 13, bubbles: true, cancelable: true
                            }));
                        });
                    }""", inp.selector)
                    frame.wait_for_timeout(300)
                    sent = True
                    log.debug("driver_submit_enter_js_event")
                except Exception as exc:
                    log.warning("driver_submit_enter_js_failed", error=str(exc)[:120])

            # Strategy C: find and click the send button via locator
            if not sent:
                SEND_BTN_SELECTORS = [
                    'button[aria-label*="send" i]',
                    'button[data-testid*="send" i]',
                    'button[title*="send" i]',
                    '[class*="send-box"] button',
                    '[class*="sendBox"] button',
                    '[class*="send_box"] button',
                    'div[class*="send"] button',
                ]
                for btn_sel in SEND_BTN_SELECTORS:
                    try:
                        _get_locator(btn_sel).click(timeout=5000)
                        sent = True
                        log.debug("driver_submit_send_button_found", selector=btn_sel)
                        break
                    except Exception:
                        continue

            if not sent:
                log.warning("driver_submit_enter_all_strategies_failed")

        else:
            submit_sel = inp.submit
            clicked = False

            # Strategy 1: FrameLocator-routed click (correct for cross-origin iframes)
            try:
                _get_locator(submit_sel).click(timeout=10000)
                clicked = True
                log.debug("driver_submit_click_via_locator", selector=submit_sel)
            except Exception as exc:
                log.warning("driver_submit_locator_click_failed", selector=submit_sel, error=str(exc)[:200])

            # Strategy 2: inner button within container
            if not clicked:
                try:
                    inner_btn = frame.query_selector(f"{submit_sel} button")
                    if inner_btn is None:
                        inner_btn = frame.query_selector(f"{submit_sel} [role='button']")
                    if inner_btn and inner_btn.is_visible():
                        inner_btn.click()
                        clicked = True
                        log.debug("driver_submit_inner_button")
                except Exception:
                    pass

            # Strategy 3: JavaScript click
            if not clicked:
                try:
                    frame.evaluate(
                        """(sel) => { const el = document.querySelector(sel); if (el) { el.click(); return true; } return false; }""",
                        submit_sel,
                    )
                    log.debug("driver_submit_js_click")
                    clicked = True
                except Exception as exc:
                    log.warning("driver_submit_js_click_failed", error=str(exc)[:120])

            # Strategy 4: Enter key fallback
            if not clicked:
                log.warning("driver_submit_fallback_enter")
                try:
                    _get_locator(inp.selector).press("Enter", timeout=5000)
                except Exception:
                    pass



# ------------------------------------------------------------------
# Convenience: run a single probe inside a fresh browser context
# ------------------------------------------------------------------

def run_probe(
    adapter: SiteAdapterConfig,
    payload: str,
    *,
    headless: bool = True,
    session_replay: Any | None = None,
    variables: dict[str, str] | None = None,
) -> CapturedResponse:
    """
    Launch Chromium, optionally replay a session login, send *payload*,
    capture and return the response.  Closes the browser when done.

    Parameters
    ----------
    session_replay:
        If provided, must be a :class:`~llm_intruder.session.replayer.SessionReplayer`
        instance.  Its ``replay()`` is called after navigation.
    """
    from playwright.sync_api import sync_playwright  # deferred import

    driver = BrowserDriver(adapter=adapter, variables=variables)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()

        try:
            log.info("probe_navigate", url=adapter.target_url)
            try:
                page.goto(adapter.target_url, wait_until="domcontentloaded", timeout=45_000)
            except Exception as _nav_err:
                log.warning("probe_navigate_slow", error=str(_nav_err)[:200])

            if session_replay is not None:
                log.info("probe_session_replay")
                session_replay.replay(page)

            result = driver.send_payload(page, payload)
        finally:
            context.close()
            browser.close()

    return result
