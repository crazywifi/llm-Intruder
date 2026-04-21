"""Response capture — reads streamed text from the DOM.

Key fix for BotFramework WebChat (HP Virtual Agent):
- MutationObserver is set up BEFORE payload is sent (via pre_capture_setup)
- Falls back to polling-based approach with multiple selector candidates
- Extracts only the NEW bot message, not the full chat history

Key fix for iframe-embedded chatbots (Haptik/PVR, Intercom, Zendesk):
- pre_capture_setup accepts extra_frames and registers SmartResponseReader
  to scan ALL frames (main page + every iframe) for new text nodes.
- This means responses appearing inside cross-origin iframes are captured.
"""
from __future__ import annotations

import time
from typing import Any

import structlog

from llm_intruder.browser.models import CapturedResponse, ResponseConfig
from llm_intruder.browser.llm_detector import SmartResponseReader
from llm_intruder.core.audit_log import sha256

log = structlog.get_logger()

# ── Adaptive timing state ─────────────────────────────────────────────────────
import threading as _threading

class _AdaptiveTimer:
    """Per-session adaptive stability window."""
    def __init__(self, min_ms=300, max_ms=3000, patience=3):
        self.min_ms   = min_ms
        self.max_ms   = max_ms
        self.patience = patience
        self._current = min_ms
        self._fails   = 0
        self._wins    = 0
        self._lock    = _threading.Lock()

    @property
    def stability_ms(self) -> int:
        with self._lock:
            return self._current

    @property
    def poll_ms(self) -> int:
        return max(80, self._current // 4)

    def record_success(self) -> None:
        with self._lock:
            self._fails = 0
            self._wins += 1
            if self._wins >= self.patience and self._current > self.min_ms:
                self._current = max(self.min_ms, self._current - 200)
                self._wins = 0
                log.info("adaptive_speed_up", stability_ms=self._current)

    def record_failure(self) -> None:
        with self._lock:
            self._wins = 0
            self._fails += 1
            if self._fails >= self.patience and self._current < self.max_ms:
                self._current = min(self.max_ms, self._current * 2)
                self._fails = 0
                log.info("adaptive_slow_down", stability_ms=self._current)

# Global adaptive timer shared across all captures in a session
_ADAPTIVE = _AdaptiveTimer(min_ms=300, max_ms=3000, patience=3)

_AUTO_RESPONSE_SELECTOR = "__AUTO__"
_DIFF_RESPONSE_SELECTOR = "__DIFF__"

# ── JavaScript: set up observer and snapshot BEFORE payload is sent ──────────
_MO_SETUP_JS = """
(sel) => {
    // Reset state
    window.__sentinel_last_mut = 0;
    window.__sentinel_new_text = '';
    window.__sentinel_msg_count = 0;
    window.__sentinel_pre_text = '';

    // Count existing bot messages before we send
    const botMsgSelectors = [
        '[class*="webchat__basic-transcript"] [class*="webchat__stacked-layout"]',
        '[class*="activity-tree"] li',
        '[class*="transcript"] li',
        '[class*="chat-history"] [class*="message"]',
    ];
    for (const s of botMsgSelectors) {
        try {
            const items = document.querySelectorAll(s);
            if (items.length > 0) {
                window.__sentinel_msg_count = items.length;
                break;
            }
        } catch(e) {}
    }

    // Snapshot the full chat container text before sending
    const el = document.querySelector(sel);
    window.__sentinel_pre_text = el ? (el.innerText || '') : '';
    window.__sentinel_pre_len = window.__sentinel_pre_text.length;

    if (!el) {
        window.__sentinel_setup_error = 'selector not found: ' + sel;
        return false;
    }
    window.__sentinel_setup_error = null;

    // Watch for ANY DOM change in the chat container
    const obs = new MutationObserver(() => {
        const current = el.innerText || '';
        if (current.length > window.__sentinel_pre_len) {
            window.__sentinel_last_mut = Date.now();
            window.__sentinel_new_text = current;
        }
    });
    obs.observe(el, {childList: true, subtree: true, characterData: true});
    window.__sentinel_obs = obs;
    return true;
}
"""

# Same MO setup but runs on the whole document body (for iframes where we
# don't have a specific selector to watch).
# SHADOW DOM NOTE: MutationObserver subtree:true does NOT cross shadow boundaries,
# but document.body.innerText DOES include shadow-DOM text in Chromium.
# We therefore add a setInterval poll of innerText as a shadow-DOM fallback.
_MO_SETUP_BODY_JS = """
() => {
    window.__sentinel_last_mut = 0;
    window.__sentinel_new_text = '';
    window.__sentinel_pre_len = (document.body ? document.body.innerText.length : 0);
    window.__sentinel_setup_error = null;

    // Standard MO — fires for light-DOM mutations
    const obs = new MutationObserver(() => {
        const current = document.body ? (document.body.innerText || '') : '';
        if (current.length > window.__sentinel_pre_len) {
            window.__sentinel_last_mut = Date.now();
            window.__sentinel_new_text = current;
        }
    });
    if (document.body) {
        obs.observe(document.body, {childList: true, subtree: true, characterData: true});
    }

    // Polling fallback — catches shadow-DOM mutations that MO misses.
    // innerText renders shadow-DOM text in Chromium even when MO doesn't fire.
    const poll = setInterval(() => {
        const current = document.body ? (document.body.innerText || '') : '';
        if (current.length > window.__sentinel_pre_len) {
            window.__sentinel_last_mut = Date.now();
            window.__sentinel_new_text = current;
        }
    }, 250);

    window.__sentinel_obs  = obs;
    window.__sentinel_poll = poll;
    return true;
}
"""

_MO_LAST_MUT_JS    = "() => window.__sentinel_last_mut || 0"
_MO_NEW_TEXT_JS    = "() => window.__sentinel_new_text || ''"
_MO_PRE_LEN_JS     = "() => window.__sentinel_pre_len || 0"
_MO_SETUP_ERR_JS   = "() => window.__sentinel_setup_error || null"
_MO_DISCONNECT_JS  = "() => { try { window.__sentinel_obs && window.__sentinel_obs.disconnect(); } catch(e) {} try { window.__sentinel_poll && clearInterval(window.__sentinel_poll); } catch(e) {} }"

# JavaScript to get the last bot reply using multiple BotFramework selectors
_GET_LAST_BOT_MSG_JS = """
() => {
    const strategies = [
        () => {
            const items = document.querySelectorAll(
                '[class*="webchat__basic-transcript__activity"]:not([class*="from-user"]):not([class*="fromUser"])'
            );
            return items.length ? items[items.length-1].innerText : null;
        },
        () => {
            const items = document.querySelectorAll('[class*="webchat__stacked-layout--from-bot"]');
            return items.length ? items[items.length-1].innerText : null;
        },
        () => {
            const items = document.querySelectorAll('[class*="webchat__activity-tree"] > li');
            if (!items.length) return null;
            for (let i = items.length - 1; i >= 0; i--) {
                const li = items[i];
                if (!li.className.includes('user') && !li.className.includes('User')) {
                    const t = (li.innerText || '').trim();
                    if (t.length > 3) return t;
                }
            }
            return null;
        },
        () => {
            const items = document.querySelectorAll('[class*="webchat__basic-transcript"] > ul > li');
            if (!items.length) return null;
            for (let i = items.length - 1; i >= 0; i--) {
                const li = items[i];
                const t = (li.innerText || '').trim();
                if (t.length > 3 && !li.querySelector('input')) return t;
            }
            return null;
        },
        () => {
            for (const sel of [
                '.wc-message-from-bot:last-of-type',
                '[data-activity-id]:last-child',
                '.webchat__bubble--from-bot:last-of-type',
            ]) {
                try {
                    const el = document.querySelector(sel);
                    if (el) { const t = el.innerText.trim(); if (t.length > 3) return t; }
                } catch(e) {}
            }
            return null;
        },
    ];

    for (const fn of strategies) {
        try {
            const result = fn();
            if (result && result.trim().length > 3) return result.trim();
        } catch(e) {}
    }
    return null;
}
"""

# Broad fallback selectors tried in order if main selector fails
_FALLBACK_SELECTORS = [
    '[role="log"]',
    '[aria-live="polite"]',
    '[aria-live="assertive"]',
    '[data-testid*="response"]',
    '[data-testid*="message"]',
    '[data-testid*="answer"]',
    '[class*="messages"]',
    '[class*="message-list"]',
    '[class*="conversation"]',
    '[class*="chat-window"]',
    '[class*="chat-log"]',
    'section[class*="webchat__basic-transcript"]',
    '[class*="webchat__basic-transcript"]',
    '[class*="webchat__transcript"]',
    'div[class*="webchat__activity-tree"]',
    'div[class*="webchat"]',
    '.wc-chatview-panel',
    '[class*="chat-history"]',
    '[class*="transcript"]',
    '.response',
    '.assistant',
    '.markdown',
    '.prose',
]


class ResponseCapture:
    """Captures the model response from a live Playwright page.

    IFRAME SUPPORT:
    Call pre_capture_setup(page, extra_frames=[frame1, frame2, ...]) to
    register additional frames (e.g. iframe where the chatbot lives).
    The SmartResponseReader will diff all registered frames for new text.
    """

    def __init__(self, config: ResponseConfig) -> None:
        self.config = config
        self._smart_reader: SmartResponseReader | None = None
        self._all_frames: list[Any] = []   # set by pre_capture_setup

    # ------------------------------------------------------------------
    # Public — called by BrowserDriver
    # ------------------------------------------------------------------

    def pre_capture_setup(self, page: Any, extra_frames: list[Any] | None = None) -> None:
        """Snapshot all visible text nodes BEFORE sending, so we can diff after.

        Parameters
        ----------
        page:
            The main Playwright page.
        extra_frames:
            Additional frames to scan (e.g. iframes containing chatbot widgets).
            Pass the full list [page, iframe_frame] or just [page].
        """
        # Determine all frames to scan
        frames = extra_frames if extra_frames else [page]
        self._all_frames = frames

        # PRIMARY: SmartResponseReader text-node diff (works on any site, any frame)
        self._smart_reader = SmartResponseReader()
        self._smart_reader.set_frames(frames)
        self._smart_reader.snapshot_before(page)

        # SECONDARY: MutationObserver fallback (main page selector + each extra frame body)
        sel = self._resolve_selector(page)
        try:
            ok = page.evaluate(_MO_SETUP_JS, sel)
            err = page.evaluate(_MO_SETUP_ERR_JS)
            if err:
                log.warning("response_capture_setup_error", error=err, selector=sel)
            else:
                log.debug("response_capture_mo_armed", selector=sel, ok=ok)
        except Exception as exc:
            log.warning("response_capture_setup_exception", error=str(exc))

        # Also arm MO in each extra frame (the iframe where responses appear)
        for i, frame in enumerate(frames):
            if frame is page:
                continue
            try:
                frame.evaluate(_MO_SETUP_BODY_JS)
                log.debug("response_capture_mo_armed_iframe", frame_index=i)
            except Exception as exc:
                log.debug("response_capture_mo_iframe_failed", frame=i, error=str(exc))

    def capture(self, page: Any, payload: str) -> CapturedResponse:
        """Capture the bot response using text-node diffing as primary strategy.

        Strategy order:
        1. SmartResponseReader text-node diff — universal, works on any site + iframes
        2. MutationObserver — fallback (checks main page and all extra frames)
        3. Polling — second fallback
        4. JS last-bot-message extraction — last resort
        """
        start = time.monotonic()
        sd = self.config.stream_detection
        text = ""
        streamed = False

        # Strategy 1: SmartResponseReader text-node diff (PRIMARY)
        smart_reader = self._smart_reader
        if smart_reader is not None:
            smart_text = smart_reader.read_new_response(
                page,
                timeout_s=sd.timeout_ms / 1000,
                stability_s=_ADAPTIVE.stability_ms / 1000,
                poll_interval_s=_ADAPTIVE.poll_ms / 1000,
                sent_payload=payload,
            )
            if smart_text and len(smart_text.strip()) >= 5:
                text = smart_text.strip()
                streamed = True
                log.debug("response_capture_smart_reader_success", chars=len(text))

        # Strategy 2: MutationObserver fallback (main page)
        if not text or len(text.strip()) < 5:
            if sd.method == "mutation_observer":
                text, streamed = self._capture_mutation_observer(page)
            else:
                text, streamed = self._capture_polling(page)

        # Strategy 2b: MutationObserver in extra frames (iframes)
        if (not text or len(text.strip()) < 5) and self._all_frames:
            for frame in self._all_frames:
                if frame is page:
                    continue
                iframe_text = self._read_mo_from_frame(frame)
                if iframe_text and len(iframe_text.strip()) >= 5:
                    text = iframe_text.strip()
                    streamed = True
                    log.debug("response_capture_iframe_mo_success",
                              chars=len(text))
                    break

        # Strategy 3: Polling fallback
        if not text or len(text.strip()) < 3:
            log.debug("response_capture_mo_empty_trying_polling")
            text, streamed = self._capture_polling(page)

        # Strategy 4: JS bot message extraction — last resort
        if not text or len(text.strip()) < 3:
            log.debug("response_capture_trying_js_extract")
            try:
                text = page.evaluate(_GET_LAST_BOT_MSG_JS) or ""
            except Exception:
                pass
            # Also try in extra frames
            if not text or len(text.strip()) < 3:
                for frame in self._all_frames:
                    if frame is page:
                        continue
                    try:
                        frame_text = frame.evaluate(_GET_LAST_BOT_MSG_JS) or ""
                        if frame_text and len(frame_text.strip()) >= 3:
                            text = frame_text.strip()
                            break
                    except Exception:
                        continue

        duration_ms = (time.monotonic() - start) * 1000
        if text and len(text.strip()) >= 5:
            _ADAPTIVE.record_success()
        else:
            _ADAPTIVE.record_failure()

        log.info("response_captured", chars=len(text), duration_ms=round(duration_ms, 1),
                 stability_ms=_ADAPTIVE.stability_ms,
                 streamed=streamed, preview=(text[:80].replace('\n', ' ') if text else ''))

        was_wiped = False
        if self.config.wipe_detection.enabled and text:
            was_wiped = self._check_wipe(page, text)

        return CapturedResponse(
            text=text,
            was_wiped=was_wiped,
            stream_detected=streamed,
            capture_duration_ms=round(duration_ms, 1),
            payload_hash=sha256(payload),
            response_hash=sha256(text),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _read_mo_from_frame(self, frame: Any) -> str:
        """Read MutationObserver captured text from a specific iframe."""
        try:
            last_mut = frame.evaluate(_MO_LAST_MUT_JS) or 0
            if last_mut > 0:
                new_text = frame.evaluate(_MO_NEW_TEXT_JS) or ""
                pre_len = frame.evaluate(_MO_PRE_LEN_JS) or 0
                try:
                    frame.evaluate(_MO_DISCONNECT_JS)
                except Exception:
                    pass
                if new_text and len(new_text) > pre_len:
                    return new_text[pre_len:].strip()
                return new_text.strip()
        except Exception:
            pass
        return ""

    def _selector_is_auto(self, selector: str | None) -> bool:
        return selector in ("", None, _AUTO_RESPONSE_SELECTOR, _DIFF_RESPONSE_SELECTOR)

    def _resolve_selector(self, page: Any) -> str:
        """Return the configured selector if it matches something, else try fallbacks."""
        primary = self.config.selector
        if not self._selector_is_auto(primary):
            try:
                el = page.query_selector(primary)
                if el is not None:
                    return primary
            except Exception:
                pass
            log.debug("response_capture_primary_selector_missing", selector=primary)
        else:
            log.debug("response_capture_auto_selector_requested", selector=primary)
        for sel in _FALLBACK_SELECTORS:
            try:
                el = page.query_selector(sel)
                if el is not None:
                    log.info("response_capture_fallback_selector_used", selector=sel)
                    return sel
            except Exception:
                continue
        log.warning("response_capture_no_selector_found_using_primary")
        return primary or _AUTO_RESPONSE_SELECTOR

    def _capture_mutation_observer(self, page: Any) -> tuple[str, bool]:
        """Poll MutationObserver state until DOM is stable after bot starts replying."""
        cfg = self.config.stream_detection
        _stab_ms = _ADAPTIVE.stability_ms
        _poll_ms = _ADAPTIVE.poll_ms
        deadline = time.monotonic() + cfg.timeout_ms / 1000
        streamed = False
        bot_started = False
        last_log = 0.0

        while time.monotonic() < deadline:
            time.sleep(_poll_ms / 1000)

            try:
                last_mut = page.evaluate(_MO_LAST_MUT_JS) or 0
            except Exception:
                break

            if not bot_started:
                if last_mut > 0:
                    bot_started = True
                    log.debug("response_capture_bot_started")
                elif time.monotonic() - last_log > 5:
                    log.debug("response_capture_waiting_for_bot")
                    last_log = time.monotonic()
                continue

            silence_ms = (time.time() * 1000) - last_mut
            if silence_ms >= _stab_ms:
                streamed = True
                break

        try:
            page.evaluate(_MO_DISCONNECT_JS)
        except Exception:
            pass

        new_text = ""
        try:
            new_text = page.evaluate(_MO_NEW_TEXT_JS) or ""
        except Exception:
            pass

        try:
            bot_msg = page.evaluate(_GET_LAST_BOT_MSG_JS) or ""
            if bot_msg and len(bot_msg.strip()) > 3:
                return bot_msg.strip(), streamed
        except Exception:
            pass

        if new_text:
            pre_len = 0
            try:
                pre_len = page.evaluate(_MO_PRE_LEN_JS) or 0
            except Exception:
                pass
            if pre_len > 0 and len(new_text) > pre_len:
                new_text = new_text[pre_len:].strip()
        if not new_text:
            new_text = self._read_selector(page, self._resolve_selector(page))

        return new_text, streamed

    def _capture_polling(self, page: Any) -> tuple[str, bool]:
        """Poll selector text until two consecutive reads match (fallback strategy)."""
        cfg = self.config.stream_detection
        _stab_ms = _ADAPTIVE.stability_ms
        _poll_ms = _ADAPTIVE.poll_ms
        sel = self._resolve_selector(page)
        deadline = time.monotonic() + cfg.timeout_ms / 1000
        prev_len = -1
        stable_count = 0
        streamed = False
        required_stable = max(2, _stab_ms // _poll_ms)

        pre_text = self._read_selector(page, sel)
        pre_len = len(pre_text)

        while time.monotonic() < deadline:
            time.sleep(_poll_ms / 1000)

            try:
                bot_msg = page.evaluate(_GET_LAST_BOT_MSG_JS) or ""
                if bot_msg and len(bot_msg.strip()) > 3:
                    current_len = len(bot_msg)
                    if current_len == prev_len:
                        stable_count += 1
                        if stable_count >= required_stable:
                            return bot_msg.strip(), True
                    else:
                        stable_count = 0
                        prev_len = current_len
                    continue
            except Exception:
                pass

            current = self._read_selector(page, sel)
            current_len = len(current)

            has_stable_text = current_len > 0 and current_len == pre_len

            if current_len > pre_len or has_stable_text:
                if current_len == prev_len:
                    stable_count += 1
                    if stable_count >= required_stable:
                        streamed = True
                        new_part = current[pre_len:].strip() if current_len > pre_len else current
                        return new_part or current, streamed
                else:
                    stable_count = 0
            prev_len = current_len

        final = self._read_selector(page, sel)
        if final and len(final) >= pre_len:
            return final[pre_len:].strip() or final, streamed
        if pre_text:
            return pre_text, streamed
        return final, streamed

    def _read_selector(self, page: Any, selector: str) -> str:
        try:
            el = page.query_selector(selector)
            if el is None:
                return ""
            return el.inner_text() or ""
        except Exception as exc:
            log.warning("response_read_error", selector=selector, error=str(exc))
            return ""

    def _check_wipe(self, page: Any, captured_text: str) -> bool:
        wd = self.config.wipe_detection
        check_sel = wd.check_selector or self.config.selector
        if self._selector_is_auto(check_sel):
            check_sel = self._resolve_selector(page)
        time.sleep(0.3)
        current = self._read_selector(page, check_sel)
        return bool(captured_text) and (not current or len(current) < len(captured_text) * 0.5)
