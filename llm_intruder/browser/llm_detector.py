"""LLM-Powered Smart UI Detector — universal, works on any web chat app.

Design principles
-----------------
1. RESPONSE DETECTION: Never pre-select a "response container".
   Instead, snapshot ALL leaf text nodes before sending, then diff
   after. The text that appeared = the response. No selector needed.
   This is the only approach that works universally.

2. INPUT/SUBMIT DETECTION: Score every interactive element by proximity
   to bottom of viewport (chat inputs live at the bottom), element type,
   ARIA role, placeholder text. Falls back to LLM if configured.

3. IFRAME SUPPORT (NEW): Automatically scans all same-origin AND
   cross-origin iframes. Haptik, Intercom, Zendesk, Drift, and similar
   widgets embed the chatbot in an <iframe>. Detection now runs inside
   every frame until an input is found.

4. LAUNCHER CLICK (NEW): Some chat widgets (PVR/Haptik) require clicking
   a launcher bubble before the input field appears. The detector tries
   common launcher patterns before giving up.

5. MULTI-FRAME DIFF (NEW): SmartResponseReader.snapshot_before() and
   read_new_response() scan every frame (main + iframes) so responses
   that appear inside an iframe are captured correctly.

6. LLM OPTIONAL: LLM improves input/submit detection accuracy but is
   never required. Heuristic mode works with zero API keys.
"""
from __future__ import annotations

import json
import re
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


# ---------------------------------------------------------------------------
# Launcher / widget-open button patterns
# ---------------------------------------------------------------------------

_LAUNCHER_CLICK_JS = """() => {
    const launcherSelectors = [
        // Haptik / XDK (PVR Cinemas)
        '[class*="haptik-xdk"]',
        '[id*="haptik"]',
        '[class*="chat-trigger"]',
        '[class*="chatbot-trigger"]',
        '[class*="chat-fab"]',
        '[class*="chat-bubble"]',
        // Intercom
        '.intercom-launcher',
        '[data-intercom-launcher]',
        '[class*="intercom-launcher"]',
        // Zendesk
        '#launcher',
        '[data-testid="launcher"]',
        // Drift
        '#drift-widget-container button',
        '[class*="drift-open-chat"]',
        // Generic chat launchers
        'button[class*="chat"]:not([disabled])',
        'button[class*="widget"]:not([disabled])',
        '[class*="fab-button"]',
        '[class*="chat-icon"]',
        '[aria-label*="chat" i]:not(input):not(textarea)',
        '[title*="open chat" i]',
        '[title*="chat with" i]',
    ];

    for (const sel of launcherSelectors) {
        try {
            const el = document.querySelector(sel);
            if (!el) continue;
            // Walk up to the actual button (handles SVG/path children)
            let clickTarget = el;
            let cur = el;
            for (let i = 0; i < 4 && cur; i++) {
                const tag = cur.tagName.toLowerCase();
                if (tag === 'button' || tag === 'a' || cur.getAttribute('role') === 'button') {
                    clickTarget = cur;
                    break;
                }
                cur = cur.parentElement;
            }
            const rect = clickTarget.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            clickTarget.click();
            return { clicked: true, selector: sel };
        } catch(e) {}
    }
    return { clicked: false };
}"""


def _try_open_chat_launcher(page: Any) -> bool:
    """Try clicking a chat launcher/bubble to open the widget.

    Returns True if a launcher was found and clicked.
    Called automatically before element detection when no input is found.
    """
    try:
        result = page.evaluate(_LAUNCHER_CLICK_JS)
        if result and result.get("clicked"):
            log.info("launcher_clicked", selector=result.get("selector"))
            try:
                page.wait_for_timeout(3000)   # 3s: widget animation + iframe load
            except Exception:
                pass
            return True
    except Exception as exc:
        log.warning("launcher_click_failed", error=str(exc))
    return False


# ---------------------------------------------------------------------------
# Heuristic scoring — runs inside any frame context
# ---------------------------------------------------------------------------

_HEURISTIC_DETECT_JS = """() => {
    // ── Shadow-DOM-aware element traversal ─────────────────────────────
    // document.querySelectorAll() does NOT pierce shadow roots.
    // This recursive walker does: it enters every element.shadowRoot found
    // anywhere in the tree, so chatbots rendered inside web-components
    // (Haptik XDK, Intercom, custom widgets) are found correctly.
    function collectAll(predicate) {
        const found = [];
        function walk(node) {
            try {
                if (node.nodeType === 1 && predicate(node)) found.push(node);
                const kids = node.children;
                if (kids) { for (let i = 0; i < kids.length; i++) walk(kids[i]); }
                if (node.shadowRoot) walk(node.shadowRoot);
            } catch(e) {}
        }
        if (document.body) walk(document.body);
        return found;
    }

    function score_input(el) {
        let s = 0;
        const tag = el.tagName.toLowerCase();
        const type = (el.type || '').toLowerCase();
        const role = (el.getAttribute('role') || '').toLowerCase();
        const ce = el.getAttribute('contenteditable');
        const label = (el.getAttribute('aria-label') || el.getAttribute('placeholder') ||
                       el.getAttribute('title') || '').toLowerCase();
        const rect = el.getBoundingClientRect();
        const vh = window.innerHeight;
        if (tag === 'textarea') s += 60;
        if (ce === 'true') s += 50;
        if (tag === 'input' && (type === 'text' || type === '')) s += 35;
        if (role === 'textbox') s += 25;
        if (/message|chat|ask|type|prompt|input|query|question/i.test(label)) s += 40;
        if (rect.bottom > vh * 0.55) s += 20;
        if (rect.bottom > vh * 0.75) s += 15;
        if (rect.width > window.innerWidth * 0.3) s += 15;
        if (rect.width > window.innerWidth * 0.5) s += 10;
        if (el.disabled || el.getAttribute('aria-disabled') === 'true') s -= 200;
        return s;
    }

    function score_submit(el, inputEl) {
        let s = 0;
        const tag = el.tagName.toLowerCase();
        const type = (el.type || '').toLowerCase();
        const text = (el.getAttribute('aria-label') || el.getAttribute('title') ||
                      (el.innerText || '')).toLowerCase().trim();
        const rect = el.getBoundingClientRect();
        const inputRect = inputEl ? inputEl.getBoundingClientRect() : null;
        if (tag === 'button') s += 30;
        if (type === 'submit') s += 25;
        if (/^send$|^ask$|^submit$|^go$/.test(text)) s += 60;
        if (/send|submit|ask|chat/.test(text)) s += 30;
        if (inputRect) {
            const dx = Math.abs(rect.left - inputRect.right);
            const dy = Math.abs(rect.top - inputRect.top);
            if (dx < 150 && dy < 80) s += 40;
            if (dy < 150 && dx < 300) s += 20;
        }
        if (rect.bottom > window.innerHeight * 0.55) s += 15;
        if (rect.width < 80 && rect.height < 80) s += 10;
        if (el.disabled || el.getAttribute('aria-disabled') === 'true') s -= 100;
        let cur = el;
        while (cur && cur.tagName) {
            const t = cur.tagName.toLowerCase();
            if (t === 'nav' || t === 'header' || t === 'footer') { s -= 80; break; }
            cur = cur.parentElement;  // stops at null when crossing shadow boundary
        }
        return s;
    }

    // uniqueSelector: prefer stable attribute-based selectors.
    // Playwright auto-pierces shadow DOM, so [placeholder="..."] works even
    // when the element lives inside a shadow root — no path needed.
    function uniqueSelector(el) {
        if (el.id) return '#' + CSS.escape(el.id);
        for (const attr of ['data-testid', 'name', 'aria-label', 'placeholder']) {
            const v = el.getAttribute && el.getAttribute(attr);
            if (v) return el.tagName.toLowerCase() + '[' + attr + '=' + JSON.stringify(v) + ']';
        }
        if (el.classList && el.classList.length > 0) {
            const s = el.tagName.toLowerCase() + '.' +
                Array.from(el.classList).slice(0, 3).join('.');
            try { if (document.querySelectorAll(s).length === 1) return s; } catch(e) {}
        }
        const parts = [];
        let cur = el;
        while (cur && cur.tagName) {
            if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
            const parent = cur.parentElement;
            if (!parent) break;  // reached shadow-root boundary — stop path here
            const sibs = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
            let seg = cur.tagName.toLowerCase();
            if (sibs.length > 1) seg += ':nth-of-type(' + (sibs.indexOf(cur)+1) + ')';
            parts.unshift(seg);
            cur = parent;
        }
        return parts.join(' > ') || el.tagName.toLowerCase();
    }

    const inputs = collectAll(function(el) {
        const tag = el.tagName.toLowerCase();
        const type = (el.type || '').toLowerCase();
        const role = (el.getAttribute('role') || '').toLowerCase();
        const ce   = el.getAttribute('contenteditable');
        return (tag === 'textarea') ||
               (tag === 'input' && (type === 'text' || type === '' || !el.hasAttribute('type'))) ||
               (ce === 'true') || (role === 'textbox');
    }).filter(el => {
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    });

    if (!inputs.length) return null;
    inputs.sort((a, b) => score_input(b) - score_input(a));
    const bestInput = inputs[0];

    const buttons = collectAll(function(el) {
        const tag  = el.tagName.toLowerCase();
        const type = (el.type || '').toLowerCase();
        const role = (el.getAttribute('role') || '').toLowerCase();
        return tag === 'button' || type === 'submit' || role === 'button';
    }).filter(el => {
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    });

    buttons.sort((a, b) => score_submit(b, bestInput) - score_submit(a, bestInput));
    const bestSubmit = buttons.length > 0 ? buttons[0] : null;

    return {
        input_selector: uniqueSelector(bestInput),
        submit_selector: bestSubmit ? uniqueSelector(bestSubmit) : '__ENTER_KEY__',
        submit_method: bestSubmit ? 'click' : 'enter',
        confidence: 0.65,
        reasoning: 'heuristic DOM scoring (shadow-DOM aware)',
    };
}"""


def _heuristic_detect(ctx: Any) -> dict | None:
    """Run heuristic detection in a given frame/page context."""
    try:
        return ctx.evaluate(_HEURISTIC_DETECT_JS)
    except Exception as exc:
        log.warning("heuristic_detect_failed", error=str(exc))
        return None


def _heuristic_detect_in_all_frames(page: Any) -> tuple[dict | None, Any]:
    """Run heuristic detection across main page AND all iframes.

    KEY CHANGE: We now collect results from ALL frames before deciding.
    Iframe results are preferred over main-page results because chatbot
    widgets (Haptik, Intercom, Zendesk) live in iframes, while the main
    page often has false-positive inputs like site search boxes.

    Returns (result_dict, frame_context).
    frame_context is the Playwright frame/page object where the input was found.
    """
    main_result = _heuristic_detect(page)

    # Collect results from every iframe
    iframe_hits: list[tuple[dict, Any]] = []
    try:
        all_frames = page.frames
    except Exception:
        all_frames = []

    for i, frame in enumerate(all_frames):
        if i == 0:
            continue  # frame 0 is the main frame -- already handled above
        try:
            result = frame.evaluate(_HEURISTIC_DETECT_JS)
            if result and result.get("input_selector"):
                frame_url = ""
                try:
                    frame_url = frame.url or ""
                except Exception:
                    pass
                log.info("heuristic_detected_in_iframe",
                         frame_index=i, url=frame_url[:80],
                         input=result.get("input_selector"),
                         confidence=result.get("confidence", 0))
                iframe_hits.append((result, frame))
        except Exception as exc:
            log.debug("heuristic_iframe_scan_failed", frame=i, error=str(exc))

    # PREFER iframe results -- chat widgets live in iframes.
    # Main-page results are often site search boxes (false positives).
    if iframe_hits:
        best = max(iframe_hits, key=lambda x: x[0].get("confidence", 0))
        log.info("heuristic_preferring_iframe_result",
                 iframe_count=len(iframe_hits),
                 input=best[0].get("input_selector"))
        return best[0], best[1]

    # Fall back to main-page result only when no iframes had inputs
    if main_result and main_result.get("input_selector"):
        log.debug("heuristic_using_main_page_result",
                  input=main_result.get("input_selector"))
        return main_result, page

    return None, page

def _get_accessibility_tree(page: Any, max_chars: int = 6000) -> str:
    try:
        snap = page.locator("body").aria_snapshot()
        if snap and len(snap.strip()) > 20:
            return snap[:max_chars]
    except Exception:
        pass

    try:
        elements = page.evaluate("""() => {
            const results = [];
            const seen = new Set();
            function getSelector(el) {
                if (el.id) return '#' + CSS.escape(el.id);
                for (const attr of ['data-testid','name','aria-label','placeholder']) {
                    const v = el.getAttribute(attr);
                    if (v) {
                        const s = el.tagName.toLowerCase() + '[' + attr + '=' + JSON.stringify(v) + ']';
                        try { if (document.querySelectorAll(s).length === 1) return s; } catch(e) {}
                    }
                }
                if (el.classList.length > 0) {
                    const s = el.tagName.toLowerCase() + '.' +
                        Array.from(el.classList).slice(0, 3).join('.');
                    try { if (document.querySelectorAll(s).length === 1) return s; } catch(e) {}
                }
                return el.tagName.toLowerCase();
            }
            const query = 'input,textarea,button,[contenteditable="true"],[role="textbox"],[role="button"]';
            document.querySelectorAll(query).forEach(el => {
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) return;
                if (el.offsetParent === null && el.tagName !== 'BODY') return;
                const label = el.getAttribute('aria-label') || el.getAttribute('placeholder') ||
                              el.getAttribute('title') || (el.innerText||'').trim().slice(0,60) || '';
                const key = getSelector(el) + label;
                if (seen.has(key)) return;
                seen.add(key);
                results.push({ tag: el.tagName.toLowerCase(), type: el.type||null,
                    role: el.getAttribute('role')||el.tagName.toLowerCase(),
                    label: label, selector: getSelector(el), disabled: !!el.disabled,
                    x: Math.round(rect.x), y: Math.round(rect.y),
                    w: Math.round(rect.width), h: Math.round(rect.height) });
            });
            return results;
        }""")
        if elements:
            lines = ["Interactive elements:"]
            for i, el in enumerate(elements[:60]):
                lines.append(
                    f"[{i}] {el['tag']} role={el['role']} label={el['label']!r} "
                    f"sel={el['selector']!r} pos=({el['x']},{el['y']}) "
                    f"size=({el['w']}x{el['h']})"
                    + (" DISABLED" if el.get("disabled") else "")
                )
            return "\n".join(lines)[:max_chars]
    except Exception as exc:
        log.warning("ax_tree_js_failed", error=str(exc))
    return "(could not extract element tree)"


def _take_screenshot_b64(page: Any) -> str | None:
    try:
        import base64
        return base64.b64encode(page.screenshot(type="png", full_page=False)).decode()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# LLM detection prompts
# ---------------------------------------------------------------------------

_DETECT_PROMPT = """\
You are analyzing a web page that contains a chat or AI assistant interface.
Identify exactly 2 elements:

1. INPUT  — the text field where the user types their message
2. SUBMIT — the button or key to send the message

Page URL: {url}

Accessibility tree / element inventory:
{ax_tree}

Output ONLY a JSON object, no explanation, no markdown:
{{
  "input_selector": "<CSS selector>",
  "submit_selector": "<CSS selector OR '__ENTER_KEY__' if Enter is used>",
  "submit_method": "click or enter",
  "confidence": <0.0-1.0>,
  "reasoning": "<one sentence>"
}}

Rules:
- Prefer id > data-testid > aria-label > class selectors
- INPUT must be editable (textarea, input, contenteditable div)
- SUBMIT is the send/ask/go button closest to the input
- If no clear button, use "__ENTER_KEY__" and "enter"
- Output ONLY the JSON
"""

_DETECT_PROMPT_VISION = """\
You are analyzing a screenshot of a web chat/AI assistant page.
Identify the INPUT field (where user types) and SUBMIT button (to send).

URL: {url}

Element inventory:
{ax_tree}

Output ONLY JSON:
{{
  "input_selector": "<CSS selector>",
  "submit_selector": "<CSS selector OR '__ENTER_KEY__'>",
  "submit_method": "click or enter",
  "confidence": <0.0-1.0>,
  "reasoning": "<one sentence>"
}}
"""


def _call_llm(url, ax_tree, screenshot_b64, provider, model, base_url, api_key):
    prompt = _DETECT_PROMPT.format(url=url, ax_tree=ax_tree)
    raw = None
    try:
        import httpx
        if provider == "ollama":
            r = httpx.post(
                f"{(base_url or 'http://localhost:11434').rstrip('/')}/api/generate",
                json={"model": model or "llama3.2:3b", "prompt": prompt, "stream": False,
                      "format": "json",
                      "options": {"temperature": 0.0, "num_predict": 400, "num_ctx": 4096}},
                timeout=90)
            raw = r.json().get("response", "")
        elif provider == "lmstudio":
            r = httpx.post(
                f"{(base_url or 'http://localhost:1234/v1').rstrip('/')}/chat/completions",
                json={"model": model or "auto",
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.0, "max_tokens": 400},
                timeout=90)
            raw = r.json()["choices"][0]["message"]["content"]
        elif provider == "openai":
            msgs = [{"role": "user", "content": prompt}]
            if screenshot_b64:
                vp = _DETECT_PROMPT_VISION.format(url=url, ax_tree=ax_tree[:2000])
                msgs = [{"role": "user", "content": [
                    {"type": "text", "text": vp},
                    {"type": "image_url", "image_url": {
                        "url": f"data:image/png;base64,{screenshot_b64}", "detail": "low"}}]}]
            r = httpx.post("https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key or ''}"},
                json={"model": model or "gpt-4o-mini", "messages": msgs,
                      "temperature": 0.0, "max_tokens": 400,
                      "response_format": {"type": "json_object"}},
                timeout=60)
            raw = r.json()["choices"][0]["message"]["content"]
        elif provider == "claude":
            content = []
            if screenshot_b64:
                vp = _DETECT_PROMPT_VISION.format(url=url, ax_tree=ax_tree[:2000])
                content = [{"type": "image", "source": {"type": "base64",
                    "media_type": "image/png", "data": screenshot_b64}},
                    {"type": "text", "text": vp}]
            else:
                content = [{"type": "text", "text": prompt}]
            r = httpx.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key or "",
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": model or "claude-haiku-4-5-20251001", "max_tokens": 400,
                      "messages": [{"role": "user", "content": content}]},
                timeout=60)
            raw = r.json()["content"][0]["text"]
        elif provider == "openrouter":
            r = httpx.post("https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key or ''}"},
                json={"model": model or "mistralai/mistral-7b-instruct",
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.0, "max_tokens": 400},
                timeout=60)
            raw = r.json()["choices"][0]["message"]["content"]
    except Exception as exc:
        log.warning("llm_call_failed", provider=provider, error=str(exc))
        return None

    if not raw:
        return None
    try:
        clean = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
        m = re.search(r"\{.*\}", clean, re.DOTALL)
        if m:
            return json.loads(m.group(0))
    except Exception as exc:
        log.warning("llm_json_parse_failed", error=str(exc), raw=raw[:200])
    return None


# ---------------------------------------------------------------------------
# Selector verification
# ---------------------------------------------------------------------------

def _verify_selector(page: Any, selector: str | None) -> bool:
    if not selector or selector == "__ENTER_KEY__":
        return True
    try:
        return page.query_selector(selector) is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Universal response capture via text-node diffing — multi-frame aware
# ---------------------------------------------------------------------------

_SNAPSHOT_TEXT_NODES_JS = """() => {
    // Shadow-DOM-aware text snapshot.
    // document.createTreeWalker() does NOT cross shadow boundaries.
    // collectFrom() recurses into every element.shadowRoot it finds so
    // text rendered inside web-components (e.g. Haptik, custom widgets)
    // is included in the pre-send baseline and later in the diff.
    const results = [];

    function isInteractiveText(el) {
        let cur = el;
        while (cur && cur.tagName) {
            const tag = cur.tagName.toLowerCase();
            if (['input','textarea','button','select','option','label','form'].includes(tag)) return true;
            if (cur.getAttribute) {
                if (cur.getAttribute('contenteditable') === 'true') return true;
                const role = (cur.getAttribute('role') || '').toLowerCase();
                if (role === 'textbox' || role === 'button') return true;
            }
            cur = cur.parentElement;  // null at shadow-root boundary — loop exits
        }
        return false;
    }

    function collectFrom(root) {
        try {
            const doc = root.ownerDocument || document;
            // Walk TEXT nodes in the light DOM of this root
            const tWalk = doc.createTreeWalker(root, 4 /* SHOW_TEXT */);
            let node;
            while ((node = tWalk.nextNode())) {
                const text = (node.nodeValue || '').trim();
                if (text.length < 2) continue;
                const parent = node.parentElement;
                if (!parent) continue;
                try {
                    const s = (doc.defaultView || window).getComputedStyle(parent);
                    if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') continue;
                } catch(e) {}
                if (isInteractiveText(parent)) continue;
                const tag = parent.tagName.toLowerCase();
                if (['script','style','noscript','meta','head'].includes(tag)) continue;
                results.push(text);
            }
            // Walk ELEMENT nodes to find shadow roots and recurse
            const eWalk = doc.createTreeWalker(root, 1 /* SHOW_ELEMENT */);
            let el;
            while ((el = eWalk.nextNode())) {
                if (el.shadowRoot) collectFrom(el.shadowRoot);
            }
        } catch(e) {}
    }

    if (document.body) collectFrom(document.body);
    return results;
}"""

_DIFF_TEXT_NODES_JS = """(preTexts) => {
    // Shadow-DOM-aware text diff — mirrors the snapshot logic above.
    // collectFrom() recurses into shadow roots so new text appearing
    // inside web-components (e.g. Haptik bot replies) is captured.
    const preSet = new Set(preTexts);
    const newNodes = [];

    function isInteractiveText(el) {
        let cur = el;
        while (cur && cur.tagName) {
            const tag = cur.tagName.toLowerCase();
            if (['input','textarea','button','select','option','label','form'].includes(tag)) return true;
            if (cur.getAttribute) {
                if (cur.getAttribute('contenteditable') === 'true') return true;
                const role = (cur.getAttribute('role') || '').toLowerCase();
                if (role === 'textbox' || role === 'button') return true;
            }
            cur = cur.parentElement;
        }
        return false;
    }

    function collectFrom(root) {
        try {
            const doc = root.ownerDocument || document;
            const tWalk = doc.createTreeWalker(root, 4 /* SHOW_TEXT */);
            let node;
            while ((node = tWalk.nextNode())) {
                const text = (node.nodeValue || '').trim();
                if (text.length < 2) continue;
                if (preSet.has(text)) continue;
                const parent = node.parentElement;
                if (!parent) continue;
                try {
                    const s = (doc.defaultView || window).getComputedStyle(parent);
                    if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') continue;
                } catch(e) {}
                if (isInteractiveText(parent)) continue;
                const tag = parent.tagName.toLowerCase();
                if (['script','style','noscript','meta','head'].includes(tag)) continue;
                const rect = parent.getBoundingClientRect();
                if (!rect || rect.width === 0) continue;
                // Skip page chrome (nav/header/footer) — stops at shadow boundary naturally
                let cur = parent; let inChrome = false;
                while (cur && cur.tagName) {
                    const t = cur.tagName.toLowerCase();
                    if (t === 'nav' || t === 'header' || t === 'footer') { inChrome = true; break; }
                    cur = cur.parentElement;
                }
                if (inChrome) continue;
                newNodes.push({ text: text, y: Math.round(rect.y), x: Math.round(rect.x) });
            }
            // Recurse into shadow roots
            const eWalk = doc.createTreeWalker(root, 1 /* SHOW_ELEMENT */);
            let el;
            while ((el = eWalk.nextNode())) {
                if (el.shadowRoot) collectFrom(el.shadowRoot);
            }
        } catch(e) {}
    }

    if (document.body) collectFrom(document.body);

    newNodes.sort((a, b) => a.y - b.y || a.x - b.x);
    if (newNodes.length === 0) return '';
    const lines = [];
    let lastY = -999;
    for (const n of newNodes) {
        if (n.y > lastY + 30) lines.push('');
        lines.push(n.text);
        lastY = n.y;
    }
    return lines.join(' ').replace(/\\s+/g, ' ').trim();
}"""

_FIND_RESPONSE_SELECTOR_JS = """(args) => {
    const [responseText, sentPayload] = args;
    const needle = (responseText || '').trim();
    const payload = (sentPayload || '').trim();
    if (!needle) return null;

    function uniqueSelector(el) {
        if (!el || el === document.body || el === document.documentElement) return null;
        if (el.id) return '#' + CSS.escape(el.id);
        for (const attr of ['data-testid', 'name', 'aria-label', 'placeholder']) {
            const v = el.getAttribute(attr);
            if (v) {
                const s = el.tagName.toLowerCase() + '[' + attr + '=' + JSON.stringify(v) + ']';
                try { if (document.querySelectorAll(s).length === 1) return s; } catch(e) {}
            }
        }
        if (el.classList && el.classList.length > 0) {
            const s = el.tagName.toLowerCase() + '.' + Array.from(el.classList).slice(0, 3).join('.');
            try { if (document.querySelectorAll(s).length === 1) return s; } catch(e) {}
        }
        const parts = [];
        let cur = el;
        while (cur && cur !== document.body && cur !== document.documentElement) {
            let seg = cur.tagName.toLowerCase();
            if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
            const parent = cur.parentElement;
            if (parent) {
                const sibs = Array.from(parent.children).filter(c => c.tagName === cur.tagName);
                if (sibs.length > 1) seg += ':nth-of-type(' + (sibs.indexOf(cur) + 1) + ')';
            }
            parts.unshift(seg);
            cur = cur.parentElement;
        }
        return parts.join(' > ');
    }

    function isInteractive(el) {
        let cur = el;
        while (cur && cur !== document.body) {
            const tag = (cur.tagName || '').toLowerCase();
            if (['input','textarea','button','select','option','label','form'].includes(tag)) return true;
            const role = cur.getAttribute ? (cur.getAttribute('role') || '').toLowerCase() : '';
            if (role === 'textbox' || role === 'button') return true;
            if (cur.getAttribute && cur.getAttribute('contenteditable') === 'true') return true;
            cur = cur.parentElement;
        }
        return false;
    }

    const candidates = [];
    const elements = document.querySelectorAll('main, article, section, div, p, span, li');
    for (const el of elements) {
        const text = (el.innerText || '').trim();
        if (!text || text.length < 3) continue;
        if (!text.includes(needle)) continue;
        if (payload && text === payload) continue;
        if (payload && text.startsWith(payload) && text.length <= payload.length + 3) continue;
        if (isInteractive(el)) continue;
        const rect = el.getBoundingClientRect();
        if (!rect || rect.width === 0 || rect.height === 0) continue;

        let score = 0;
        score += Math.min(needle.length, text.length);
        score -= Math.max(0, text.length - needle.length);
        score -= Math.round(rect.width * rect.height / 5000);
        if (el.matches('[role="log"], [aria-live], .markdown, .prose, .response, .assistant')) score += 40;
        if (text === needle) score += 60;

        const sel = uniqueSelector(el);
        if (!sel) continue;
        candidates.push({ selector: sel, score: score, textLength: text.length });
    }

    candidates.sort((a, b) => b.score - a.score || a.textLength - b.textLength);
    return candidates.length ? candidates[0] : null;
}"""


class SmartResponseReader:
    """Universal response capture via text-node diffing.

    Works on ANY web app — no response_selector needed.
    Finds new text by comparing all visible text nodes before/after sending.

    IFRAME SUPPORT: When the chatbot lives inside an iframe (e.g. Haptik/PVR),
    call set_frames([page, iframe_frame]) before snapshot_before(). Both frames
    will be scanned for new text, so responses inside iframes are captured.
    """

    def __init__(self) -> None:
        self._pre_snapshot: list[str] = []
        self._scan_frames: list[Any] = []   # set by set_frames()

    def set_frames(self, frames: list[Any]) -> None:
        """Set which Playwright frames to diff for response text.

        Pass [page] for main-page-only (default).
        Pass [page, iframe_frame] when the chatbot is in an iframe.
        """
        self._scan_frames = frames

    def _snapshot_one(self, ctx: Any) -> list[str]:
        try:
            return ctx.evaluate(_SNAPSHOT_TEXT_NODES_JS) or []
        except Exception:
            return []

    def snapshot_before(self, page: Any) -> None:
        """Snapshot all visible text nodes BEFORE sending the payload.

        Scans the main page and any registered iframes.
        """
        frames = self._scan_frames if self._scan_frames else [page]
        combined: list[str] = []
        for ctx in frames:
            combined.extend(self._snapshot_one(ctx))
        self._pre_snapshot = combined
        log.debug("pre_snapshot_taken", node_count=len(self._pre_snapshot),
                  frame_count=len(frames))

    def _diff_one(self, ctx: Any, pre: list[str]) -> str:
        try:
            return ctx.evaluate(_DIFF_TEXT_NODES_JS, pre) or ""
        except Exception:
            return ""

    @staticmethod
    def _strip_echoed_payload(text: str, sent_payload: str | None) -> str:
        cleaned = (text or "").strip()
        payload = (sent_payload or "").strip()
        if not cleaned or not payload:
            return cleaned
        if cleaned == payload:
            return ""
        if cleaned.startswith(payload):
            remainder = cleaned[len(payload):].lstrip(" \n\r\t:-")
            if remainder:
                return remainder
        return cleaned

    def read_new_response(
        self,
        page: Any,
        timeout_s: float = 60.0,
        stability_s: float = 2.0,
        poll_interval_s: float = 0.4,
        sent_payload: str | None = None,
    ) -> str:
        """Wait for new text nodes to appear and stabilise across all frames."""
        frames = self._scan_frames if self._scan_frames else [page]
        deadline = time.monotonic() + timeout_s
        last_text = ""
        stable_since: float | None = None
        pre = self._pre_snapshot

        while time.monotonic() < deadline:
            time.sleep(poll_interval_s)

            # Collect diff from all frames
            parts = []
            for ctx in frames:
                part = self._diff_one(ctx, pre)
                if part and part.strip():
                    parts.append(part.strip())
            new_text = " ".join(parts).strip()

            if new_text and len(new_text) >= 3:
                if new_text == last_text:
                    if stable_since is None:
                        stable_since = time.monotonic()
                    if time.monotonic() - stable_since >= stability_s:
                        new_text = self._strip_echoed_payload(new_text, sent_payload)
                        log.info("response_stable", chars=len(new_text),
                                 preview=new_text[:100].replace("\n", " "))
                        return new_text
                else:
                    stable_since = None
                    last_text = new_text
            else:
                stable_since = None

        log.warning("response_capture_timeout", chars=len(last_text))
        return self._strip_echoed_payload(last_text, sent_payload)

    @staticmethod
    def infer_response_selector(
        page: Any,
        response_text: str,
        sent_payload: str | None = None,
    ) -> dict | None:
        cleaned = SmartResponseReader._strip_echoed_payload(response_text, sent_payload)
        if not cleaned:
            return None
        try:
            return page.evaluate(_FIND_RESPONSE_SELECTOR_JS, [cleaned, sent_payload or ""])
        except Exception as exc:
            log.warning("response_selector_inference_failed", error=str(exc))
            return None

    @staticmethod
    def infer_response_selector_from_outer_html(
        page: Any,
        outer_html: str,
    ) -> dict | None:
        """Derive a CSS selector from a pasted outerHTML snippet."""
        import re as _re

        html = (outer_html or "").strip()
        if not html:
            return None

        tag_match = _re.search(r"<\s*([a-zA-Z0-9:_-]+)", html)
        tag = tag_match.group(1).lower() if tag_match else None

        def _attr(name: str) -> str | None:
            m = _re.search(rf'{name}\s*=\s*["\']([^"\']+)["\']', html, _re.IGNORECASE)
            return m.group(1).strip() if m else None

        def _count(sel: str) -> int:
            try:
                return page.evaluate(
                    "(sel) => document.querySelectorAll(sel).length", sel
                )
            except Exception:
                return 0

        def _try(selector: str) -> dict | None:
            try:
                el = page.query_selector(selector)
            except Exception:
                return None
            if el is None:
                return None
            try:
                if hasattr(el, "is_visible") and not el.is_visible():
                    return None
            except Exception:
                pass
            return {"selector": selector, "source": "outer_html"}

        def _css_safe_token(token: str) -> bool:
            return bool(token) and not _re.search(r'[\[\]():./\\@#]', token)

        candidate_selectors: list[str] = []

        if tag:
            id_val = _attr("id")
            if id_val:
                candidate_selectors.append(f"#{id_val}")

            for name in ("data-testid", "data-message-id", "data-index",
                         "data-cy", "name", "aria-label", "role"):
                value = _attr(name)
                if value:
                    candidate_selectors.append(f'{tag}[{name}="{value}"]')
                    candidate_selectors.append(f'[{name}="{value}"]')

            class_value = _attr("class")
            safe_tokens = [t for t in (class_value or "").split() if _css_safe_token(t)]

            if safe_tokens:
                compound = tag + "." + ".".join(safe_tokens[:3])
                if _count(compound) == 1:
                    candidate_selectors.insert(0, compound)
                elif len(safe_tokens) >= 2:
                    compound2 = tag + "." + ".".join(safe_tokens[:2])
                    if _count(compound2) == 1:
                        candidate_selectors.insert(0, compound2)

                for token in safe_tokens[:5]:
                    sel = f"{tag}.{token}"
                    if _count(sel) == 1:
                        candidate_selectors.append(sel)

            if _count(tag) == 1:
                candidate_selectors.append(tag)

        seen: set[str] = set()
        for selector in candidate_selectors:
            if not selector or selector in seen:
                continue
            seen.add(selector)
            result = _try(selector)
            if result:
                return result

        return None


# ---------------------------------------------------------------------------
# Main detector class
# ---------------------------------------------------------------------------

class LLMSmartDetector:
    """Detects input/submit selectors via LLM or heuristics.

    NEW CAPABILITIES:
    - Scans all iframes (handles Haptik/PVR, Intercom, Zendesk, Drift, etc.)
    - Tries launcher-click when no input is found on initial scan
    - Stores _detected_frame so BrowserDriver can target the right frame

    Response capture uses SmartResponseReader (text-node diff) — no selector needed.
    """

    def __init__(self, provider="heuristic", model=None, base_url=None,
                 api_key=None, use_screenshot=True, max_retries=2):
        self.provider = provider
        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.use_screenshot = use_screenshot and provider in ("openai", "claude")
        self.max_retries = max_retries
        # Set after detect() — the frame where the input was found
        self._detected_frame: Any = None
        # Frames to diff for response (main + iframe if applicable)
        self._diff_frames: list[Any] = []

    def detect(self, page: Any, url: str) -> dict:
        log.info("llm_detector_start", provider=self.provider, url=url)
        try:
            page.wait_for_load_state("networkidle", timeout=10_000)
        except Exception:
            pass
        try:
            page.wait_for_timeout(1500)
        except Exception:
            pass

        # Pass 1: detect in main page + all iframes as-is
        result, active_frame = self._run_detection(page, url)

        # Pass 2: if still nothing, try clicking a launcher button then re-detect
        if result is None or not result.get("input_selector"):
            log.info("no_input_found_trying_launcher_click")
            launched = _try_open_chat_launcher(page)
            if launched:
                try:
                    page.wait_for_timeout(2500)
                except Exception:
                    pass
                result, active_frame = self._run_detection(page, url)

        # Final fallback
        if result is None:
            log.warning("all_detection_methods_failed_using_defaults")
            result = {
                "input_selector": "textarea, input[type='text'], [contenteditable='true']",
                "submit_selector": "__ENTER_KEY__",
                "response_selector": "__DIFF__",
                "submit_method": "enter",
                "confidence": 0.1,
                "reasoning": "all methods failed — using broad defaults",
                "provider_used": "fallback",
            }
            active_frame = page

        # Store for caller use
        self._detected_frame = active_frame
        diff_frames = [page]
        if active_frame is not page:
            diff_frames.append(active_frame)
        self._diff_frames = diff_frames

        result["_active_frame_is_iframe"] = (active_frame is not page)
        return result

    def _run_detection(self, page: Any, url: str) -> tuple[dict | None, Any]:
        """Run LLM + heuristic detection across main page and all iframes."""
        ax_tree = _get_accessibility_tree(page)
        screenshot_b64 = _take_screenshot_b64(page) if self.use_screenshot else None
        result = None
        active_frame = page

        # LLM detection (main page only — screenshot covers the whole viewport)
        if self.provider != "heuristic":
            ax = ax_tree
            for attempt in range(self.max_retries + 1):
                llm_result = _call_llm(url, ax, screenshot_b64, self.provider,
                                       self.model, self.base_url, self.api_key)
                if llm_result:
                    input_ok = _verify_selector(page, llm_result.get("input_selector"))
                    submit_ok = _verify_selector(page, llm_result.get("submit_selector"))
                    if input_ok and submit_ok:
                        llm_result["provider_used"] = self.provider
                        llm_result["response_selector"] = "__DIFF__"
                        result = llm_result
                        log.info("llm_detection_success", attempt=attempt,
                                 input=llm_result.get("input_selector"),
                                 submit=llm_result.get("submit_selector"))
                        break
                    if attempt < self.max_retries:
                        failed = []
                        if not input_ok: failed.append(f"input={llm_result.get('input_selector')!r}")
                        if not submit_ok: failed.append(f"submit={llm_result.get('submit_selector')!r}")
                        ax += f"\n\nNOTE: Attempt {attempt+1} — selectors NOT found: {', '.join(failed)}. Use different selectors."
                    log.warning("llm_selectors_invalid", attempt=attempt,
                                input_ok=input_ok, submit_ok=submit_ok)

        # Heuristic detection: main page + ALL iframes
        if result is None:
            log.info("llm_detector_falling_back_to_heuristic")
            heuristic_result, active_frame = _heuristic_detect_in_all_frames(page)
            if heuristic_result:
                heuristic_result["provider_used"] = "heuristic"
                heuristic_result["response_selector"] = "__DIFF__"
                result = heuristic_result

        return result, active_frame

    def build_site_adapter(self, page: Any, url: str) -> SiteAdapterConfig:
        d = self.detect(page, url)
        input_sel = d["input_selector"]
        submit_sel = d["submit_selector"]
        submit_method = d.get("submit_method", "click")
        if submit_sel == "__ENTER_KEY__":
            submit_method = "enter"
            submit_sel = input_sel

        log.info("site_adapter_built", input=input_sel, submit=submit_sel,
                 method=submit_method, confidence=d.get("confidence"),
                 provider=d.get("provider_used"))

        return SiteAdapterConfig(
            mode="browser",
            target_url=url,
            input=InputConfig(selector=input_sel, submit=submit_sel,
                              submit_method=submit_method, clear_before_fill=True),
            response=ResponseConfig(
                selector=_AUTO_RESPONSE_SELECTOR,
                stream_detection=StreamDetectionConfig(
                    method="mutation_observer", stability_ms=2000,
                    polling_interval_ms=400, timeout_ms=60_000),
                wipe_detection=WipeDetectionConfig(enabled=False,
                                                   check_selector=_AUTO_RESPONSE_SELECTOR)),
            csrf=CsrfConfig(enabled=False),
            wait_for_ready=WaitForReadyConfig(selector=input_sel, timeout=30_000),
        )
