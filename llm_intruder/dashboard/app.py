"""LLM-Intruder Dashboard — FastAPI application factory."""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from llm_intruder.dashboard.local_llm_probe import probe_local_llms
from llm_intruder.dashboard.routes import payloads, playground, projects, runs, sessions

# ── Structlog → WebSocket bridge ─────────────────────────────────────────────
# Worker threads (hunt, browser-intruder) use structlog for low-level logging.
# By default those events only reach the server console. This processor
# intercepts specific event keys and forwards them to the dashboard terminal
# log so operators see payload/response lines in real time.
#
# Usage (set before starting a run thread):
#   _ws_log_ctx.run_id = run_id
#   _ws_log_ctx.loop   = asyncio_loop
# Reset on thread exit:
#   _ws_log_ctx.run_id = None

_ws_log_ctx = threading.local()

# Event keys whose "message" (or "event") field should appear in the terminal.
_WS_BRIDGE_EVENTS = {
    "intruder_trial_payload",
    "intruder_trial_response",
    "intruder_trial_response_empty",
    "intruder_trial_response_error",
    "intruder_inject_start",
    "intruder_inject_done",
    "intruder_inject_mutation_fallback",
    "intruder_inject_network_fallback",
    "intruder_inject_no_response_but_dom_changed",
    "intruder_inject_no_response_no_dom_change",
}


def _structlog_ws_bridge(logger, method, event_dict):
    """Structlog processor: forward selected events to the active run's WS."""
    event = event_dict.get("event", "")
    run_id = getattr(_ws_log_ctx, "run_id", None)
    loop   = getattr(_ws_log_ctx, "loop",   None)

    if run_id and loop and event in _WS_BRIDGE_EVENTS:
        # Prefer the human-readable "message" kwarg if present, else use event key.
        msg = event_dict.get("message") or event
        level = "warn" if method in ("warning", "error", "critical") else "info"
        try:
            import asyncio
            from datetime import datetime
            ts = datetime.now().strftime("%H:%M:%S")
            from llm_intruder.dashboard.ws_manager import ws_manager
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_log(run_id, level, f"[{ts}] {msg}"),
                loop,
            )
        except Exception:
            pass  # never crash the run thread over a log bridge failure

    return event_dict


def _install_structlog_ws_bridge() -> None:
    """Add the WS bridge processor to structlog's pipeline (idempotent)."""
    try:
        import structlog
        current = structlog.get_config().get("processors", [])
        # Only install once
        if any(getattr(p, "__name__", "") == "_structlog_ws_bridge" for p in current):
            return
        structlog.configure(processors=[_structlog_ws_bridge] + list(current))
    except Exception:
        pass  # structlog not installed or already locked — safe to ignore

_STATIC_DIR = Path(__file__).parent / "static"

# ── Payload field names heuristic (mirrors the JS _payloadFieldNames set) ────
_PAYLOAD_FIELDS = {
    "prompt", "message", "query", "question", "input", "text", "content",
    "msg", "user_input", "user_message", "userinput", "usermessage",
    "q", "ask", "request",
}


def _parse_burp_request(raw: str) -> dict[str, Any]:
    """Parse a raw Burp Suite HTTP request into adapter config fields."""
    blank = re.search(r"\r?\n\r?\n", raw)
    header_section = raw[: blank.start()] if blank else raw
    body_section = raw[blank.end():] if blank else ""

    lines = header_section.split("\n")
    req_line = lines[0].strip() if lines else ""
    parts = req_line.split(" ")
    path = parts[1] if len(parts) >= 2 else "/"

    # Headers to DROP from the preserved set (pseudo-headers, hop-by-hop, body-related)
    _DROP_HEADERS = {
        "host", "content-length", "transfer-encoding", "connection",
        "keep-alive", "upgrade", "proxy-authenticate", "proxy-authorization",
        "te", "trailers",
    }

    host = content_type = auth_header = ""
    preserved_headers: dict[str, str] = {}  # headers to pass through to adapter

    for line in lines[1:]:
        line = line.rstrip("\r")
        if not line.strip():
            break  # end of headers
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name_stripped = name.strip()
        value_stripped = value.strip()
        lc = name_stripped.lower()

        if lc == "host":
            host = value_stripped
        elif lc == "content-type":
            content_type = value_stripped
        elif lc == "authorization":
            auth_header = value_stripped
        elif lc not in _DROP_HEADERS:
            # Preserve all other headers (User-Agent, Accept, Origin, Referer, etc.)
            preserved_headers[name_stripped] = value_stripped

    scheme = "http" if ("localhost" in host or re.search(r":\d+$", host)) else "https"
    url = f"{scheme}://{host}{path}" if host else ""

    # Normalise content-type
    ct_base = content_type.split(";")[0].strip().lower()
    ct_map = {
        "application/json": "application/json",
        "application/x-www-form-urlencoded": "application/x-www-form-urlencoded",
        "multipart/form-data": "multipart/form-data",
        "application/graphql": "application/graphql",
        "application/xml": "application/xml",
        "text/xml": "text/xml",
        "application/soap+xml": "application/soap+xml",
        "text/plain": "text/plain",
        "application/octet-stream": "application/octet-stream",
        "application/x-ndjson": "application/x-ndjson",
        "text/html": "text/html",
    }
    norm_ct = ct_map.get(ct_base, ct_base)

    # Auth
    auth_type = auth_value = ""
    if auth_header:
        lower_auth = auth_header.lower()
        if lower_auth.startswith("bearer "):
            auth_type, auth_value = "bearer", auth_header[7:].strip()
        elif lower_auth.startswith("basic "):
            import base64
            try:
                auth_type = "basic"
                auth_value = base64.b64decode(auth_header[6:].strip()).decode()
            except Exception:
                auth_type, auth_value = "basic", auth_header[6:].strip()
        elif lower_auth.startswith("apikey ") or lower_auth.startswith("api-key "):
            auth_type = "api_key"
            auth_value = " ".join(auth_header.split(" ")[1:]).strip()

    # Body template for multipart / form-urlencoded
    burp_body_template = ""
    if body_section.strip():
        if "multipart" in ct_base:
            bm = re.search(r"boundary=([^\s;\"]+)", content_type, re.IGNORECASE)
            if bm:
                # RFC 2046: the boundary marker in the body is "--" + the boundary param value
                boundary = "--" + bm.group(1)
                fields: dict[str, str] = {}
                # Plain string split — most robust; ignores regex quoting issues
                for part in body_section.split(boundary):
                    stripped = part.strip()
                    # Skip empty parts and the closing "--" delimiter
                    if not stripped or stripped.startswith("--"):
                        continue
                    cd = re.search(r'Content-Disposition:[^\r\n]*name="([^"]+)"', part, re.IGNORECASE)
                    if not cd:
                        continue
                    name = cd.group(1)
                    # Value is the text after the blank line following the part headers
                    val_match = re.search(r"\r?\n\r?\n([\s\S]*)", part)
                    value = val_match.group(1).rstrip("\r\n") if val_match else ""
                    fields[name] = value
                if fields:
                    # Identify payload field
                    payload_field = next(
                        (k for k in fields if k.lower() in _PAYLOAD_FIELDS), None
                    ) or list(fields.keys())[-1]
                    tpl = {k: ("${PAYLOAD}" if k == payload_field else v)
                           for k, v in fields.items()}
                    import json as _json
                    burp_body_template = _json.dumps(tpl)
        elif "form-urlencoded" in ct_base:
            import json as _json
            from urllib.parse import parse_qs
            pairs = {k: v[0] for k, v in parse_qs(body_section.strip()).items()}
            if pairs:
                payload_field = next(
                    (k for k in pairs if k.lower() in _PAYLOAD_FIELDS), None
                ) or list(pairs.keys())[-1]
                tpl = {k: ("${PAYLOAD}" if k == payload_field else v) for k, v in pairs.items()}
                burp_body_template = _json.dumps(tpl)

    # ── Auto-detect response extraction path from the Host / URL ─────────────
    # Known API patterns: try to give a helpful default extraction path
    response_extraction_path = "$.choices[0].message.content"  # OpenAI-compatible default
    url_lower = url.lower()
    if "lakera" in url_lower or "gandalf" in url_lower:
        response_extraction_path = "$.answer"
    elif "anthropic" in url_lower:
        response_extraction_path = "$.content[0].text"
    elif "generativelanguage.googleapis" in url_lower or "gemini" in url_lower:
        response_extraction_path = "$.candidates[0].content.parts[0].text"
    elif "huggingface" in url_lower:
        response_extraction_path = "$[0].generated_text"
    elif "watson" in url_lower or "appdomain.cloud" in url_lower:
        response_extraction_path = "$.output.generic[0].text"

    return {
        "url": url,
        "content_type": norm_ct,
        "auth_type": auth_type,
        "auth_value": auth_value,
        "burp_body_template": burp_body_template,
        "response_extraction_path": response_extraction_path,
        "extra_headers": preserved_headers,  # all original headers preserved
    }


class BurpImportRequest(BaseModel):
    burp_text: str


class LLMTestRequest(BaseModel):
    provider: str
    api_key: str | None = None
    model: str | None = None
    base_url: str | None = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="LLM-Intruder Dashboard",
        description="LLM Security Assessment Tool — Web Dashboard",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Suppress noisy ProactorEventLoop pipe-write AssertionError ──────────
    # Python 3.14 + Windows ProactorEventLoop has a regression in
    # _ProactorBaseWritePipeTransport._loop_writing where the assertion
    #     assert f is self._write_fut
    # fires intermittently when subprocess pipes (Playwright/Chromium IPC,
    # uvicorn websocket frames) are torn down. The exception is raised inside
    # an event-loop callback and does NOT abort the run, but it spams the
    # cmd window with tracebacks. Swallow this specific case only.
    @app.on_event("startup")
    async def _install_structlog_bridge() -> None:
        _install_structlog_ws_bridge()

    @app.on_event("startup")
    async def _install_proactor_assert_filter() -> None:  # pragma: no cover
        import asyncio as _asyncio
        import os as _os
        loop = _asyncio.get_running_loop()
        prev_handler = loop.get_exception_handler()
        _DEBUG = _os.environ.get("LLM_INTRUDER_DEBUG") == "1"

        # Frames that legitimately produce *benign* asyncio exceptions on
        # Windows when a websocket / browser tab disconnects, or when a
        # subprocess pipe is closed faster than the loop's writer:
        #   • _ProactorBaseWritePipeTransport._loop_writing — pipe assert
        #   • _ProactorBasePipeTransport._call_connection_lost — RST close
        # Both are recoverable; the loop continues normally.
        _BENIGN_FRAMES = {"_loop_writing", "_call_connection_lost"}
        _BENIGN_MSG_KEYWORDS = (
            "proactor_events", "_loop_writing", "_call_connection_lost",
            "_ProactorBaseWritePipeTransport", "_ProactorBasePipeTransport",
        )
        # Exception types we know are benign in those frames.
        _BENIGN_TYPES: tuple = (
            AssertionError,
            ConnectionResetError,         # WinError 10054 — RST
            ConnectionAbortedError,       # WinError 10053 — abort
            BrokenPipeError,              # WinError 109   — pipe gone
        )

        def _handler(loop_, context):
            exc = context.get("exception")
            msg = str(context.get("message", ""))

            if isinstance(exc, _BENIGN_TYPES):
                # Match by message first (fast path)
                if any(k in msg for k in _BENIGN_MSG_KEYWORDS):
                    if _DEBUG:
                        loop_.default_exception_handler(context)
                    return
                # Or by traceback frame name (fallback)
                tbobj = getattr(exc, "__traceback__", None)
                while tbobj is not None:
                    if tbobj.tb_frame.f_code.co_name in _BENIGN_FRAMES:
                        if _DEBUG:
                            loop_.default_exception_handler(context)
                        return
                    tbobj = tbobj.tb_next

            if prev_handler is not None:
                prev_handler(loop_, context)
            else:
                loop_.default_exception_handler(context)

        loop.set_exception_handler(_handler)

        # ── Also filter the "Exception in callback …" lines that the
        # asyncio module logs at WARNING/ERROR level *before* our exception
        # handler runs, on Windows ProactorEventLoop.  Without this the user
        # still sees the traceback even though the loop continues.
        if not _DEBUG:
            import logging as _logging

            class _BenignProactorFilter(_logging.Filter):
                def filter(self, record: _logging.LogRecord) -> bool:
                    text = record.getMessage()
                    if any(k in text for k in _BENIGN_MSG_KEYWORDS):
                        return False
                    if record.exc_info and record.exc_info[1] is not None:
                        if isinstance(record.exc_info[1], _BENIGN_TYPES):
                            tbobj = record.exc_info[2]
                            while tbobj is not None:
                                if tbobj.tb_frame.f_code.co_name in _BENIGN_FRAMES:
                                    return False
                                tbobj = tbobj.tb_next
                    return True

            for name in ("asyncio", "uvicorn.error", "uvicorn"):
                _logging.getLogger(name).addFilter(_BenignProactorFilter())

    # ── API routers ───────────────────────────────────────────────────────────
    app.include_router(projects.router)
    app.include_router(runs.router)
    app.include_router(runs.util_router)
    app.include_router(payloads.router)
    app.include_router(playground.router)
    app.include_router(sessions.router)

    # ── Local LLM probe endpoint ──────────────────────────────────────────────
    @app.get("/api/local-llms")
    async def local_llms():
        return await probe_local_llms()

    # ── Health check ──────────────────────────────────────────────────────────
    @app.get("/api/health")
    def health():
        return {"status": "ok", "tool": "LLM-Intruder", "version": "0.1.0"}

    # ── LLM connection test ───────────────────────────────────────────────────
    @app.post("/api/test-llm")
    async def test_llm_connection(body: LLMTestRequest) -> dict:
        """Send a tiny ping message to the configured LLM and return success/failure."""
        _TIMEOUT = 15.0
        TEST_PROMPT = "Reply with the single word: pong"

        provider = body.provider.lower()

        try:
            # ── Local providers ──────────────────────────────────────────────
            if provider == "ollama":
                base = (body.base_url or "http://localhost:11434").rstrip("/")
                model = body.model or "llama3"
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(f"{base}/api/chat", json={
                        "model": model,
                        "messages": [{"role": "user", "content": TEST_PROMPT}],
                        "stream": False,
                    })
                r.raise_for_status()
                reply = r.json().get("message", {}).get("content", "").strip()
                return {"status": "ok", "provider": provider, "model": model, "reply": reply[:120]}

            if provider == "lmstudio":
                base = (body.base_url or "http://localhost:1234").rstrip("/")
                model = body.model or ""
                payload: dict[str, Any] = {
                    "messages": [{"role": "user", "content": TEST_PROMPT}],
                    "max_tokens": 16,
                    "stream": False,
                }
                if model:
                    payload["model"] = model
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(f"{base}/v1/chat/completions", json=payload)
                r.raise_for_status()
                reply = r.json()["choices"][0]["message"]["content"].strip()
                return {"status": "ok", "provider": provider, "model": model or "default", "reply": reply[:120]}

            # ── Cloud providers (OpenAI-compatible or vendor-specific) ────────
            if not body.api_key:
                return {"status": "error", "detail": "API key is required for cloud providers."}

            if provider == "openrouter":
                model = body.model or "openai/gpt-4o-mini"
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {body.api_key}",
                            "HTTP-Referer": "https://llm-intruder.io",
                            "X-Title": "LLM-Intruder",
                        },
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content": TEST_PROMPT}],
                            "max_tokens": 16,
                        },
                    )
                r.raise_for_status()
                reply = r.json()["choices"][0]["message"]["content"].strip()
                return {"status": "ok", "provider": provider, "model": model, "reply": reply[:120]}

            if provider == "openai":
                model = body.model or "gpt-4o-mini"
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={"Authorization": f"Bearer {body.api_key}"},
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content": TEST_PROMPT}],
                            "max_tokens": 16,
                        },
                    )
                r.raise_for_status()
                reply = r.json()["choices"][0]["message"]["content"].strip()
                return {"status": "ok", "provider": provider, "model": model, "reply": reply[:120]}

            if provider == "claude":
                model = body.model or "claude-haiku-4-5-20251001"
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(
                        "https://api.anthropic.com/v1/messages",
                        headers={
                            "x-api-key": body.api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        json={
                            "model": model,
                            "max_tokens": 16,
                            "messages": [{"role": "user", "content": TEST_PROMPT}],
                        },
                    )
                r.raise_for_status()
                reply = r.json()["content"][0]["text"].strip()
                return {"status": "ok", "provider": provider, "model": model, "reply": reply[:120]}

            if provider == "gemini":
                model = body.model or "gemini-1.5-flash"
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(
                        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={body.api_key}",
                        json={"contents": [{"parts": [{"text": TEST_PROMPT}]}]},
                    )
                r.raise_for_status()
                reply = r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                return {"status": "ok", "provider": provider, "model": model, "reply": reply[:120]}

            if provider == "grok":
                model = body.model or "grok-3-mini"
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    r = await client.post(
                        "https://api.x.ai/v1/chat/completions",
                        headers={"Authorization": f"Bearer {body.api_key}"},
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content": TEST_PROMPT}],
                            "max_tokens": 16,
                        },
                    )
                r.raise_for_status()
                reply = r.json()["choices"][0]["message"]["content"].strip()
                return {"status": "ok", "provider": provider, "model": model, "reply": reply[:120]}

            return {"status": "error", "detail": f"Unsupported provider for test: {provider}"}

        except httpx.HTTPStatusError as exc:
            try:
                err_body = exc.response.json()
                # Extract a human-readable message from common API error shapes
                if isinstance(err_body, dict):
                    # OpenAI / OpenRouter / Grok: {"error": {"message": "..."}}
                    inner = err_body.get("error") or {}
                    if isinstance(inner, dict):
                        msg = inner.get("message") or inner.get("msg") or str(inner)
                    else:
                        msg = str(inner)
                    # Anthropic: {"error": {"type": "...", "message": "..."}}
                    # Gemini:    {"error": {"code": 400, "message": "...", "status": "..."}}
                    if not msg or msg == "{}":
                        msg = err_body.get("message") or str(err_body)
                else:
                    msg = str(err_body)[:300]
            except Exception:
                msg = exc.response.text[:300]
            return {"status": "error", "detail": f"HTTP {exc.response.status_code}: {msg}"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

    # ── Burp import endpoint ──────────────────────────────────────────────────
    @app.post("/api/burp-import")
    async def burp_import(body: BurpImportRequest) -> dict:
        """Parse a Burp Suite saved HTTP request and return adapter config fields.
        Accepts JSON body: {"burp_text": "<raw HTTP request>"}
        """
        try:
            result = _parse_burp_request(body.burp_text)
            return {"status": "ok", "adapter": result}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

    # ── Static files and SPA fallback ────────────────────────────────────────
    # Disable browser caching so UI updates are picked up immediately without
    # requiring a hard-refresh. The dashboard is a local dev/ops tool where
    # freshness matters more than bandwidth.
    _NO_CACHE = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    }

    if _STATIC_DIR.exists():
        class _NoCacheStatic(StaticFiles):
            async def get_response(self, path, scope):
                resp = await super().get_response(path, scope)
                for k, v in _NO_CACHE.items():
                    resp.headers[k] = v
                return resp

        app.mount("/static", _NoCacheStatic(directory=str(_STATIC_DIR)), name="static")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str):
            # API calls go to their own routes; everything else → index.html
            if full_path.startswith("api/") or full_path == "openapi.json":
                from fastapi import HTTPException
                raise HTTPException(status_code=404)
            index = _STATIC_DIR / "index.html"
            if index.exists():
                return FileResponse(str(index), headers=_NO_CACHE)
            return {"error": "Dashboard UI not found. Run: pip install -e .[dashboard]"}

    return app
