"""Run lifecycle routes + WebSocket endpoint."""
from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from llm_intruder.dashboard.models import RunRequest, RunStatus
from llm_intruder.dashboard.runner_bridge import get_run, launch_run, list_runs, stop_run, skip_run, pause_run, resume_run, resolve_approval, submit_outer_html, submit_input_response, set_trial_delay
from llm_intruder.dashboard.ws_manager import ws_manager
from llm_intruder.dashboard.project_store import get_project_dir, list_run_dirs, get_run_meta

router = APIRouter(prefix="/api/runs", tags=["runs"])


@router.post("", status_code=202)
def start_run(req: RunRequest) -> dict:
    """Launch a new run. Returns run_id immediately; stream progress via WebSocket."""
    run_id = launch_run(req)
    return {"run_id": run_id, "status": "started"}


@router.get("/{project_id}")
def list_project_runs(project_id: str) -> list[dict]:
    """List all runs (in-memory + persisted) for a project."""
    # In-memory runs
    live = {r["run_id"]: r for r in list_runs(project_id)}
    # Persisted run dirs
    try:
        dirs = list_run_dirs(project_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")

    result = []
    for d in dirs:
        run_id = d.name
        if run_id in live:
            result.append(live[run_id])
        else:
            meta = get_run_meta(project_id, run_id)
            if meta:
                # Mark scheduled runs that can be resumed (have a checkpoint DB + not completed)
                if (
                    meta.get("run_mode") == "scheduled"
                    and meta.get("status") not in ("completed",)
                ):
                    db_path = d / "llm_intruder.db"
                    req_path = d / "run_request.json"
                    if db_path.exists() and req_path.exists():
                        # Check if a checkpoint exists in the DB
                        try:
                            import sqlite3
                            conn = sqlite3.connect(str(db_path))
                            cur = conn.cursor()
                            cur.execute(
                                "SELECT COUNT(*) FROM sqlite_master "
                                "WHERE type='table' AND name='campaign_checkpoints'"
                            )
                            has_table = cur.fetchone()[0] > 0
                            if has_table:
                                cur.execute("SELECT COUNT(*) FROM campaign_checkpoints")
                                has_ckpt = cur.fetchone()[0] > 0
                            else:
                                has_ckpt = False
                            conn.close()
                            meta["resumable"] = has_ckpt
                        except Exception:
                            meta["resumable"] = False
                result.append(meta)
    return result


@router.get("/detail/{run_id}")
def get_run_detail(run_id: str) -> dict:
    run = get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found in active runs.")
    return run


@router.post("/{run_id}/stop")
def request_stop(run_id: str) -> dict:
    ok = stop_run(run_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Run not active or already stopped.")
    return {"run_id": run_id, "status": "stopped"}


@router.post("/{run_id}/skip")
def request_skip(run_id: str) -> dict:
    """Skip current phase (attack→judge, judge→report) without stopping everything."""
    ok = skip_run(run_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Run not active or nothing to skip.")
    return {"run_id": run_id, "status": "skip_requested"}


@router.post("/{run_id}/pause")
def request_pause(run_id: str) -> dict:
    ok = pause_run(run_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Run not active or already paused.")
    return {"run_id": run_id, "status": "paused"}


@router.post("/{run_id}/resume")
def request_resume(run_id: str) -> dict:
    ok = resume_run(run_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Run not paused.")
    return {"run_id": run_id, "status": "resumed"}


class DelayRequest(BaseModel):
    delay_s: float


@router.post("/{run_id}/delay")
def request_set_delay(run_id: str, body: DelayRequest) -> dict:
    """Live-update the inter-trial delay (0–30 s). Takes effect on the next trial.

    Campaign, Hunt, and RAG Test modes honour this setting. Pool is concurrent
    and uses its own concurrency knob instead.
    """
    ok = set_trial_delay(run_id, body.delay_s)
    if not ok:
        raise HTTPException(status_code=404, detail="Run not found.")
    return {"run_id": run_id, "inter_trial_delay_s": body.delay_s}


class ApproveRequest(BaseModel):
    # accepted can be True (accept), False (cancel), or "retry" (try different element)
    accepted: bool | str


@router.post("/{run_id}/approve")
def approve_recording(run_id: str, body: ApproveRequest) -> dict:
    """Accept, reject, or retry the browser selector during a web-app run.

    accepted=True    → proceed with detected selectors
    accepted=False   → cancel the run
    accepted="retry" → go back to outerHTML input to try a different element
    """
    ok = resolve_approval(run_id, body.accepted)
    if not ok:
        raise HTTPException(status_code=400, detail="No approval pending for this run.")
    return {"run_id": run_id, "accepted": body.accepted}


class OuterHtmlRequest(BaseModel):
    outer_html: str


@router.post("/{run_id}/outer_html")
def submit_outer_html_route(run_id: str, body: OuterHtmlRequest) -> dict:
    """Submit the outerHTML of the response element when auto-capture fails.

    Called by the dashboard when the user pastes outerHTML from DevTools into
    the manual-mode input box that appears after a failed auto-capture attempt.
    The runner thread uses this to infer a CSS selector and re-verify capture.
    """
    ok = submit_outer_html(run_id, body.outer_html)
    if not ok:
        raise HTTPException(status_code=400, detail="No outerHTML submission pending for this run.")
    return {"run_id": run_id, "outer_html_received": True}


class InputResponseRequest(BaseModel):
    prompt_id: str
    value: str = ""


@router.post("/{run_id}/input_response")
def submit_input_response_route(run_id: str, body: InputResponseRequest) -> dict:
    """Submit the response to an interactive prompt (intruder setup wizard, etc.).

    The dashboard receives an ``input_request`` WebSocket event, renders a modal,
    and POSTs here when the user submits.  The server-side runner thread, which
    is blocked on a ``threading.Event``, is then unblocked with the supplied
    value via ``submit_input_response`` in ``runner_bridge``.
    """
    ok = submit_input_response(run_id, body.prompt_id, body.value)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="No input prompt pending for this run and prompt_id.",
        )
    return {"run_id": run_id, "prompt_id": body.prompt_id, "received": True}


@router.get("/{project_id}/{run_id}/trials")
def get_run_trials(project_id: str, run_id: str) -> dict:
    """Return all trials with verdicts from the run's SQLite DB."""
    import sqlite3
    try:
        run_dir = get_project_dir(project_id) / "runs" / run_id
        db_path = run_dir / "llm_intruder.db"
        if not db_path.exists():
            return {"trials": [], "verdict_counts": {}}
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # Get column names first to avoid errors on schema variations
        cur.execute("PRAGMA table_info(trials)")
        cols = {row["name"] for row in cur.fetchall()}
        select_cols = ", ".join(c for c in [
            "trial_id", "strategy", "verdict", "confidence",
            "request_payload", "response_text", "response_preview",
        ] if c in cols)
        if not select_cols:
            conn.close()
            return {"trials": [], "verdict_counts": {}}
        cur.execute(f"SELECT rowid, {select_cols} FROM trials ORDER BY rowid")
        rows = cur.fetchall()
        conn.close()
        trials = []
        verdict_counts: dict[str, int] = {}
        for i, row in enumerate(rows):
            rd = dict(row)
            verdict = (rd.get("verdict") or "pending").strip()
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            # Build a short payload preview from the request body
            raw_payload = rd.get("request_payload") or rd.get("response_text") or ""
            payload_preview = ""
            try:
                import json as _json
                data = _json.loads(raw_payload)
                for key in ("prompt", "message", "input", "text", "query", "content"):
                    if key in data and isinstance(data[key], str):
                        payload_preview = data[key][:120]
                        break
                if not payload_preview:
                    payload_preview = raw_payload[:120]
            except Exception:
                payload_preview = raw_payload[:120]
            resp_preview = (rd.get("response_preview") or rd.get("response_text") or "")[:120]
            trials.append({
                "trial_num": i + 1,
                "strategy": rd.get("strategy") or "unknown",
                "encoding": None,
                "verdict": verdict,
                "confidence": float(rd.get("confidence") or 0),
                "payload_preview": payload_preview,
                "response_preview": resp_preview,
                "duration_ms": 0,
            })
        return {"trials": trials, "verdict_counts": verdict_counts}
    except Exception as exc:
        return {"trials": [], "verdict_counts": {}, "error": str(exc)}


@router.get("/{project_id}/{run_id}/report")
def get_report(project_id: str, run_id: str, fmt: str = "html") -> dict:
    """Return the path and content of a generated report."""
    try:
        run_dir = get_project_dir(project_id) / "runs" / run_id
        ext = "md" if fmt == "markdown" else fmt
        report_path = run_dir / f"report.{ext}"
        if not report_path.exists():
            raise HTTPException(status_code=404, detail=f"Report '{fmt}' not yet generated.")
        content = report_path.read_text(encoding="utf-8")
        return {"format": fmt, "content": content, "path": str(report_path)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.websocket("/ws/{run_id}")
async def run_websocket(websocket: WebSocket, run_id: str) -> None:
    """WebSocket endpoint — streams log/trial/progress events for a run."""
    await ws_manager.connect(run_id, websocket)
    # Send current state immediately on connect
    run = get_run(run_id)
    if run:
        await websocket.send_text(json.dumps({"event": "progress", "data": run}))
    # Replay any pending interactive prompts (approval / outerHTML / input)
    # so that a reconnecting dashboard can re-render the modal without the
    # operator missing the request.
    await ws_manager.replay_pending(run_id, websocket)
    try:
        while True:
            # Keep connection alive; actual data is pushed by runner_bridge
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(run_id, websocket)


class OpenFolderRequest(BaseModel):
    path: str


# Separate router mounted at /api so it doesn't get the /api/runs prefix
util_router = APIRouter(prefix="/api", tags=["util"])


@util_router.post("/open-folder")
def open_folder(req: OpenFolderRequest) -> dict:
    """Open the folder containing the given file path in the OS file manager."""
    try:
        target = Path(req.path)
        # If path points to a file, open its parent directory
        folder = target.parent if target.is_file() else target
        if not folder.exists():
            raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
        system = platform.system()
        if system == "Windows":
            # On Windows, open Explorer with the file selected
            if target.is_file():
                subprocess.Popen(["explorer", "/select,", str(target)])
            else:
                subprocess.Popen(["explorer", str(folder)])
        elif system == "Darwin":
            if target.is_file():
                subprocess.Popen(["open", "-R", str(target)])
            else:
                subprocess.Popen(["open", str(folder)])
        else:
            # Linux — try xdg-open
            subprocess.Popen(["xdg-open", str(folder)])
        return {"status": "ok", "folder": str(folder)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
