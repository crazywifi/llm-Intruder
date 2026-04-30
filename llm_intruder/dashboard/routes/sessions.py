"""Session recording and management routes."""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException

from llm_intruder.dashboard.project_store import get_project_dir
from llm_intruder.dashboard.runner_bridge import (
    _make_dashboard_io,
    _cancel_input_waits,
)
from llm_intruder.dashboard.ws_manager import ws_manager

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.post("/record")
async def start_record(project_id: str, target_url: str) -> dict:
    """Open a headed browser and record a login session.

    The ENTER prompt that historically blocked on server stdin now surfaces
    as an input_request modal in the dashboard.  The caller receives a
    ``session_id`` it can subscribe to via the existing ``/api/runs/ws/{id}``
    WebSocket to receive ``log`` and ``input_request`` events.

    Saves the session template YAML inside the project folder.
    """
    try:
        project_dir = get_project_dir(project_id)
        output_path = str(project_dir / "session_template.yaml")
        session_id = "rec-" + uuid.uuid4().hex[:10]
        loop = asyncio.get_running_loop()

        # Bridge stdout/stdin → dashboard via the same machinery used for
        # intruder setup. Operator presses ENTER in the modal; recorder
        # thread unblocks and saves the template + storage_state.
        print_fn, input_fn = _make_dashboard_io(session_id, loop)

        async def _run():
            try:
                await loop.run_in_executor(
                    None, _record_sync, target_url, output_path, print_fn, input_fn,
                )
            finally:
                _cancel_input_waits(session_id)
                ws_manager.clear_pending(session_id)

        # Launch in background; client uses session_id to follow progress.
        asyncio.create_task(_run())
        return {
            "status": "started",
            "session_id": session_id,
            "session_template": output_path,
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


def _record_sync(target_url: str, output_path: str, print_fn=None, input_fn=None) -> None:
    from llm_intruder.session.recorder import SessionRecorder
    recorder = SessionRecorder(target_url=target_url, output_path=output_path)
    if print_fn or input_fn:
        recorder.set_io(print_fn=print_fn, input_fn=input_fn)
    recorder.record()


@router.get("/templates/{project_id}")
def list_session_templates(project_id: str) -> list[dict]:
    """List recorded login-session templates only.

    Filters by:
      - filename containing "session" (case-insensitive), AND
      - structurally validates as a SessionTemplate (has a session_template
        root key) so engagement.yaml, site_adapter.yaml, intruder configs
        and other random YAMLs are excluded.
    """
    try:
        project_dir = get_project_dir(project_id)
        # Recursive scan but de-duplicated
        candidates = {
            p.resolve()
            for p in project_dir.rglob("*.yaml")
            if "session" in p.stem.lower()
        }
        result = []
        for t in sorted(candidates):
            # Skip files inside per-run dirs that aren't real session templates
            try:
                from llm_intruder.session.store import load_template
                load_template(str(t))  # raises if not a valid SessionTemplate
            except Exception:
                continue
            result.append({"name": t.stem, "path": str(t)})
        return result
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/validate")
async def validate_session(template_path: str) -> dict:
    try:
        from llm_intruder.session.store import load_template
        tmpl = load_template(template_path)
        data = tmpl.session_template
        return {
            "valid": True,
            "name": data.name,
            "target_url": data.target_url,
            "actions": len(data.actions),
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}
