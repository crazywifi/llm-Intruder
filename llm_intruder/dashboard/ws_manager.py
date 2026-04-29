"""WebSocket connection manager — broadcasts run progress to connected clients."""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

_LOG_BUFFER_MAX = 1000   # max lines kept per run


class WSManager:
    """Manages WebSocket connections keyed by run_id."""

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)
        # Latest "pending interaction" state per run_id, replayed on reconnect.
        self._pending: dict[str, dict[str, Any]] = defaultdict(dict)
        # Rolling log buffer per run_id — replayed to reconnecting clients.
        self._log_buffer: dict[str, list[dict]] = defaultdict(list)

    async def connect(self, run_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections[run_id].append(ws)

    def disconnect(self, run_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(run_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, run_id: str, event: str, data: Any) -> None:
        """Send a JSON event to all sockets watching this run."""
        message = json.dumps({"event": event, "data": data})
        dead: list[WebSocket] = []
        for ws in self._connections.get(run_id, []):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(run_id, ws)

    async def broadcast_log(self, run_id: str, level: str, message: str) -> None:
        entry = {"level": level, "message": message}
        buf = self._log_buffer[run_id]
        buf.append(entry)
        if len(buf) > _LOG_BUFFER_MAX:
            self._log_buffer[run_id] = buf[-_LOG_BUFFER_MAX:]
        await self.broadcast(run_id, "log", entry)

    async def replay_log_buffer(self, run_id: str, ws: WebSocket) -> None:
        """Send all buffered log lines to a freshly connected client."""
        for entry in self._log_buffer.get(run_id, []):
            try:
                await ws.send_text(json.dumps({"event": "log", "data": entry}))
            except Exception:
                break

    def clear_log_buffer(self, run_id: str) -> None:
        self._log_buffer.pop(run_id, None)

    async def broadcast_trial(self, run_id: str, trial: dict) -> None:
        await self.broadcast(run_id, "trial", trial)

    async def broadcast_progress(self, run_id: str, progress: dict) -> None:
        await self.broadcast(run_id, "progress", progress)

    async def broadcast_done(self, run_id: str, summary: dict) -> None:
        await self.broadcast(run_id, "done", summary)

    async def broadcast_error(self, run_id: str, error: str) -> None:
        await self.broadcast(run_id, "error", {"message": error})

    async def broadcast_alert(self, run_id: str, alert: dict) -> None:
        await self.broadcast(run_id, "alert", alert)

    async def broadcast_approval_request(self, run_id: str, payload: dict) -> None:
        """Ask the dashboard user to approve/reject detected selectors + test probe."""
        self._pending[run_id]["approval_request"] = payload
        await self.broadcast(run_id, "approval_request", payload)

    async def broadcast_approval_result(self, run_id: str, accepted: bool) -> None:
        """Confirm to the dashboard that the approval decision was received."""
        self._pending[run_id].pop("approval_request", None)
        await self.broadcast(run_id, "approval_result", {"accepted": accepted})

    async def broadcast_outerhtml_request(self, run_id: str, payload: dict) -> None:
        """Ask the dashboard user to paste the outerHTML of the response element.

        Sent when auto-capture fails so the user can manually anchor the
        response selector.  The UI should render an input box with step-by-step
        instructions and a Submit button that POSTs to /api/runs/{run_id}/outer_html.
        """
        self._pending[run_id]["outerhtml_request"] = payload
        await self.broadcast(run_id, "outerhtml_request", payload)

    async def broadcast_outerhtml_result(self, run_id: str, payload: dict) -> None:
        """Confirm to the dashboard that the outerHTML was received and processed."""
        # Don't drop outerhtml_request here — operator may still need to act on it.
        # It is cleared by broadcast_approval_request (success path) or by run end.
        await self.broadcast(run_id, "outerhtml_result", payload)

    # ── Generic interactive-prompt channel ────────────────────────────────────
    # Used by intruder setup wizard, login recorder, and any other code path
    # that previously printed to server stdin/stdout via input()/print(). The
    # dashboard renders a modal, the user submits, and the server-side runner
    # thread (blocked on a threading.Event) is unblocked via
    # /api/runs/{run_id}/input_response.
    def clear_pending(self, run_id: str) -> None:
        """Drop all replay state for a run (call at run completion / cleanup)."""
        self._pending.pop(run_id, None)

    async def replay_pending(self, run_id: str, ws: WebSocket) -> None:
        """Send any cached pending-interaction events to a freshly connected socket."""
        cached = self._pending.get(run_id, {})
        for event_name, payload in list(cached.items()):
            try:
                await ws.send_text(json.dumps({"event": event_name, "data": payload}))
            except Exception:
                pass

    async def broadcast_input_request(self, run_id: str, payload: dict) -> None:
        """Ask the dashboard user to respond to an interactive prompt.

        Payload shape:
            {
              "prompt_id": str,       # unique id; echo back on submit
              "prompt":    str,       # full prompt text (may be multi-line)
              "title":     str,       # short header for the modal
              "type":      "text" | "choice" | "confirm" | "enter",
              "choices":   list[{"label": str, "value": str}]   # for "choice"
            }
        """
        self._pending[run_id]["input_request"] = payload
        await self.broadcast(run_id, "input_request", payload)

    async def broadcast_input_result(self, run_id: str, payload: dict) -> None:
        """Confirm to the dashboard that the input submission was received.

        Payload shape: {"prompt_id": str}.
        """
        cached = self._pending.get(run_id, {}).get("input_request") or {}
        if cached.get("prompt_id") == payload.get("prompt_id"):
            self._pending[run_id].pop("input_request", None)
        await self.broadcast(run_id, "input_result", payload)


# Singleton used by routes and runner_bridge
ws_manager = WSManager()
