"""Evidence capture — saves probe artefacts to disk for post-engagement review.

Every live probe writes a JSON evidence file containing:
  - SHA-256 hash of the payload (never the raw text — audit ground rule)
  - SHA-256 hash of the response
  - The response text (for finding review)
  - Timing information

On error, a separate error evidence file is written with traceback details.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from llm_intruder.resilience.models import EvidenceRecord


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ts_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class EvidenceCapture:
    """Write evidence artefacts to ``output_dir`` for one pool slot.

    Parameters
    ----------
    output_dir:
        Directory to write evidence JSON files. Created if absent.
    slot_id:
        Worker slot identifier written to each record.
    """

    def __init__(
        self,
        output_dir: str | Path,
        slot_id: int | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.slot_id = slot_id

    # ── Capture methods ───────────────────────────────────────────────────────

    def capture_response(
        self,
        trial_id: str,
        payload: str,
        response_text: str,
        latency_ms: float | None = None,
    ) -> EvidenceRecord:
        """Save payload hash + full response to a JSON file.

        The payload itself is never stored — only its SHA-256 hash.
        """
        data = {
            "trial_id": trial_id,
            "slot_id": self.slot_id,
            "event": "response",
            "payload_hash": _sha256(payload),
            "payload_length": len(payload),
            "response_hash": _sha256(response_text),
            "response_text": response_text,
            "latency_ms": latency_ms,
            "captured_at": _now_iso(),
        }
        fname = f"{_safe_id(trial_id)}_response_{_ts_compact()}.json"
        path = self.output_dir / fname
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

        return EvidenceRecord(
            trial_id=trial_id,
            slot_id=self.slot_id,
            event="response",
            content=response_text[:300],
            file_path=str(path),
            latency_ms=latency_ms,
        )

    def capture_error(
        self,
        trial_id: str,
        error: Exception | str,
        payload: str = "",
    ) -> EvidenceRecord:
        """Save error details to a JSON file."""
        error_text = str(error)
        data = {
            "trial_id": trial_id,
            "slot_id": self.slot_id,
            "event": "error",
            "error": error_text,
            "payload_hash": _sha256(payload) if payload else None,
            "captured_at": _now_iso(),
        }
        fname = f"{_safe_id(trial_id)}_error_{_ts_compact()}.json"
        path = self.output_dir / fname
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

        return EvidenceRecord(
            trial_id=trial_id,
            slot_id=self.slot_id,
            event="error",
            content=error_text[:500],
            file_path=str(path),
        )

    def capture_retry(
        self,
        trial_id: str,
        attempt: int,
        wait_seconds: float,
        reason: str,
    ) -> EvidenceRecord:
        """Record a retry event (in-memory only — not written to disk).

        Retry events are lightweight audit markers stored in the
        ``WorkerResult.evidence`` list so the pool summary can report
        retry counts per trial without cluttering the evidence directory.
        """
        content = f"attempt={attempt} wait={wait_seconds:.3f}s reason={reason}"
        return EvidenceRecord(
            trial_id=trial_id,
            slot_id=self.slot_id,
            event="retry",
            content=content,
            file_path=None,
        )

    def list_files(self) -> list[Path]:
        """Return all evidence files written to ``output_dir``."""
        return sorted(self.output_dir.glob("*.json"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_id(trial_id: str) -> str:
    """Return the first 8 chars of the trial_id, safe for filenames."""
    return trial_id.replace("-", "")[:8]
