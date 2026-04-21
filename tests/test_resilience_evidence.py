"""Tests for llm_intruder.resilience.evidence — EvidenceCapture."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from llm_intruder.resilience.evidence import EvidenceCapture
from llm_intruder.resilience.models import EvidenceRecord


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── EvidenceCapture.capture_response ──────────────────────────────────────────

class TestCaptureResponse:
    def test_creates_json_file(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_response("trial-001", "payload text", "response text")
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1

    def test_returns_evidence_record(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=1)
        rec = cap.capture_response("trial-002", "p", "r")
        assert isinstance(rec, EvidenceRecord)
        assert rec.event == "response"
        assert rec.trial_id == "trial-002"
        assert rec.slot_id == 1

    def test_payload_hash_not_raw_payload(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        payload = "secret payload content"
        cap.capture_response("t1", payload, "response")
        f = list(tmp_path.glob("*.json"))[0]
        data = json.loads(f.read_text())
        # Raw payload must NOT be stored
        assert payload not in json.dumps(data)
        # Hash must be stored
        assert data["payload_hash"] == _sha256(payload)

    def test_response_text_stored(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_response("t1", "p", "the response")
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        assert data["response_text"] == "the response"

    def test_response_hash_stored(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        response = "hello world"
        cap.capture_response("t1", "p", response)
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        assert data["response_hash"] == _sha256(response)

    def test_latency_ms_written(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_response("t1", "p", "r", latency_ms=42.5)
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        assert data["latency_ms"] == pytest.approx(42.5)

    def test_file_path_in_record(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        rec = cap.capture_response("t1", "p", "r")
        assert rec.file_path is not None
        assert Path(rec.file_path).exists()

    def test_content_truncated_to_300(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        long_response = "x" * 500
        rec = cap.capture_response("t1", "p", long_response)
        assert len(rec.content) <= 300

    def test_output_dir_created(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        cap = EvidenceCapture(nested, slot_id=0)
        cap.capture_response("t1", "p", "r")
        assert nested.exists()


# ── EvidenceCapture.capture_error ─────────────────────────────────────────────

class TestCaptureError:
    def test_creates_json_file(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_error("trial-err", ValueError("oops"))
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1

    def test_event_is_error(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        rec = cap.capture_error("trial-err", RuntimeError("boom"))
        assert rec.event == "error"

    def test_error_text_stored(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_error("t1", "Connection refused")
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        assert "Connection refused" in data["error"]

    def test_payload_hash_when_provided(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        payload = "probe text"
        cap.capture_error("t1", "err", payload=payload)
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        assert data["payload_hash"] == _sha256(payload)

    def test_payload_hash_none_when_empty(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_error("t1", "err", payload="")
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        # empty payload → None hash
        assert data["payload_hash"] is None

    def test_content_truncated_to_500(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        long_err = "e" * 600
        rec = cap.capture_error("t1", long_err)
        assert len(rec.content) <= 500


# ── EvidenceCapture.capture_retry ─────────────────────────────────────────────

class TestCaptureRetry:
    def test_no_file_written(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_retry("t1", attempt=1, wait_seconds=2.5, reason="429")
        assert list(tmp_path.glob("*.json")) == []

    def test_returns_evidence_record(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        rec = cap.capture_retry("t1", attempt=2, wait_seconds=4.0, reason="503")
        assert isinstance(rec, EvidenceRecord)
        assert rec.event == "retry"

    def test_content_includes_attempt_and_wait(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        rec = cap.capture_retry("t1", attempt=3, wait_seconds=8.0, reason="timeout")
        assert "attempt=3" in rec.content
        assert "8.000" in rec.content

    def test_file_path_is_none(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        rec = cap.capture_retry("t1", attempt=1, wait_seconds=1.0, reason="retry")
        assert rec.file_path is None


# ── EvidenceCapture.list_files ─────────────────────────────────────────────────

class TestListFiles:
    def test_empty_dir(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        assert cap.list_files() == []

    def test_returns_sorted_paths(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_response("t1", "p1", "r1")
        cap.capture_response("t2", "p2", "r2")
        cap.capture_error("t3", "err")
        files = cap.list_files()
        assert len(files) == 3
        assert files == sorted(files)

    def test_only_json_files(self, tmp_path):
        cap = EvidenceCapture(tmp_path, slot_id=0)
        cap.capture_response("t1", "p", "r")
        # Create a non-JSON file
        (tmp_path / "noise.txt").write_text("ignored")
        files = cap.list_files()
        assert all(f.suffix == ".json" for f in files)
