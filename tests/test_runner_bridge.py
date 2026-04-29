from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from llm_intruder.dashboard.models import (
    EngagementProfile,
    RunMode,
    RunRequest,
)
from llm_intruder.dashboard.runner_bridge import (
    _RUNS,
    _RUNS_LOCK,
    _consume_skip_request,
    _ensure_engagement_id,
    _gen_engagement_yaml,
    _hydrate_resume_request,
    _should_abort_phase,
    _should_pause_run,
    _should_skip_phase,
    _should_stop_run,
)


def test_ensure_engagement_id_is_stable() -> None:
    eng = EngagementProfile()
    eid = _ensure_engagement_id(eng)
    assert eid
    assert eng.engagement_id == eid
    assert _ensure_engagement_id(eng) == eid


def test_gen_engagement_yaml_preserves_generated_id() -> None:
    eng = EngagementProfile()
    req = RunRequest(project_id="proj", run_mode=RunMode.scheduled, engagement=eng)
    with patch.object(Path, "write_text", return_value=0) as write_text:
        path = _gen_engagement_yaml(Path.cwd(), req.engagement, req.target)
    assert path.name == "engagement.yaml"
    assert req.engagement.engagement_id
    assert write_text.called


def test_hydrate_resume_request_uses_existing_meta_id() -> None:
    req = RunRequest(project_id="proj", run_mode=RunMode.scheduled)
    eid = _hydrate_resume_request(req, {"engagement_id": "ENG-RESUME-001"})
    assert eid == "ENG-RESUME-001"
    assert req.engagement.engagement_id == "ENG-RESUME-001"


def test_control_helpers_respect_skip_stop_pause_flags() -> None:
    run_id = "runner-bridge-test"
    with _RUNS_LOCK:
        _RUNS[run_id] = {
            "stop_requested": False,
            "skip_requested": True,
            "pause_requested": True,
        }

    try:
        assert not _should_stop_run(run_id)
        assert _should_skip_phase(run_id)
        assert _should_pause_run(run_id)
        assert _should_abort_phase(run_id)
        assert _consume_skip_request(run_id) is True
        assert _should_skip_phase(run_id) is False
        assert _consume_skip_request(run_id) is False
    finally:
        with _RUNS_LOCK:
            _RUNS.pop(run_id, None)
