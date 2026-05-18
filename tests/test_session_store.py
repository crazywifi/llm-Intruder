"""Tests for the template store (save / load / list)."""
from __future__ import annotations

from pathlib import Path

import pytest

from llm_intruder.exceptions import ConfigurationError
from llm_intruder.session.models import SessionTemplate
from llm_intruder.session.store import list_templates, load_template, save_template


def _make_template(name: str = "test", url: str = "https://example.internal") -> SessionTemplate:
    return SessionTemplate.model_validate({
        "session_template": {
            "name": name,
            "recorded_at": "2026-04-01T10:00:00+00:00",
            "target_url": url,
        }
    })


# ── save / load round-trip ────────────────────────────────────────────────────

def test_save_and_load_round_trip(tmp_path: Path) -> None:
    tmpl = _make_template()
    out = tmp_path / "tmpl.yaml"
    save_template(tmpl, out)
    assert out.exists()
    loaded = load_template(out)
    assert loaded.session_template.name == "test"
    assert loaded.session_template.target_url == "https://example.internal"


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    tmpl = _make_template()
    out = tmp_path / "deep" / "nested" / "tmpl.yaml"
    save_template(tmpl, out)
    assert out.exists()


def test_load_missing_file_raises() -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_template("/nonexistent/path/session.yaml")


def test_load_invalid_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid: session: template: here")
    with pytest.raises(ConfigurationError):
        load_template(bad)


def test_save_and_load_with_actions(tmp_path: Path) -> None:
    tmpl = SessionTemplate.model_validate({
        "session_template": {
            "name": "with_actions",
            "recorded_at": "2026-04-01T10:00:00+00:00",
            "target_url": "https://example.internal",
            "actions": [
                {"type": "navigate", "url": "https://example.internal/login"},
                {"type": "fill", "selector": "input[name='email']", "value": "${USERNAME}"},
            ],
            "logout_detection": {
                "triggers": [{"type": "http_status", "codes": [401, 403]}]
            },
        }
    })
    out = tmp_path / "with_actions.yaml"
    save_template(tmpl, out)
    loaded = load_template(out)
    assert len(loaded.session_template.actions) == 2
    assert len(loaded.session_template.logout_detection.triggers) == 1


# ── list_templates ────────────────────────────────────────────────────────────

def test_list_templates_finds_valid(tmp_path: Path) -> None:
    tmpl = _make_template()
    save_template(tmpl, tmp_path / "a.yaml")
    save_template(tmpl, tmp_path / "b.yaml")
    found = list_templates(tmp_path)
    assert len(found) == 2


def test_list_templates_ignores_non_session_yaml(tmp_path: Path) -> None:
    (tmp_path / "engagement.yaml").write_text(
        "engagement_id: ENG-001\nauthor: test\n"
    )
    found = list_templates(tmp_path)
    assert found == []


def test_list_templates_empty_dir(tmp_path: Path) -> None:
    assert list_templates(tmp_path) == []


def test_list_templates_nested(tmp_path: Path) -> None:
    sub = tmp_path / "sessions"
    sub.mkdir()
    save_template(_make_template("nested"), sub / "nested.yaml")
    found = list_templates(tmp_path)
    assert len(found) == 1


def test_load_example_template() -> None:
    """The bundled example must load without error."""
    example = Path(__file__).parent.parent / "examples" / "session_template.yaml"
    if example.exists():
        tmpl = load_template(example)
        assert tmpl.session_template.target_url
