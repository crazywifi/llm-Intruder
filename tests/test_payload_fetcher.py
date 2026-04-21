"""Tests for llm_intruder.payloads.fetcher (Phase 13)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from llm_intruder.payloads.fetcher import (
    _strip_html,
    catalogue_to_payloads_yaml,
    load_catalogue,
)

CATALOGUE_DIR = Path(__file__).parent.parent / "llm_intruder" / "payloads" / "catalogue"


# ── load_catalogue ─────────────────────────────────────────────────────────────

def test_load_catalogue_returns_list():
    payloads = load_catalogue()
    assert isinstance(payloads, list)
    assert len(payloads) > 0


def test_load_catalogue_payload_structure():
    payloads = load_catalogue()
    for p in payloads[:10]:
        assert "id" in p
        assert "text" in p
        assert "category" in p
        assert "tags" in p
        assert isinstance(p["text"], str)
        assert len(p["text"]) > 0


def test_load_catalogue_filter_by_category():
    payloads = load_catalogue(categories=["direct_injection"])
    assert all(p["category"] == "direct_injection" for p in payloads)
    assert len(payloads) > 0


def test_load_catalogue_filter_multiple_categories():
    payloads = load_catalogue(categories=["direct_injection", "roleplay_jailbreak"])
    cats = {p["category"] for p in payloads}
    assert cats <= {"direct_injection", "roleplay_jailbreak"}


def test_load_catalogue_unknown_category_returns_empty():
    payloads = load_catalogue(categories=["nonexistent_category_xyz"])
    assert payloads == []


def test_load_catalogue_all_have_source():
    payloads = load_catalogue()
    for p in payloads:
        assert p.get("source") == "catalogue"


def test_load_catalogue_ids_unique():
    payloads = load_catalogue()
    ids = [p["id"] for p in payloads]
    assert len(ids) == len(set(ids)), "Payload IDs should be unique across catalogue"


def test_load_catalogue_financial_domain():
    payloads = load_catalogue(categories=["financial_domain"])
    assert len(payloads) >= 10


def test_load_catalogue_medical_domain():
    payloads = load_catalogue(categories=["medical_domain"])
    assert len(payloads) >= 8


def test_load_catalogue_enterprise_domain():
    payloads = load_catalogue(categories=["enterprise_domain"])
    assert len(payloads) >= 10


def test_load_catalogue_custom_dir(tmp_path):
    """load_catalogue works with a custom directory."""
    cat_file = tmp_path / "test_cat.yaml"
    cat_file.write_text(
        "category: test_cat\npayloads:\n  - id: t001\n    text: hello world test\n    tags: []\n",
        encoding="utf-8",
    )
    payloads = load_catalogue(catalogue_dir=tmp_path)
    assert len(payloads) == 1
    assert payloads[0]["id"] == "t001"


def test_load_catalogue_skips_invalid_yaml(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: valid: yaml: content: :", encoding="utf-8")
    # Should not raise; just skip files without 'payloads' key
    payloads = load_catalogue(catalogue_dir=tmp_path)
    assert payloads == []


# ── catalogue_to_payloads_yaml ────────────────────────────────────────────────

def test_catalogue_to_payloads_yaml_writes_file():
    payloads = load_catalogue(categories=["direct_injection"])
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "payloads.yaml"
        result = catalogue_to_payloads_yaml(payloads, out)
        assert result == out
        assert out.exists()


def test_catalogue_to_payloads_yaml_structure():
    payloads = load_catalogue(categories=["direct_injection"])
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "payloads.yaml"
        catalogue_to_payloads_yaml(payloads, out)
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert "payloads" in data
        for p in data["payloads"]:
            assert "id" in p
            assert "text" in p
            assert "category" in p


def test_catalogue_to_payloads_yaml_max_per_category():
    payloads = load_catalogue()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "payloads.yaml"
        catalogue_to_payloads_yaml(payloads, out, max_per_category=3)
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        from collections import Counter
        counts = Counter(p["category"] for p in data["payloads"])
        for cat, cnt in counts.items():
            assert cnt <= 3, f"Category {cat!r} has {cnt} payloads, expected <= 3"


def test_catalogue_to_payloads_yaml_creates_parent_dir():
    payloads = load_catalogue(categories=["direct_injection"])[:2]
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "nested" / "payloads.yaml"
        catalogue_to_payloads_yaml(payloads, out)
        assert out.exists()


# ── _strip_html ───────────────────────────────────────────────────────────────

def test_strip_html_removes_tags():
    assert _strip_html("<b>Hello</b> <i>World</i>") == "Hello World"


def test_strip_html_decodes_entities():
    # &nbsp; becomes a space; trailing whitespace stripped by .strip()
    result = _strip_html("&amp; &lt; &gt; &quot; &#39;")
    assert "&" in result
    assert "<" in result
    assert ">" in result
    assert '"' in result
    assert "'" in result


def test_strip_html_collapses_whitespace():
    assert _strip_html("  foo   bar  ") == "foo bar"


def test_strip_html_empty():
    assert _strip_html("") == ""


def test_strip_html_nested_tags():
    assert _strip_html("<div><p>text</p></div>") == "text"
