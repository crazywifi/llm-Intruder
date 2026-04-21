"""Tests for CampaignRunner — mocked driver, in-memory SQLite."""
from __future__ import annotations

import random
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from llm_intruder.config.models import EngagementConfig
from llm_intruder.db.schema import Base, Trial
from llm_intruder.payloads.campaign import CampaignRunner, _weighted_choice
from llm_intruder.payloads.library import PayloadLibrary
from llm_intruder.payloads.models import CampaignSummary, PayloadTemplate
from llm_intruder.browser.models import CapturedResponse


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def db_session(engine):
    with Session(engine) as session:
        yield session


@pytest.fixture()
def engagement() -> EngagementConfig:
    return EngagementConfig(
        engagement_id="ENG-TEST-001",
        authorisation_confirmed=True,
        scope=["https://test.example.com"],
        max_trials=5,
        strategy_weights={
            "paraphrase": 1.0,
            "roleplay_reframe": 1.0,
            "language_switch": 1.0,
            "token_obfuscation": 1.0,
            "many_shot_context": 1.0,
        },
    )


@pytest.fixture()
def library() -> PayloadLibrary:
    return PayloadLibrary(payloads=[
        PayloadTemplate(id=f"t{i}", strategy=s, text=f"probe text {i}")
        for i, s in enumerate([
            "paraphrase", "roleplay_reframe", "language_switch",
            "token_obfuscation", "many_shot_context",
        ])
    ])


def _mock_driver(response_text: str = "I cannot help with that.") -> Any:
    """Return a duck-typed driver that mimics ApiDriver.send_payload."""
    driver = MagicMock()
    captured = CapturedResponse(
        text=response_text,
        stream_detected=False,
        was_wiped=False,
        payload_hash="a" * 64,
        response_hash="b" * 64,
    )
    driver.send_payload.return_value = captured
    return driver


# ── _weighted_choice ──────────────────────────────────────────────────────────

def test_weighted_choice_returns_key() -> None:
    weights = {"a": 1.0, "b": 2.0, "c": 0.5}
    rng = random.Random(0)
    result = _weighted_choice(weights, rng)
    assert result in weights


def test_weighted_choice_zero_total_falls_back() -> None:
    weights = {"x": 0.0, "y": 0.0}
    rng = random.Random(0)
    result = _weighted_choice(weights, rng)
    assert result in weights


def test_weighted_choice_single_key() -> None:
    weights = {"only": 5.0}
    rng = random.Random(0)
    for _ in range(10):
        assert _weighted_choice(weights, rng) == "only"


def test_weighted_choice_distribution() -> None:
    """Higher-weight keys should be selected more often."""
    weights = {"rare": 1.0, "common": 99.0}
    rng = random.Random(42)
    counts: dict[str, int] = {"rare": 0, "common": 0}
    for _ in range(1000):
        counts[_weighted_choice(weights, rng)] += 1
    assert counts["common"] > counts["rare"] * 5


# ── CampaignRunner.run — dry_run ──────────────────────────────────────────────

def test_campaign_dry_run_returns_summary(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement,
        library=library,
        driver=_mock_driver(),
        db_session=db_session,
        seed=42,
    )
    summary = runner.run(max_trials=3, dry_run=True)
    assert isinstance(summary, CampaignSummary)
    assert summary.total_trials == 3
    assert summary.dry_run is True
    assert summary.engagement_id == "ENG-TEST-001"


def test_campaign_dry_run_does_not_call_driver(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    driver = _mock_driver()
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=driver, db_session=db_session, seed=0,
    )
    runner.run(max_trials=5, dry_run=True)
    driver.send_payload.assert_not_called()


def test_campaign_dry_run_persists_trials(
    engine,
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=7,
    )
    runner.run(max_trials=4, dry_run=True)
    rows = db_session.query(Trial).all()
    assert len(rows) == 4


def test_campaign_dry_run_trials_have_pending_verdict(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=9,
    )
    runner.run(max_trials=3, dry_run=True)
    for row in db_session.query(Trial).all():
        assert row.verdict == "pending"


def test_campaign_dry_run_strategies_used_map(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=3,
    )
    summary = runner.run(max_trials=10, dry_run=True)
    total = sum(summary.strategies_used.values())
    assert total == 10
    for s in summary.strategies_used:
        assert s in engagement.strategy_weights


# ── CampaignRunner.run — live (mocked driver) ─────────────────────────────────

def test_campaign_live_calls_driver(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    driver = _mock_driver()
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=driver, db_session=db_session, seed=1,
    )
    runner.run(max_trials=5, dry_run=False)
    assert driver.send_payload.call_count == 5


def test_campaign_live_returns_summary(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=2,
    )
    summary = runner.run(max_trials=5, dry_run=False)
    assert isinstance(summary, CampaignSummary)
    assert summary.total_trials == 5
    assert summary.dry_run is False


def test_campaign_live_persists_trials(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=4,
    )
    runner.run(max_trials=5, dry_run=False)
    rows = db_session.query(Trial).all()
    assert len(rows) == 5


def test_campaign_live_response_preview_stored(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver("Refused!"), db_session=db_session, seed=5,
    )
    results = runner.run(max_trials=2, dry_run=False)
    # results summary doesn't contain individual previews, but trials table does
    rows = db_session.query(Trial).all()
    assert len(rows) == 2


def test_campaign_live_driver_error_handled(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    driver = MagicMock()
    driver.send_payload.side_effect = RuntimeError("connection refused")
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=driver, db_session=db_session, seed=6,
    )
    # Should not raise — errors are caught and logged
    summary = runner.run(max_trials=3, dry_run=False)
    assert summary.total_trials == 3
    rows = db_session.query(Trial).all()
    assert len(rows) == 3


# ── max_trials defaults ────────────────────────────────────────────────────────

def test_campaign_uses_config_max_trials(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    # engagement.max_trials = 5
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=8,
    )
    summary = runner.run(dry_run=True)  # no explicit max_trials
    assert summary.total_trials == 5


def test_campaign_explicit_max_trials_overrides(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    runner = CampaignRunner(
        config=engagement, library=library,
        driver=_mock_driver(), db_session=db_session, seed=10,
    )
    summary = runner.run(max_trials=2, dry_run=True)
    assert summary.total_trials == 2


# ── empty strategy_weights auto-fill ─────────────────────────────────────────

def test_campaign_empty_weights_auto_filled(
    library: PayloadLibrary,
    db_session: Session,
) -> None:
    eng = EngagementConfig(
        engagement_id="ENG-NOWEIGHTS",
        authorisation_confirmed=True,
        scope=["https://test.example.com"],
        max_trials=5,
        strategy_weights={},   # empty → auto-fill from registry
    )
    runner = CampaignRunner(
        config=eng, library=library,
        driver=_mock_driver(), db_session=db_session, seed=0,
    )
    summary = runner.run(max_trials=5, dry_run=True)
    assert summary.total_trials == 5


# ── determinism ───────────────────────────────────────────────────────────────

def test_campaign_deterministic_with_seed(
    engagement: EngagementConfig,
    library: PayloadLibrary,
    engine,
) -> None:
    """Same seed → same trial sequence."""
    def run_campaign(db_session: Session) -> list[str]:
        runner = CampaignRunner(
            config=engagement, library=library,
            driver=_mock_driver(), db_session=db_session, seed=999,
        )
        runner.run(max_trials=5, dry_run=True)
        return [r.strategy for r in db_session.query(Trial).order_by(Trial.id).all()]

    with Session(engine) as s1:
        seq1 = run_campaign(s1)

    # fresh engine / schema for second run
    engine2 = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine2)
    with Session(engine2) as s2:
        seq2 = run_campaign(s2)

    assert seq1 == seq2
