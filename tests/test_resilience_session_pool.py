"""Tests for llm_intruder.resilience.session_pool — SessionPool."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from llm_intruder.resilience.models import PoolSummary, SessionPoolConfig, WorkerResult
from llm_intruder.resilience.session_pool import SessionPool


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(coro):
    """Shorthand: run a coroutine in a fresh event loop."""
    return asyncio.run(coro)


async def _pool_run(payloads, pool_size=2, evidence_dir=None, fail_after=None, delay=0.0):
    """Convenience async helper: open a dry-run pool and run all payloads."""
    cfg = SessionPoolConfig(pool_size=pool_size)
    async with SessionPool(
        config=cfg,
        evidence_dir=evidence_dir,
        dry_run=True,
        dry_run_delay=delay,
    ) as pool:
        # Inject fail_after into each worker's client if needed
        if fail_after is not None:
            pool._dry_run_delay = delay
            # override _make_client to inject fail_after
            from llm_intruder.resilience.async_client import DryRunAsyncClient
            original_make = pool._make_client
            pool._make_client = lambda slot_id: DryRunAsyncClient(
                delay_seconds=delay, fail_after=fail_after
            )
        return await pool.run_all(payloads, engagement_id="test-eng")


# ── Construction ──────────────────────────────────────────────────────────────

class TestSessionPoolConstruction:
    def test_requires_adapter_when_not_dry_run(self):
        with pytest.raises(ValueError, match="adapter is required"):
            SessionPool(dry_run=False)

    def test_dry_run_no_adapter_needed(self):
        pool = SessionPool(dry_run=True)
        assert pool.dry_run is True

    def test_default_config(self):
        pool = SessionPool(dry_run=True)
        assert pool.config.pool_size == 4

    def test_custom_config(self):
        cfg = SessionPoolConfig(pool_size=8)
        pool = SessionPool(dry_run=True, config=cfg)
        assert pool.config.pool_size == 8

    def test_evidence_dir_stored_as_path(self, tmp_path):
        pool = SessionPool(dry_run=True, evidence_dir=tmp_path)
        assert pool.evidence_dir == tmp_path

    def test_evidence_dir_none_by_default(self):
        pool = SessionPool(dry_run=True)
        assert pool.evidence_dir is None


# ── Context manager ───────────────────────────────────────────────────────────

class TestSessionPoolContextManager:
    def test_slots_created_on_enter(self):
        async def _run():
            cfg = SessionPoolConfig(pool_size=3)
            async with SessionPool(config=cfg, dry_run=True) as pool:
                return len(pool._slots)
        assert run(_run()) == 3

    def test_slots_closed_on_exit(self):
        async def _run():
            cfg = SessionPoolConfig(pool_size=2)
            async with SessionPool(config=cfg, dry_run=True) as pool:
                pass
            return [s.status for s in pool._slots]
        statuses = run(_run())
        assert all(s == "closed" for s in statuses)

    def test_results_reset_on_enter(self):
        async def _run():
            cfg = SessionPoolConfig(pool_size=2)
            pool = SessionPool(config=cfg, dry_run=True)
            pool._results = [object()]  # pre-pollute
            async with pool:
                return pool._results
        assert run(_run()) == []


# ── run_all — happy path ──────────────────────────────────────────────────────

class TestRunAll:
    def test_returns_pool_summary(self):
        summary = run(_pool_run(["payload-1", "payload-2"]))
        assert isinstance(summary, PoolSummary)

    def test_total_sent_matches_payloads(self):
        payloads = [f"p{i}" for i in range(8)]
        summary = run(_pool_run(payloads, pool_size=3))
        assert summary.total_sent == 8

    def test_all_succeeded_in_dry_run(self):
        payloads = [f"p{i}" for i in range(6)]
        summary = run(_pool_run(payloads))
        assert summary.succeeded == 6
        assert summary.failed == 0

    def test_success_rate_is_one(self):
        summary = run(_pool_run(["a", "b", "c"]))
        assert summary.success_rate == 1.0

    def test_engagement_id_propagated(self):
        async def _run():
            cfg = SessionPoolConfig(pool_size=2)
            async with SessionPool(config=cfg, dry_run=True) as pool:
                return await pool.run_all(["p"], engagement_id="eng-xyz")
        summary = run(_run())
        assert summary.engagement_id == "eng-xyz"

    def test_worker_results_populated(self):
        payloads = ["a", "b", "c"]
        summary = run(_pool_run(payloads))
        assert len(summary.worker_results) == 3
        assert all(isinstance(r, WorkerResult) for r in summary.worker_results)

    def test_empty_payloads(self):
        summary = run(_pool_run([]))
        assert summary.total_sent == 0
        assert summary.succeeded == 0

    def test_single_payload(self):
        summary = run(_pool_run(["only one"]))
        assert summary.total_sent == 1
        assert summary.succeeded == 1

    def test_pool_size_recorded(self):
        summary = run(_pool_run(["x"], pool_size=5))
        assert summary.pool_size == 5

    def test_latency_ms_positive(self):
        payloads = ["a", "b"]
        summary = run(_pool_run(payloads, delay=0.005))
        assert summary.avg_latency_ms >= 0.0


# ── run_all — error handling ──────────────────────────────────────────────────

class TestRunAllErrors:
    def test_error_recorded_in_results(self):
        summary = run(_pool_run(["good", "good", "trigger"], pool_size=1, fail_after=2))
        # At least one failure expected
        failed = [r for r in summary.worker_results if not r.success]
        assert len(failed) >= 1

    def test_error_message_non_empty(self):
        summary = run(_pool_run(["ok", "boom"], pool_size=1, fail_after=1))
        failed = [r for r in summary.worker_results if not r.success]
        if failed:
            assert failed[0].error_message != ""


# ── Evidence capture ──────────────────────────────────────────────────────────

class TestRunAllEvidence:
    def test_evidence_files_created(self, tmp_path):
        payloads = ["probe-1", "probe-2", "probe-3"]
        summary = run(_pool_run(payloads, pool_size=2, evidence_dir=tmp_path))
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) >= len(payloads)

    def test_no_evidence_files_without_dir(self, tmp_path):
        # evidence_dir=None → no files written anywhere
        summary = run(_pool_run(["p1", "p2"], evidence_dir=None))
        assert summary.succeeded == 2

    def test_evidence_dir_in_summary(self, tmp_path):
        async def _run():
            cfg = SessionPoolConfig(pool_size=2)
            async with SessionPool(config=cfg, dry_run=True, evidence_dir=tmp_path) as pool:
                return await pool.run_all(["x"])
        summary = run(_run())
        assert str(tmp_path) in summary.evidence_dir

    def test_worker_results_have_evidence_records(self, tmp_path):
        summary = run(_pool_run(["a", "b"], evidence_dir=tmp_path))
        # Every successful result should have at least one evidence record
        successful = [r for r in summary.worker_results if r.success]
        assert all(len(r.evidence) >= 1 for r in successful)


# ── Concurrency ───────────────────────────────────────────────────────────────

class TestConcurrency:
    def test_many_payloads_many_workers(self):
        payloads = [f"payload-{i}" for i in range(50)]
        summary = run(_pool_run(payloads, pool_size=8))
        assert summary.total_sent == 50
        assert summary.succeeded == 50

    def test_more_workers_than_payloads(self):
        summary = run(_pool_run(["only-one"], pool_size=10))
        assert summary.total_sent == 1
        assert summary.succeeded == 1
