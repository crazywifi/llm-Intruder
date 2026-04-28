"""N-worker async session pool for concurrent payload delivery.

Each worker holds its own client (AsyncApiClient or DryRunAsyncClient)
so connections are isolated. A shared asyncio.Queue distributes work.
Workers run until the queue is drained (one sentinel per worker).

Usage::

    import asyncio
    from llm_intruder.resilience import SessionPool, SessionPoolConfig

    async def main():
        async with SessionPool(
            adapter=api_cfg,
            config=SessionPoolConfig(pool_size=4),
            evidence_dir="./evidence",
            dry_run=True,
        ) as pool:
            summary = await pool.run_all(payloads, engagement_id="eng-001")
        print(summary.success_rate)

    asyncio.run(main())
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from llm_intruder.resilience.async_client import AsyncApiClient, DryRunAsyncClient
from llm_intruder.resilience.evidence import EvidenceCapture
from llm_intruder.resilience.models import (
    EvidenceRecord,
    PoolSummary,
    SessionPoolConfig,
    SessionSlot,
    WorkerResult,
)

if TYPE_CHECKING:
    from llm_intruder.api.models import ApiAdapterConfig

log = structlog.get_logger()


class SessionPool:
    """Async N-worker pool for concurrent payload delivery.

    Parameters
    ----------
    adapter:
        API adapter configuration. Required unless *dry_run* is True.
    config:
        :class:`~llm_intruder.resilience.models.SessionPoolConfig`.
    evidence_dir:
        Directory to write evidence files. ``None`` disables file capture.
    variables:
        ``${VAR}`` substitution table forwarded to each worker's client.
    dry_run:
        If True, workers use :class:`~llm_intruder.resilience.async_client.DryRunAsyncClient`
        instead of :class:`~llm_intruder.resilience.async_client.AsyncApiClient`.
        Useful for testing the pool machinery without a live target.
    dry_run_delay:
        Per-request simulated latency for dry-run workers (seconds).
    """

    def __init__(
        self,
        adapter: "ApiAdapterConfig | None" = None,
        config: SessionPoolConfig | None = None,
        evidence_dir: str | Path | None = None,
        variables: dict[str, str] | None = None,
        dry_run: bool = False,
        dry_run_delay: float = 0.001,
    ) -> None:
        if not dry_run and adapter is None:
            raise ValueError("adapter is required when dry_run=False")
        self.adapter = adapter
        self.config = config or SessionPoolConfig()
        self.evidence_dir = Path(evidence_dir) if evidence_dir else None
        self.variables = variables or {}
        self.dry_run = dry_run
        self._dry_run_delay = dry_run_delay
        self._slots: list[SessionSlot] = []
        self._results: list[WorkerResult] = []
        # Token-bucket rate limiter: shared asyncio.Lock + timestamp tracking
        self._rate_lock: asyncio.Lock | None = None
        self._last_send_at: float = 0.0

    # ── Async context manager ─────────────────────────────────────────────────

    async def __aenter__(self) -> "SessionPool":
        self._slots = [
            SessionSlot(slot_id=i) for i in range(self.config.pool_size)
        ]
        self._results = []
        if self.config.requests_per_second is not None:
            self._rate_lock = asyncio.Lock()
            self._last_send_at = 0.0
        log.info(
            "session_pool_open",
            pool_size=self.config.pool_size,
            dry_run=self.dry_run,
            requests_per_second=self.config.requests_per_second,
        )
        return self

    async def __aexit__(self, *_args) -> None:
        for slot in self._slots:
            slot.status = "closed"
        log.info("session_pool_closed", pool_size=self.config.pool_size)

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run_all(
        self,
        payloads: list[str],
        engagement_id: str = "unknown",
    ) -> PoolSummary:
        """Process all *payloads* concurrently across N workers.

        Parameters
        ----------
        payloads:
            List of payload strings to deliver.
        engagement_id:
            Written to the :class:`~llm_intruder.resilience.models.PoolSummary`.

        Returns
        -------
        PoolSummary
        """
        # Build a bounded queue and fill it with (trial_id, payload) pairs
        queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue(
            maxsize=max(self.config.max_queue_size, len(payloads) + self.config.pool_size)
        )

        for payload in payloads:
            trial_id = str(uuid.uuid4())
            await queue.put((trial_id, payload))

        # One sentinel per worker signals end-of-work
        for _ in self._slots:
            await queue.put(None)

        workers = [
            asyncio.create_task(
                self._worker(slot, queue),
                name=f"pool-worker-{slot.slot_id}",
            )
            for slot in self._slots
        ]

        await asyncio.gather(*workers, return_exceptions=False)

        return self._build_summary(engagement_id)

    # ── Worker coroutine ──────────────────────────────────────────────────────

    async def _worker(
        self,
        slot: SessionSlot,
        queue: asyncio.Queue,
    ) -> None:
        """Consume items from the queue until a sentinel is received."""
        client = self._make_client(slot.slot_id)
        evidence_cap = (
            EvidenceCapture(self.evidence_dir, slot_id=slot.slot_id)
            if self.evidence_dir
            else None
        )

        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break

            trial_id, payload = item
            slot.status = "busy"
            await self._rate_gate()
            t0 = time.monotonic()
            ev_records: list[EvidenceRecord] = []

            try:
                response_text, _ = await client.send(payload)
                latency_ms = (time.monotonic() - t0) * 1000.0
                retries = getattr(client, "last_retry_count", 0)

                if evidence_cap:
                    rec = evidence_cap.capture_response(
                        trial_id, payload, response_text, latency_ms
                    )
                    ev_records.append(rec)

                slot.requests_sent += 1
                slot.last_used = datetime.now(timezone.utc)

                result = WorkerResult(
                    slot_id=slot.slot_id,
                    trial_id=trial_id,
                    payload=payload,
                    response_text=response_text,
                    success=True,
                    retries=retries,
                    latency_ms=round(latency_ms, 2),
                    evidence=ev_records,
                )
                log.info(
                    "pool_trial_success",
                    slot=slot.slot_id,
                    trial_id=trial_id[:8],
                    latency_ms=round(latency_ms, 1),
                )

            except Exception as exc:
                latency_ms = (time.monotonic() - t0) * 1000.0
                slot.errors += 1

                if evidence_cap:
                    err_rec = evidence_cap.capture_error(trial_id, exc, payload)
                    ev_records.append(err_rec)

                result = WorkerResult(
                    slot_id=slot.slot_id,
                    trial_id=trial_id,
                    payload=payload,
                    response_text="",
                    success=False,
                    latency_ms=round(latency_ms, 2),
                    error_message=str(exc),
                    evidence=ev_records,
                )
                log.warning(
                    "pool_trial_error",
                    slot=slot.slot_id,
                    trial_id=trial_id[:8],
                    error=str(exc)[:120],
                )

            self._results.append(result)
            slot.status = "idle"
            queue.task_done()

    # ── Rate limiting ─────────────────────────────────────────────────────────

    async def _rate_gate(self) -> None:
        """Block until sending the next request would not exceed requests_per_second.

        Uses a shared asyncio.Lock so only one worker can update the token
        timestamp at a time — preventing burst storms where all N workers
        simultaneously pass the check before any of them has incremented it.
        """
        if self._rate_lock is None or self.config.requests_per_second is None:
            return
        min_interval = 1.0 / self.config.requests_per_second
        async with self._rate_lock:
            now = time.monotonic()
            wait = min_interval - (now - self._last_send_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_send_at = time.monotonic()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_client(self, slot_id: int) -> AsyncApiClient | DryRunAsyncClient:
        if self.dry_run:
            return DryRunAsyncClient(delay_seconds=self._dry_run_delay)
        return AsyncApiClient(
            adapter=self.adapter,
            variables=self.variables,
            retry_config=self.config.retry,
        )

    def _build_summary(self, engagement_id: str) -> PoolSummary:
        total = len(self._results)
        succeeded = sum(1 for r in self._results if r.success)
        failed = total - succeeded
        retried = sum(r.retries for r in self._results)
        latencies = [r.latency_ms for r in self._results if r.latency_ms > 0]
        avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        max_lat = round(max(latencies), 2) if latencies else 0.0

        return PoolSummary(
            engagement_id=engagement_id,
            total_sent=total,
            succeeded=succeeded,
            failed=failed,
            retried=retried,
            avg_latency_ms=avg_lat,
            max_latency_ms=max_lat,
            pool_size=self.config.pool_size,
            evidence_dir=str(self.evidence_dir or ""),
            worker_results=self._results,
        )
