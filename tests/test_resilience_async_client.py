"""Tests for llm_intruder.resilience.async_client."""
from __future__ import annotations

import asyncio

import pytest

from llm_intruder.resilience.async_client import DryRunAsyncClient


# ── DryRunAsyncClient ──────────────────────────────────────────────────────────

class TestDryRunAsyncClient:
    def test_returns_dry_run_string(self):
        client = DryRunAsyncClient()
        text, streamed = asyncio.run(client.send("hello"))
        assert "[DRY RUN]" in text
        assert streamed is False

    def test_payload_length_in_response(self):
        client = DryRunAsyncClient()
        payload = "x" * 50
        text, _ = asyncio.run(client.send(payload))
        assert "payload_len=50" in text

    def test_empty_payload(self):
        client = DryRunAsyncClient()
        text, _ = asyncio.run(client.send(""))
        assert "payload_len=0" in text

    def test_send_count_increments(self):
        client = DryRunAsyncClient()
        asyncio.run(client.send("a"))
        asyncio.run(client.send("b"))
        assert client._send_count == 2

    def test_fail_after_raises(self):
        client = DryRunAsyncClient(fail_after=2)
        asyncio.run(client.send("1"))
        asyncio.run(client.send("2"))
        with pytest.raises(RuntimeError, match="simulated failure"):
            asyncio.run(client.send("3"))

    def test_fail_after_none_never_fails(self):
        client = DryRunAsyncClient(fail_after=None)
        for i in range(20):
            asyncio.run(client.send(f"payload-{i}"))
        assert client._send_count == 20

    def test_delay_parameter_accepted(self):
        # Just verify construction + one send with a tiny delay
        client = DryRunAsyncClient(delay_seconds=0.0)
        text, _ = asyncio.run(client.send("fast"))
        assert "[DRY RUN]" in text

    def test_return_type(self):
        client = DryRunAsyncClient()
        result = asyncio.run(client.send("test"))
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)
        assert isinstance(result[1], bool)

    def test_concurrent_sends(self):
        """Multiple coroutines sharing a client should not race on _send_count."""
        client = DryRunAsyncClient(delay_seconds=0.001)

        async def _run_many():
            coros = [client.send(f"p{i}") for i in range(10)]
            return await asyncio.gather(*coros)

        results = asyncio.run(_run_many())
        assert len(results) == 10
        assert all("[DRY RUN]" in r[0] for r in results)

    def test_fail_after_zero_fails_immediately(self):
        client = DryRunAsyncClient(fail_after=0)
        # First send: _send_count becomes 1, which is > 0 → raises
        with pytest.raises(RuntimeError):
            asyncio.run(client.send("trigger"))
