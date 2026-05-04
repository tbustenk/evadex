"""Tests for Engine streaming vs batch mode (v3.25.0)."""
from __future__ import annotations

import tracemalloc

import pytest

from evadex.core.engine import Engine
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant
from evadex.adapters.base import BaseAdapter


class _StubAdapter(BaseAdapter):
    """Adapter that immediately returns detected=True for every variant."""

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        return ScanResult(payload=payload, variant=variant, detected=True)


def _make_payloads(n: int = 3) -> list[Payload]:
    cards = [
        "4532015112830366",
        "5425233430109903",
        "374251018720955",
    ]
    return [
        Payload(cards[i % len(cards)], PayloadCategory.CREDIT_CARD, f"Card {i}")
        for i in range(n)
    ]


# ── Correctness: both modes produce identical results ─────────────────────────

def test_streaming_and_batch_same_result_count():
    payloads = _make_payloads(2)
    adapter = _StubAdapter({})

    streaming_engine = Engine(adapter=adapter, strategies=["text"], streaming=True)
    batch_engine     = Engine(adapter=adapter, strategies=["text"], streaming=False)

    r_stream = streaming_engine.run(payloads)
    r_batch  = batch_engine.run(payloads)

    assert len(r_stream) == len(r_batch)


def test_streaming_and_batch_same_keys():
    """Both modes must return the same (payload, technique, strategy) key set."""
    payloads = _make_payloads(2)
    adapter  = _StubAdapter({})

    def _key_set(results):
        return {
            (r.payload.value, r.variant.technique, r.variant.strategy)
            for r in results
        }

    streaming_engine = Engine(adapter=adapter, strategies=["text"], streaming=True)
    batch_engine     = Engine(adapter=adapter, strategies=["text"], streaming=False)

    keys_stream = _key_set(streaming_engine.run(payloads))
    keys_batch  = _key_set(batch_engine.run(payloads))

    assert keys_stream == keys_batch


def test_streaming_all_detected():
    payloads = _make_payloads(1)
    engine   = Engine(adapter=_StubAdapter({}), strategies=["text"], streaming=True)
    results  = engine.run(payloads)
    assert all(r.detected for r in results)


def test_batch_all_detected():
    payloads = _make_payloads(1)
    engine   = Engine(adapter=_StubAdapter({}), strategies=["text"], streaming=False)
    results  = engine.run(payloads)
    assert all(r.detected for r in results)


# ── on_result callback wired in both modes ────────────────────────────────────

def test_streaming_on_result_called():
    calls = []
    engine = Engine(
        adapter=_StubAdapter({}),
        strategies=["text"],
        streaming=True,
        on_result=lambda r, c, t: calls.append((c, t)),
    )
    engine.run(_make_payloads(1))
    assert len(calls) > 0


def test_batch_on_result_called():
    calls = []
    engine = Engine(
        adapter=_StubAdapter({}),
        strategies=["text"],
        streaming=False,
        on_result=lambda r, c, t: calls.append((c, t)),
    )
    engine.run(_make_payloads(1))
    assert len(calls) > 0


def test_batch_total_known_upfront():
    """In batch mode total is pre-computed; every callback should see the same total."""
    totals_seen = set()

    def _cb(r, completed, total):
        totals_seen.add(total)

    engine = Engine(
        adapter=_StubAdapter({}),
        strategies=["text"],
        streaming=False,
        on_result=_cb,
    )
    results = engine.run(_make_payloads(2))
    # total must be constant across all callbacks and equal the final result count
    assert len(totals_seen) == 1
    assert totals_seen.pop() == len(results)


# ── Memory: streaming peak ≤ batch peak ──────────────────────────────────────

def _measure_peak_kb(streaming: bool, n_payloads: int = 5) -> float:
    payloads = _make_payloads(n_payloads)
    adapter  = _StubAdapter({})
    engine   = Engine(adapter=adapter, strategies=["text"], streaming=streaming)

    tracemalloc.start()
    engine.run(payloads)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024


@pytest.mark.slow
def test_streaming_peak_memory_not_worse_than_batch():
    """Streaming mode must use no more peak memory than batch mode (or at most
    a very small delta due to measurement noise)."""
    peak_stream = _measure_peak_kb(streaming=True,  n_payloads=5)
    peak_batch  = _measure_peak_kb(streaming=False, n_payloads=5)
    # Allow 10% headroom for measurement noise
    assert peak_stream <= peak_batch * 1.10, (
        f"Streaming peak {peak_stream:.1f} KB > batch peak {peak_batch:.1f} KB"
    )


# ── Scan CLI --stream / --no-stream flag ──────────────────────────────────────

def test_scan_stream_flag_accepted():
    from click.testing import CliRunner
    from unittest.mock import patch, AsyncMock
    from evadex.cli.app import main
    from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter

    result_obj = ScanResult(
        payload=Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa"),
        variant=Variant("4532015112830366", "structural", "no_delimiter", "desc", strategy="text"),
        detected=True,
    )
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [result_obj]
        r = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text", "--stream",
        ])
    assert r.exit_code == 0, r.output


def test_scan_no_stream_flag_accepted():
    from click.testing import CliRunner
    from unittest.mock import patch, AsyncMock
    from evadex.cli.app import main
    from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter

    result_obj = ScanResult(
        payload=Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa"),
        variant=Variant("4532015112830366", "structural", "no_delimiter", "desc", strategy="text"),
        detected=True,
    )
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [result_obj]
        r = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text", "--no-stream",
        ])
    assert r.exit_code == 0, r.output


def test_scan_no_stream_passes_streaming_false_to_engine():
    from click.testing import CliRunner
    from unittest.mock import patch, AsyncMock
    from evadex.cli.app import main
    from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter

    result_obj = ScanResult(
        payload=Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa"),
        variant=Variant("4532015112830366", "structural", "no_delimiter", "desc", strategy="text"),
        detected=True,
    )
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [result_obj]
        runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text", "--no-stream",
        ])
        # Engine must have been constructed with streaming=False
        assert ME.call_args is not None
        assert ME.call_args.kwargs.get("streaming") is False
