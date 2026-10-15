"""Batched CLI transport: many inputs, one `siphon scan-dir` process.

The scanner is never run; `asyncio.create_subprocess_exec` is replaced by a
fake that reads the batch directory the client wrote and answers in
`scan-dir --format json` shape.
"""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock

import pytest

from evadex.adapters.siphon_cli import client as client_module
from evadex.adapters.siphon_cli.adapter import SiphonCliAdapter, _Batcher
from evadex.adapters.siphon_cli.client import (
    SiphonCliClient,
    SiphonCliError,
    SiphonCliNoResult,
    _parse_dir_results,
)
from evadex.core.registry import get_adapter
from evadex.core.result import Payload, PayloadCategory, Variant

CARD = "4532015112830366"


# ── command and parsing ─────────────────────────────────────────────────────


def test_scan_dir_command_carries_the_common_flags():
    c = SiphonCliClient(executable="siphon", require_context=True, min_confidence=0.5)
    cmd = c.build_scan_dir_command("/tmp/x")
    assert cmd[:2] == ["siphon", "scan-dir"]
    assert "--require-context" in cmd
    assert cmd[cmd.index("--min-confidence") + 1] == "0.5"
    assert cmd[-1] == "/tmp/x"


def test_parse_dir_results_keys_by_file_stem():
    out = _parse_dir_results(
        json.dumps(
            [
                {
                    "file_path": "C:\\tmp\\b\\000000.txt",
                    "matches": [{"category": "x"}],
                    "error": None,
                },
                {
                    "file_path": "/tmp/b/000001.docx",
                    "matches": [],
                    "error": "unreadable",
                },
                {"not": "a file object"},
            ]
        )
    )
    assert out["000000"] == ([{"category": "x"}], None)
    assert out["000001"] == ([], "unreadable")
    assert len(out) == 2


def test_parse_dir_results_rejects_non_list():
    with pytest.raises(SiphonCliError):
        _parse_dir_results('{"a": 1}')


# ── scan_batch against a fake scanner process ───────────────────────────────


class _FakeProc:
    def __init__(self, stdout: bytes, rc: int = 0):
        self._stdout, self.returncode = stdout, rc

    async def communicate(self):
        return self._stdout, b""

    def kill(self):
        pass

    async def wait(self):
        return self.returncode


@pytest.fixture
def fake_scan_dir(monkeypatch):
    """Replace the subprocess with one that scans the batch directory itself."""
    seen = {"dirs": [], "cmds": [], "names": []}

    async def fake_exec(*cmd, **kwargs):
        d = cmd[-1]
        seen["dirs"].append(d)
        seen["cmds"].append(list(cmd))
        objs = []
        for name in sorted(os.listdir(d)):
            seen["names"].append(name)
            with open(os.path.join(d, name), "rb") as f:
                text = f.read().decode("utf-8", "replace")
            path = os.path.join(d, name)
            if "BOOM" in text:
                objs.append({"file_path": path, "matches": [], "error": "boom"})
            elif "VANISH" in text:
                continue  # scanner reports nothing for this file
            else:
                hit = [{"category": "Credit Card Numbers", "confidence": 0.9}]
                objs.append(
                    {
                        "file_path": path,
                        "matches": hit if CARD in text else [],
                        "error": None,
                    }
                )
        return _FakeProc(json.dumps(objs).encode())

    monkeypatch.setattr(client_module.asyncio, "create_subprocess_exec", fake_exec)
    return seen


async def test_scan_texts_maps_results_back_in_input_order(fake_scan_dir):
    c = SiphonCliClient(executable="siphon")
    res = await c.scan_texts([f"card {CARD}", "nothing here", f"{CARD} again"])
    assert [len(r) for r in res] == [1, 0, 1]
    assert len(fake_scan_dir["cmds"]) == 1
    assert fake_scan_dir["cmds"][0][1] == "scan-dir"
    assert fake_scan_dir["names"] == ["000000.txt", "000001.txt", "000002.txt"]


async def test_scan_batch_writes_each_suffix(fake_scan_dir):
    c = SiphonCliClient(executable="siphon")
    res = await c.scan_batch([(b"x", ".docx"), (CARD.encode(), ".pdf"), (b"y", ".txt")])
    assert fake_scan_dir["names"] == ["000000.docx", "000001.pdf", "000002.txt"]
    assert [len(r) for r in res] == [0, 1, 0]


async def test_scan_batch_per_input_errors_do_not_poison_the_batch(fake_scan_dir):
    c = SiphonCliClient(executable="siphon")
    res = await c.scan_texts([f"card {CARD}", "BOOM", "VANISH", "fine"])
    assert len(res[0]) == 1
    assert isinstance(res[1], SiphonCliError) and "boom" in str(res[1])
    assert isinstance(res[2], SiphonCliNoResult)
    assert res[3] == []


async def test_scan_batch_cleans_up_the_temp_dir(fake_scan_dir):
    c = SiphonCliClient(executable="siphon")
    await c.scan_texts(["a", "b"])
    assert not os.path.exists(fake_scan_dir["dirs"][0])


async def test_scan_batch_empty_input_spawns_nothing(fake_scan_dir):
    assert await SiphonCliClient(executable="siphon").scan_batch([]) == []
    assert fake_scan_dir["cmds"] == []


async def test_scan_batch_nonzero_exit_raises(monkeypatch):
    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(b"", rc=3)

    monkeypatch.setattr(client_module.asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(SiphonCliError, match="exited 3"):
        await SiphonCliClient(executable="siphon").scan_texts(["x"])


# ── the batcher ─────────────────────────────────────────────────────────────


class _RecordingClient:
    """Answers each item with its own text as the category; knobs force failures."""

    def __init__(self, fail_text=None, vanish_text=None, raise_all=False):
        self.batches: list[list[str]] = []
        self.fail_text, self.vanish_text, self.raise_all = (
            fail_text,
            vanish_text,
            raise_all,
        )
        self.scan_file_bytes = AsyncMock(return_value=[{"category": "fallback"}])

    async def scan_batch(self, items):
        texts = [data.decode("utf-8") for data, _ in items]
        self.batches.append(texts)
        if self.raise_all:
            raise SiphonCliError("process died")
        out = []
        for t in texts:
            if t == self.fail_text:
                out.append(SiphonCliError("bad input"))
            elif t == self.vanish_text:
                out.append(SiphonCliNoResult("nothing"))
            else:
                out.append([{"category": t}])
        return out


async def test_batcher_flushes_on_size_then_on_timer():
    client = _RecordingClient()
    b = _Batcher(client, max_size=4, max_wait=0.02)
    results = await asyncio.gather(*(b.scan_text(f"t{i}") for i in range(10)))
    assert [len(x) for x in client.batches] == [4, 4, 2]
    assert results[7] == [{"category": "t7"}]
    assert results[9] == [{"category": "t9"}]


async def test_batcher_lone_call_returns_after_max_wait():
    client = _RecordingClient()
    b = _Batcher(client, max_size=64, max_wait=0.01)
    assert await b.scan_text("solo") == [{"category": "solo"}]
    assert client.batches == [["solo"]]


async def test_batcher_mixes_text_and_file_items_in_one_batch():
    client = _RecordingClient()
    b = _Batcher(client, max_size=2, max_wait=1.0)
    text, doc = await asyncio.gather(b.scan_text("t"), b.scan_bytes(b"d", ".docx"))
    assert client.batches == [["t", "d"]]
    assert text == [{"category": "t"}] and doc == [{"category": "d"}]


async def test_batcher_per_item_error_reaches_only_that_caller():
    b = _Batcher(_RecordingClient(fail_text="t1"), max_size=3, max_wait=1.0)
    results = await asyncio.gather(
        b.scan_text("t0"), b.scan_text("t1"), b.scan_text("t2"), return_exceptions=True
    )
    assert results[0] == [{"category": "t0"}]
    assert isinstance(results[1], SiphonCliError)
    assert results[2] == [{"category": "t2"}]


async def test_batcher_no_result_falls_back_to_single_file_scan():
    client = _RecordingClient(vanish_text="odd")
    b = _Batcher(client, max_size=2, max_wait=1.0)
    ok, odd = await asyncio.gather(b.scan_text("ok"), b.scan_bytes(b"odd", ".xyz"))
    assert ok == [{"category": "ok"}]
    assert odd == [{"category": "fallback"}]
    client.scan_file_bytes.assert_awaited_once_with(b"odd", ".xyz")


async def test_batcher_process_failure_reaches_every_caller():
    b = _Batcher(_RecordingClient(raise_all=True), max_size=2, max_wait=1.0)
    results = await asyncio.gather(
        b.scan_text("a"), b.scan_text("b"), return_exceptions=True
    )
    assert all(isinstance(r, SiphonCliError) for r in results)


async def test_batcher_drain_flushes_pending_without_waiting_for_timer():
    client = _RecordingClient()
    b = _Batcher(client, max_size=64, max_wait=60.0)
    pending = asyncio.ensure_future(b.scan_text("late"))
    await asyncio.sleep(0)
    await b.drain()
    assert await pending == [{"category": "late"}]
    assert client.batches == [["late"]]


# ── through the adapter ─────────────────────────────────────────────────────


def _variant(value: str, strategy: str = "text") -> Variant:
    return Variant(value, "structural", "uppercase", "Uppercased", strategy)


PAYLOAD = Payload(CARD, PayloadCategory.CREDIT_CARD, "Visa")


async def test_adapter_batch_routes_text_submissions_through_one_process():
    adapter = get_adapter(
        "siphon-cli",
        {"executable": "siphon", "batch": True, "batch_size": 8, "batch_wait": 0.05},
    )
    assert isinstance(adapter, SiphonCliAdapter) and adapter._batcher is not None
    hit = [{"category": "Credit Card Numbers"}]
    adapter._client.scan_batch = AsyncMock(return_value=[[], hit, []])
    adapter._client.scan_text = AsyncMock(
        side_effect=AssertionError("per-text path used")
    )
    results = await asyncio.gather(
        *(adapter.submit(PAYLOAD, _variant(f"v{i}")) for i in range(3))
    )
    adapter._client.scan_batch.assert_awaited_once()
    assert [r.detected for r in results] == [False, True, False]
    await adapter.teardown()


async def test_adapter_batch_routes_file_strategies_through_the_same_process():
    adapter = get_adapter(
        "siphon-cli", {"executable": "siphon", "batch": True, "batch_size": 8}
    )
    adapter._client.scan_batch = AsyncMock(return_value=[[], []])
    adapter._client.scan_file_bytes = AsyncMock(
        side_effect=AssertionError("per-file path used")
    )
    await asyncio.gather(
        adapter.submit(PAYLOAD, _variant("v", "docx")),
        adapter.submit(PAYLOAD, _variant("v")),
    )
    items = adapter._client.scan_batch.call_args.args[0]
    assert sorted(suffix for _, suffix in items) == [".docx", ".txt"]
    assert all(isinstance(data, bytes) for data, _ in items)


async def test_adapter_without_batch_keeps_the_per_text_path():
    adapter = get_adapter("siphon-cli", {"executable": "siphon"})
    assert adapter._batcher is None
    adapter._client.scan_text = AsyncMock(return_value=[])
    await adapter.submit(PAYLOAD, _variant("v"))
    adapter._client.scan_text.assert_awaited_once()


async def test_adapter_auto_transport_installs_batcher_when_cli_is_chosen():
    adapter = get_adapter(
        "siphon-cli", {"executable": "siphon", "transport": "auto", "batch": True}
    )
    assert adapter._batcher is None
    adapter._http_client.health_check = AsyncMock(return_value=False)
    adapter._http_client.close = AsyncMock()
    await adapter.setup()
    assert adapter._transport == "cli" and adapter._batcher is not None
