"""End-to-end tests for C2 integration across scan / falsepos / compare / history.

The DLP adapter is stubbed via a tiny BaseAdapter subclass so no scanner
needs to be running, and Siphon-C2 is mocked with respx so no network is hit.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from evadex.adapters.base import BaseAdapter
from evadex.cli.app import main
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, ScanResult, Variant
from evadex.reporters.c2_reporter import (
    PATH_COMPARE,
    PATH_FALSEPOS,
    PATH_HISTORY,
    PATH_SCAN,
)


C2 = "http://c2.test"
KEY = "c2-test-key"


@register_adapter("c2-stub")
class _C2StubAdapter(BaseAdapter):
    """Minimal adapter that flags everything — lets scan finish fast."""

    name = "c2-stub"

    async def health_check(self) -> bool:
        return True

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        return ScanResult(payload=payload, variant=variant, detected=True)


# ── scan -> C2 ────────────────────────────────────────────────────────────────

@respx.mock
def test_scan_pushes_to_c2(tmp_path):
    route = respx.post(f"{C2}{PATH_SCAN}").mock(return_value=httpx.Response(200))
    out = tmp_path / "scan.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--tool", "c2-stub", "--category", "credit_card",
        "--tier", "banking", "--scanner-label", "e2e",
        "--output", str(out),
        "--c2-url", C2, "--c2-key", KEY,
    ])
    # Scan must succeed and output must be written
    assert result.exit_code == 0, result.output
    assert out.exists()
    # C2 received one scan push
    assert route.call_count == 1
    body = json.loads(route.calls.last.request.content)
    assert body["type"] == "scan"
    assert body["tool"] == "c2-stub"
    assert body["scanner_label"] == "e2e"
    assert "pass_rate" in body
    # x-api-key was forwarded
    assert route.calls.last.request.headers["x-api-key"] == KEY


@respx.mock
def test_scan_c2_unreachable_does_not_fail_scan(tmp_path):
    """Graceful degradation: C2 errors must never bubble up to exit code."""
    respx.post(f"{C2}{PATH_SCAN}").mock(side_effect=httpx.ConnectError("refused"))
    out = tmp_path / "scan.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--tool", "c2-stub", "--category", "credit_card",
        "--output", str(out),
        "--c2-url", C2, "--c2-key", KEY,
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()
    # Warning must appear somewhere in stderr (Click captures combined output)
    combined = (result.output or "") + (result.stderr_bytes.decode("utf-8", errors="replace") if result.stderr_bytes else "")
    assert "C2 push failed" in combined or "warning" in combined.lower()


@respx.mock
def test_scan_without_c2_flags_does_not_hit_c2(tmp_path, monkeypatch):
    """When neither --c2-url nor EVADEX_C2_URL is set, no push happens."""
    monkeypatch.delenv("EVADEX_C2_URL", raising=False)
    monkeypatch.delenv("EVADEX_C2_KEY", raising=False)
    route = respx.post(f"{C2}{PATH_SCAN}").mock(return_value=httpx.Response(200))
    out = tmp_path / "scan.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--tool", "c2-stub", "--category", "credit_card",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert route.call_count == 0


# ── falsepos -> C2 ──────────────────────────────────────────────────────────

@respx.mock
def test_falsepos_pushes_to_c2(tmp_path):
    route = respx.post(f"{C2}{PATH_FALSEPOS}").mock(return_value=httpx.Response(200))
    runner = CliRunner()
    result = runner.invoke(main, [
        "falsepos", "--tool", "c2-stub",
        "--category", "credit_card", "--count", "3",
        "--format", "json",
        "--c2-url", C2, "--c2-key", KEY,
    ])
    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    body = json.loads(route.calls.last.request.content)
    assert body["type"] == "falsepos"
    assert "report" in body


# ── compare -> C2 ───────────────────────────────────────────────────────────

def _fake_scan_file(path: Path, label: str, pass_count: int = 5, fail_count: int = 0):
    data = {
        "meta": {
            "timestamp": "2026-04-17T00:00:00+00:00",
            "scanner": label,
            "total": pass_count + fail_count,
            "pass": pass_count, "fail": fail_count, "error": 0,
            "pass_rate": 100.0 * pass_count / max(1, pass_count + fail_count),
            "summary_by_category": {},
        },
        "results": [
            {
                "payload": {"value": f"V{i}", "category": "credit_card",
                            "category_type": "structured", "label": "cc"},
                "variant": {"value": f"V{i}", "generator": "structural",
                            "technique": "uppercase", "transform_name": "upper",
                            "strategy": "text"},
                "detected": i < pass_count,
                "severity": "pass" if i < pass_count else "fail",
                "duration_ms": 1.0, "error": None, "raw_response": {},
            }
            for i in range(pass_count + fail_count)
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")


@respx.mock
def test_compare_pushes_to_c2(tmp_path):
    route = respx.post(f"{C2}{PATH_COMPARE}").mock(return_value=httpx.Response(200))
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    _fake_scan_file(fa, "python", pass_count=5, fail_count=0)
    _fake_scan_file(fb, "rust", pass_count=3, fail_count=2)
    runner = CliRunner()
    result = runner.invoke(main, [
        "compare", str(fa), str(fb),
        "--c2-url", C2, "--c2-key", KEY,
    ])
    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    body = json.loads(route.calls.last.request.content)
    assert body["type"] == "compare"
    assert "overall" in body["comparison"]


# ── history --push-c2 ───────────────────────────────────────────────────────

@respx.mock
def test_history_push_c2_backfill(tmp_path):
    route = respx.post(f"{C2}{PATH_HISTORY}").mock(return_value=httpx.Response(200))
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    audit = results_dir / "audit.jsonl"
    entries = [
        {"type": "scan", "timestamp": "2026-04-17T00:00:00Z",
         "scanner_label": "a", "pass_rate": 80.0, "total": 100},
        {"type": "falsepos", "timestamp": "2026-04-17T01:00:00Z",
         "scanner_label": "b", "fp_rate": 5.0, "total_tested": 100},
        {"type": "scan", "timestamp": "2026-04-17T02:00:00Z",
         "scanner_label": "c", "pass_rate": 90.0, "total": 100},
    ]
    audit.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, [
        "history", "--results-dir", str(results_dir),
        "--push-c2", "--c2-url", C2, "--c2-key", KEY,
    ])
    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    body = json.loads(route.calls.last.request.content)
    assert body["type"] == "history"
    assert body["count"] == 3
    assert len(body["entries"]) == 3


def test_history_push_c2_missing_url_errors(tmp_path, monkeypatch):
    """--push-c2 without --c2-url is a user error, exits non-zero."""
    monkeypatch.delenv("EVADEX_C2_URL", raising=False)
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    audit = results_dir / "audit.jsonl"
    audit.write_text(
        json.dumps({"type": "scan", "timestamp": "2026-04-17T00:00:00Z",
                    "pass_rate": 80.0, "total": 100}) + "\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, [
        "history", "--results-dir", str(results_dir),
        "--push-c2",
    ])
    assert result.exit_code != 0
    assert "c2-url" in result.output.lower() or "c2_url" in result.output.lower()


@respx.mock
def test_history_push_c2_unreachable_does_not_exit_nonzero(tmp_path):
    """Same graceful-degradation contract as scan/falsepos/compare."""
    respx.post(f"{C2}{PATH_HISTORY}").mock(side_effect=httpx.ConnectError("refused"))
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    audit = results_dir / "audit.jsonl"
    audit.write_text(
        json.dumps({"type": "scan", "timestamp": "2026-04-17T00:00:00Z",
                    "pass_rate": 80.0, "total": 100}) + "\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, [
        "history", "--results-dir", str(results_dir),
        "--push-c2", "--c2-url", C2, "--c2-key", KEY,
    ])
    assert result.exit_code == 0, result.output


# ── Config file → C2 ───────────────────────────────────────────────────────

@respx.mock
def test_scan_reads_c2_from_evadex_yaml(tmp_path, monkeypatch):
    """c2_url / c2_key in evadex.yaml should activate C2 push without CLI flags."""
    monkeypatch.delenv("EVADEX_C2_URL", raising=False)
    monkeypatch.delenv("EVADEX_C2_KEY", raising=False)
    # The config file's `tool` key is validated against a fixed allowlist; use
    # the CLI --tool to point at our stub and rely on the config for c2_url/c2_key only.
    cfg = tmp_path / "evadex.yaml"
    cfg.write_text(
        f"c2_url: {C2}\n"
        f"c2_key: {KEY}\n",
        encoding="utf-8",
    )
    out = tmp_path / "scan.json"
    route = respx.post(f"{C2}{PATH_SCAN}").mock(return_value=httpx.Response(200))
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--config", str(cfg),
        "--tool", "c2-stub",
        "--category", "credit_card",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert route.call_count == 1
    # Config key forwarded as x-api-key
    assert route.calls.last.request.headers["x-api-key"] == KEY
