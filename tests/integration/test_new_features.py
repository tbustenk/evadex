"""Tests for --min-detection-rate, --baseline/--compare-baseline, list-payloads, list-techniques."""
import json
import pytest
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock
from evadex.cli.app import main
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory
from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter


def _make_result(detected: bool):
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=detected, duration_ms=1.0)


# ── --min-detection-rate ──────────────────────────────────────────────────────

def test_min_rate_passes_when_above_threshold():
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True), _make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--min-detection-rate", "80",
        ])
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_min_rate_fails_when_below_threshold():
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(False), _make_result(False)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--min-detection-rate", "80",
        ])
    assert result.exit_code == 1
    assert "FAIL" in result.output
    assert "80.0%" in result.output


def test_min_rate_exact_boundary_passes():
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True), _make_result(False)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--min-detection-rate", "50",
        ])
    assert result.exit_code == 0


# ── --baseline / --compare-baseline ──────────────────────────────────────────

def test_baseline_creates_file(tmp_path):
    baseline = tmp_path / "baseline.json"
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--baseline", str(baseline),
        ])
    assert result.exit_code == 0
    assert baseline.exists()
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert "meta" in data and "results" in data


def test_compare_baseline_no_regression(tmp_path):
    baseline = tmp_path / "baseline.json"
    runner = CliRunner()
    results = [_make_result(True)]
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = results
        runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--baseline", str(baseline),
        ])

    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = results
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--compare-baseline", str(baseline),
        ])
    assert result.exit_code == 0
    assert "No changes" in result.output


def test_compare_baseline_detects_regression(tmp_path):
    baseline = tmp_path / "baseline.json"
    runner = CliRunner()

    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--baseline", str(baseline),
        ])

    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(False)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--compare-baseline", str(baseline),
        ])
    assert result.exit_code == 0
    assert "regression" in result.output.lower()


def test_compare_baseline_missing_file():
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--compare-baseline", "/nonexistent/path/baseline.json",
        ])
    assert result.exit_code == 1


# ── list-payloads ─────────────────────────────────────────────────────────────

def test_list_payloads_shows_all():
    runner = CliRunner()
    result = runner.invoke(main, ["list-payloads"])
    assert result.exit_code == 0
    assert "Visa 16-digit" in result.output
    assert "US SSN" in result.output
    assert "30 payload" in result.output


def test_list_payloads_filter_structured():
    runner = CliRunner()
    result = runner.invoke(main, ["list-payloads", "--type", "structured"])
    assert result.exit_code == 0
    assert "23 payload" in result.output
    assert "AWS Access Key" not in result.output


def test_list_payloads_filter_heuristic():
    runner = CliRunner()
    result = runner.invoke(main, ["list-payloads", "--type", "heuristic"])
    assert result.exit_code == 0
    assert "AWS Access Key" in result.output
    assert "Visa 16-digit" not in result.output
    assert "7 payload" in result.output


# ── list-techniques ───────────────────────────────────────────────────────────

def test_list_techniques_shows_generators():
    runner = CliRunner()
    result = runner.invoke(main, ["list-techniques"])
    assert result.exit_code == 0
    for gen in ("unicode_encoding", "delimiter", "splitting", "structural",
                "encoding", "regional_digits", "leetspeak"):
        assert gen in result.output


def test_list_techniques_filter_generator():
    runner = CliRunner()
    result = runner.invoke(main, ["list-techniques", "--generator", "delimiter"])
    assert result.exit_code == 0
    assert "delimiter" in result.output
    assert "unicode_encoding" not in result.output


def test_list_techniques_unknown_generator():
    runner = CliRunner()
    result = runner.invoke(main, ["list-techniques", "--generator", "nonexistent"])
    assert result.exit_code != 0


# ── engine on_result callback ─────────────────────────────────────────────────

def test_engine_on_result_called():
    from evadex.core.engine import Engine
    from evadex.adapters.base import BaseAdapter, AdapterConfig

    class StubAdapter(BaseAdapter):
        async def submit(self, payload, variant):
            return ScanResult(payload=payload, variant=variant, detected=True)

    calls = []
    engine = Engine(
        adapter=StubAdapter({}),
        strategies=["text"],
        on_result=lambda r, completed, total: calls.append((completed, total)),
    )
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    engine.run([p])
    assert len(calls) > 0
    # completed should always equal total on the last call
    assert calls[-1][0] == calls[-1][1]
