"""Tests for --min-detection-rate, --baseline/--compare-baseline, list-payloads, list-techniques."""
import json
import pytest
from pathlib import Path
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


# ── output path error handling ────────────────────────────────────────────────

def test_output_nonexistent_dir_gives_clear_error():
    """Writing to a path whose parent directory doesn't exist should produce a
    clear error message, not a raw FileNotFoundError traceback."""
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--output", "/nonexistent/directory/results.json",
        ])
    assert result.exit_code == 1
    # SystemExit from sys.exit(1) is expected; a raw OSError/FileNotFoundError is not
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Cannot write output file" in result.output or "nonexistent" in result.output.lower()
    # Ensure it is NOT a raw traceback
    assert "FileNotFoundError" not in result.output
    assert "Traceback" not in result.output


def test_baseline_nonexistent_dir_gives_clear_error(tmp_path):
    """Saving a baseline to a path whose parent directory doesn't exist should
    produce a clear error message."""
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--baseline", "/nonexistent/directory/baseline.json",
        ])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "FileNotFoundError" not in result.output
    assert "Traceback" not in result.output


# ── compare-baseline error handling ──────────────────────────────────────────

def test_compare_baseline_empty_file_gives_clear_error(tmp_path):
    """An empty baseline file should produce a descriptive error, not a traceback."""
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--compare-baseline", str(empty),
        ])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "JSON" in result.output
    assert "JSONDecodeError" not in result.output
    assert "Traceback" not in result.output


def test_compare_baseline_wrong_schema_gives_clear_error(tmp_path):
    """A JSON file that is not an evadex result (missing meta/results) should
    produce a descriptive error, not a KeyError traceback."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"unexpected": "value"}), encoding="utf-8")
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = [_make_result(True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366", "--strategy", "text",
            "--compare-baseline", str(bad),
        ])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "evadex result file" in result.output or "meta" in result.output
    assert "KeyError" not in result.output
    assert "Traceback" not in result.output


# ── engine exception handling ─────────────────────────────────────────────────

def test_engine_adapter_exception_becomes_error_result():
    """If the adapter raises an exception for one variant, the engine should
    return a ScanResult with error set rather than crashing."""
    from evadex.core.engine import Engine
    from evadex.adapters.base import BaseAdapter

    class BrokenAdapter(BaseAdapter):
        async def submit(self, payload, variant):
            raise RuntimeError("scanner exploded")

    from evadex.core.registry import load_builtins
    load_builtins()
    engine = Engine(adapter=BrokenAdapter({}), strategies=["text"], concurrency=1)
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    results = engine.run([p])
    assert len(results) > 0
    assert all(r.error is not None for r in results)
    assert all("scanner exploded" in (r.error or "") for r in results)


def test_engine_keyboard_interrupt_propagates():
    """KeyboardInterrupt from the adapter should propagate out of the engine,
    not be silently swallowed as an error ScanResult."""
    from evadex.core.engine import Engine
    from evadex.adapters.base import BaseAdapter

    class KIAdapter(BaseAdapter):
        async def submit(self, payload, variant):
            raise KeyboardInterrupt("simulated Ctrl+C")

    from evadex.core.registry import load_builtins
    load_builtins()
    engine = Engine(adapter=KIAdapter({}), strategies=["text"], concurrency=1)
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    with pytest.raises(KeyboardInterrupt):
        engine.run([p])


def test_engine_on_result_exception_does_not_abort_scan():
    """A callback that raises must not interrupt the scan; all results must be returned."""
    from evadex.core.engine import Engine
    from evadex.adapters.base import BaseAdapter

    class StubAdapter(BaseAdapter):
        async def submit(self, payload, variant):
            return ScanResult(payload=payload, variant=variant, detected=True)

    def bad_callback(result, completed, total):
        raise RuntimeError("callback exploded")

    from evadex.core.registry import load_builtins
    load_builtins()
    engine = Engine(
        adapter=StubAdapter({}),
        strategies=["text"],
        on_result=bad_callback,
    )
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    results = engine.run([p])
    # Scan must complete and return all results despite the failing callback
    assert len(results) > 0


def test_baseline_and_compare_baseline_same_file_rejected(tmp_path):
    """Using the same path for --baseline and --compare-baseline must fail early
    with a clear error before running any scan."""
    runner = CliRunner()
    same_file = str(tmp_path / "baseline.json")
    result = runner.invoke(main, [
        "scan", "--input", "4532015112830366", "--strategy", "text",
        "--baseline", same_file,
        "--compare-baseline", same_file,
    ])
    assert result.exit_code == 1
    assert "same file" in result.output.lower() or "cannot" in result.output.lower()
