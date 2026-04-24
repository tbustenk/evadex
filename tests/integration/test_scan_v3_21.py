"""Integration tests for v3.21.0 scan features — --fast, --verbose, Rich progress,
and per-technique / per-category granularity in the JSON reporter."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter
from evadex.cli.app import main
from evadex.core.result import (
    Payload, PayloadCategory, ScanResult, Variant,
)


def _mock_result(detected: bool = True, technique: str = "no_delimiter") -> ScanResult:
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant(
        "4532015112830366", "structural", technique, "No delimiter",
        strategy="text",
    )
    return ScanResult(
        payload=p, variant=v, detected=detected, duration_ms=5.2,
        confidence=0.95 if detected else None,
    )


def _find_json(output: str) -> dict:
    """Extract the JSON body from mixed stderr+stdout Click test output.

    Fix-suggestion lines print after the JSON when the scan has failures,
    so use raw_decode to parse just the first complete JSON object.
    """
    start = output.index("{")
    data, _end = json.JSONDecoder().raw_decode(output[start:])
    return data


def test_fast_flag_trims_variant_pool(tmp_path):
    """--fast must pass a technique_filter to the Engine."""
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = [_mock_result()]
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--fast",
            "--strategy", "text",
            "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    # The Engine must have been instantiated with a non-None technique_filter.
    _, kwargs = MockEngine.call_args
    assert kwargs.get("technique_filter") is not None
    assert isinstance(kwargs["technique_filter"], set)
    assert len(kwargs["technique_filter"]) > 0
    # User-facing signal that fast mode engaged must appear in the output.
    assert "fast" in result.output.lower()


def test_fast_flag_vs_full_produces_smaller_pool():
    """--fast must restrict to fewer techniques than the default exhaustive pool."""
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = [_mock_result()]
        # Full run
        runner.invoke(main, [
            "scan", "--input", "4532015112830366",
            "--strategy", "text", "--format", "json",
        ])
        full_kwargs = MockEngine.call_args.kwargs
        # Fast run
        runner.invoke(main, [
            "scan", "--input", "4532015112830366",
            "--fast", "--strategy", "text", "--format", "json",
        ])
        fast_kwargs = MockEngine.call_args.kwargs
    assert full_kwargs.get("technique_filter") is None
    assert fast_kwargs.get("technique_filter") is not None


def test_verbose_flag_emits_per_variant_lines():
    """--verbose must print one indicator per result to stderr."""
    runner = CliRunner()
    mock_results = [
        _mock_result(detected=True, technique="homoglyph_substitution"),
        _mock_result(detected=False, technique="zero_width_space"),
    ]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True):
        # --verbose flows results through on_result, so replicate that here:
        def _runner(*args, **kwargs):
            cb = MockEngine.call_args.kwargs.get("on_result")
            for i, r in enumerate(mock_results, 1):
                if cb:
                    cb(r, i, len(mock_results))
            return mock_results
        MockEngine.return_value.run.side_effect = _runner
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--verbose",
            "--strategy", "text",
            "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    # Every mocked result should surface its technique name.
    assert "homoglyph_substitution" in result.output
    assert "zero_width_space" in result.output
    # And a detected/evaded marker.
    assert "detected" in result.output.lower()
    assert "evaded" in result.output.lower()


def test_per_technique_granularity_in_json_output():
    """summary_by_technique must include evasion_rate + example fields."""
    runner = CliRunner()
    mock_results = [
        _mock_result(detected=True),
        _mock_result(detected=False),
        _mock_result(detected=False),
    ]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = mock_results
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--strategy", "text",
            "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    data = _find_json(result.output)
    sbt = data["meta"]["summary_by_technique"]
    assert sbt, "summary_by_technique must not be empty"
    entry = next(iter(sbt.values()))
    assert "evasion_rate" in entry
    assert "example_evaded_value" in entry
    assert "example_detected_value" in entry
    # 2 fails out of 3 (1 pass) — evasion rate is 66.7%
    assert entry["evasion_rate"] == 66.7


def test_per_category_granularity_in_json_output():
    """summary_by_category must include evasion_rate and worst/best technique."""
    runner = CliRunner()
    # 4 results of the same category but two techniques — one always
    # evades, one always detects.
    mock_results = [
        _mock_result(detected=False, technique="homoglyph"),
        _mock_result(detected=False, technique="homoglyph"),
        _mock_result(detected=False, technique="homoglyph"),
        _mock_result(detected=True,  technique="leet_substitution"),
        _mock_result(detected=True,  technique="leet_substitution"),
        _mock_result(detected=True,  technique="leet_substitution"),
    ]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = mock_results
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366",
            "--strategy", "text", "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    data = _find_json(result.output)
    sbc = data["meta"]["summary_by_category"]
    cc = sbc["credit_card"]
    assert cc["evasion_rate"] == 50.0
    assert cc["worst_technique"]["technique"] == "homoglyph"
    assert cc["best_technique"]["technique"] == "leet_substitution"
    assert "sample_evaded" in cc


def test_confidence_distribution_in_json_output():
    """JSON output must carry a confidence_distribution block."""
    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = [_mock_result(detected=True)]
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366",
            "--strategy", "text", "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    data = _find_json(result.output)
    assert "confidence_distribution" in data["meta"]
    cd = data["meta"]["confidence_distribution"]
    assert cd["total"] == 1
    # 0.95 falls in the 0.9-1.0 bucket
    assert cd["buckets"]["0.9-1.0"] == 1


def test_progress_bar_renders_during_scan():
    """The Rich progress context must be active during the scan (not an error)."""
    runner = CliRunner()
    mock_results = [_mock_result()]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check",
                      new_callable=AsyncMock, return_value=True), \
         patch("evadex.cli.commands.scan.Progress") as MockProgress:
        MockEngine.return_value.run.return_value = mock_results
        MockProgress.return_value.__enter__.return_value = MockProgress.return_value
        MockProgress.return_value.add_task.return_value = "task-id"
        result = runner.invoke(main, [
            "scan", "--input", "4532015112830366",
            "--strategy", "text", "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    # Progress was instantiated and a task added.
    assert MockProgress.called
    MockProgress.return_value.add_task.assert_called()
