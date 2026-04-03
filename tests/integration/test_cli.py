import json
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock
from evadex.cli.app import main
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory
from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter


def _mock_result():
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=True, duration_ms=5.2)


def test_scan_json_output():
    runner = CliRunner()
    mock_results = [_mock_result()]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = mock_results
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--format", "json",
            "--url", "http://localhost:8080",
            "--strategy", "text",
        ])
    assert result.exit_code == 0, result.output
    # Rich status lines precede the JSON block; find the JSON start
    json_start = result.output.index('{')
    data = json.loads(result.output[json_start:])
    assert "meta" in data
    assert data["meta"]["total"] == 1


def test_scan_html_output():
    runner = CliRunner()
    mock_results = [_mock_result()]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = mock_results
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--format", "html",
            "--strategy", "text",
        ])
    assert result.exit_code == 0
    assert "<table>" in result.output


def test_scan_health_check_failure_exits():
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=False):
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--strategy", "text",
        ])
    assert result.exit_code == 1


def test_scan_no_payloads_exits():
    """Filtering to a category with no built-in payloads should exit with error."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        result = runner.invoke(main, [
            "scan",
            "--category", "unknown",
            "--strategy", "text",
        ])
    assert result.exit_code == 1


def test_scan_heuristic_category_without_flag_exits():
    """Requesting a heuristic category without --include-heuristic should exit with error."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        result = runner.invoke(main, [
            "scan",
            "--category", "aws_key",
            "--strategy", "text",
        ])
    assert result.exit_code == 1
    assert "heuristic" in result.output.lower() or "include-heuristic" in result.output


def test_scan_invalid_variant_group_exits():
    """Unknown --variant-group name should exit with error."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--variant-group", "nonexistent_generator",
            "--strategy", "text",
        ])
    assert result.exit_code == 1
