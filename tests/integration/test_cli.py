import json
from click.testing import CliRunner
from unittest.mock import patch
from evadex.cli.app import main
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory


def _mock_result():
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=True, duration_ms=5.2)


def test_scan_json_output():
    runner = CliRunner()
    mock_results = [_mock_result()]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine:
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
    with patch("evadex.cli.commands.scan.Engine") as MockEngine:
        MockEngine.return_value.run.return_value = mock_results
        result = runner.invoke(main, [
            "scan",
            "--input", "4532015112830366",
            "--format", "html",
            "--strategy", "text",
        ])
    assert result.exit_code == 0
    assert "<table>" in result.output
