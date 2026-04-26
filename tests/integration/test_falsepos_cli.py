"""Integration tests for the evadex falsepos command."""
import json
from unittest.mock import patch, AsyncMock

from click.testing import CliRunner

from evadex.cli.app import main
from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory


def _make_not_detected(value: str, cat: str) -> ScanResult:
    try:
        cat_enum = PayloadCategory(cat)
    except ValueError:
        cat_enum = PayloadCategory.UNKNOWN
    p = Payload(value, cat_enum, f"falsepos:{cat}")
    v = Variant(value, "falsepos", "falsepos_value", "False positive test value", strategy="text")
    return ScanResult(payload=p, variant=v, detected=False)


def _make_detected(value: str, cat: str) -> ScanResult:
    result = _make_not_detected(value, cat)
    object.__setattr__(result, "detected", True)
    return result


def test_falsepos_table_no_flagged():
    """All values not flagged → 0% false positive rate."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True), \
         patch.object(DlpscanCliAdapter, "submit", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = ScanResult(
            payload=Payload("dummy", PayloadCategory.CREDIT_CARD, "x"),
            variant=Variant("dummy", "falsepos", "falsepos_value", "FP value", strategy="text"),
            detected=False,
        )
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--category", "credit_card",
            "--count", "5",
        ])

    assert result.exit_code == 0, result.output
    assert "0/5" in result.output
    assert "0.0%" in result.output


def test_falsepos_some_flagged():
    """Adapter flags every value → 100% false positive rate."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True), \
         patch.object(DlpscanCliAdapter, "submit", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = ScanResult(
            payload=Payload("dummy", PayloadCategory.SSN, "x"),
            variant=Variant("dummy", "falsepos", "falsepos_value", "FP value", strategy="text"),
            detected=True,
            # strict_category mode checks raw_response["matches"] for a
            # category-relevant sub_category before counting as an FP.
            raw_response={"matches": [{"sub_category": "usa ssn"}]},
        )
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--category", "ssn",
            "--count", "10",
        ])

    assert result.exit_code == 0, result.output
    assert "10/10" in result.output
    assert "100.0%" in result.output


def test_falsepos_json_output():
    """--format json writes a valid JSON report to stdout."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True), \
         patch.object(DlpscanCliAdapter, "submit", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = ScanResult(
            payload=Payload("dummy", PayloadCategory.CREDIT_CARD, "x"),
            variant=Variant("dummy", "falsepos", "falsepos_value", "FP value", strategy="text"),
            detected=False,
        )
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--category", "credit_card",
            "--count", "5",
            "--format", "json",
        ])

    assert result.exit_code == 0, result.output
    # Find JSON start
    json_start = result.output.index("{")
    data = json.loads(result.output[json_start:])
    assert "overall_false_positive_rate" in data
    assert "by_category" in data
    assert "credit_card" in data["by_category"]
    assert data["by_category"]["credit_card"]["total"] == 5
    assert data["by_category"]["credit_card"]["flagged"] == 0


def test_falsepos_json_output_to_file(tmp_path):
    """--output saves JSON to file."""
    out_file = tmp_path / "fp_report.json"
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True), \
         patch.object(DlpscanCliAdapter, "submit", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = ScanResult(
            payload=Payload("dummy", PayloadCategory.SIN, "x"),
            variant=Variant("dummy", "falsepos", "falsepos_value", "FP value", strategy="text"),
            detected=False,
        )
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--category", "sin",
            "--count", "5",
            "--format", "json",
            "--output", str(out_file),
        ])

    assert result.exit_code == 0, result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["by_category"]["sin"]["total"] == 5


def test_falsepos_health_check_failure():
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=False):
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--category", "credit_card",
            "--count", "5",
        ])
    assert result.exit_code == 1


def test_falsepos_all_categories_run():
    """No --category flag → all 7 categories run."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True), \
         patch.object(DlpscanCliAdapter, "submit", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = ScanResult(
            payload=Payload("dummy", PayloadCategory.CREDIT_CARD, "x"),
            variant=Variant("dummy", "falsepos", "falsepos_value", "FP value", strategy="text"),
            detected=False,
        )
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--count", "3",
            "--format", "json",
        ])

    assert result.exit_code == 0, result.output
    json_start = result.output.index("{")
    data = json.loads(result.output[json_start:])
    assert len(data["by_category"]) == 8
    assert data["total_tested"] == 8 * 3


def test_falsepos_report_structure():
    """JSON report contains all required fields."""
    runner = CliRunner()
    with patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True), \
         patch.object(DlpscanCliAdapter, "submit", new_callable=AsyncMock) as mock_submit:
        mock_submit.return_value = ScanResult(
            payload=Payload("dummy", PayloadCategory.IBAN, "x"),
            variant=Variant("dummy", "falsepos", "falsepos_value", "FP value", strategy="text"),
            detected=True,
            # strict_category mode checks raw_response["matches"] for a
            # category-relevant sub_category before counting as an FP.
            raw_response={"matches": [{"sub_category": "iban"}]},
        )
        result = runner.invoke(main, [
            "falsepos",
            "--tool", "dlpscan-cli",
            "--category", "iban",
            "--count", "4",
            "--format", "json",
        ])

    assert result.exit_code == 0, result.output
    json_start = result.output.index("{")
    data = json.loads(result.output[json_start:])
    # Top-level fields
    for field in ("tool", "count_per_category", "total_tested", "total_flagged",
                  "overall_false_positive_rate", "by_category"):
        assert field in data, f"Missing field: {field}"
    # Per-category fields
    cat = data["by_category"]["iban"]
    for field in ("total", "flagged", "false_positive_rate", "flagged_values"):
        assert field in cat, f"Missing per-category field: {field}"
    # All values were detected → flagged_values should be non-empty
    assert len(cat["flagged_values"]) == 4
