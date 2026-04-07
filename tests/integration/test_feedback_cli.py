"""Integration tests for Phase 2 feedback loop:
--feedback-report flag, regression file generation, and fix suggestions.
"""
import ast
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter
from evadex.cli.app import main
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fail(
    technique: str = "homoglyph_substitution",
    generator: str = "unicode_encoding",
    value: str = "4532\u041e15112830366",
    transform_name: str = "Visually similar Cyrillic/Greek characters substituted",
    category: PayloadCategory = PayloadCategory.CREDIT_CARD,
) -> ScanResult:
    p = Payload("4532015112830366", category, "Visa 16-digit")
    v = Variant(value, generator, technique, transform_name, strategy="text")
    return ScanResult(payload=p, variant=v, detected=False, duration_ms=1.0)


def _pass() -> ScanResult:
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=True, duration_ms=1.0)


def _invoke(runner, mock_results, extra_args=None):
    args = [
        "scan", "--input", "4532015112830366", "--strategy", "text",
    ] + (extra_args or [])
    with patch("evadex.cli.commands.scan.Engine") as ME, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        ME.return_value.run.return_value = mock_results
        return runner.invoke(main, args)


# ── --feedback-report ─────────────────────────────────────────────────────────

def test_feedback_report_created(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    result = _invoke(runner, [_fail(), _pass()],
                     extra_args=["--feedback-report", str(report_path)])
    assert result.exit_code == 0
    assert report_path.exists()


def test_feedback_report_valid_json(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    _invoke(runner, [_fail(), _pass()],
            extra_args=["--feedback-report", str(report_path)])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert "meta" in data
    assert "techniques" in data
    assert "fix_suggestions" in data
    assert "regression_test_code" in data


def test_feedback_report_meta_counts(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    _invoke(runner, [_fail(), _fail("zero_width_zwsp"), _pass()],
            extra_args=["--feedback-report", str(report_path)])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["meta"]["total_tests"] == 3
    assert data["meta"]["total_evasions"] == 2


def test_feedback_report_techniques_list(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    _invoke(runner, [_fail("homoglyph_substitution"), _fail("zero_width_zwsp")],
            extra_args=["--feedback-report", str(report_path)])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    techs = {t["technique"] for t in data["techniques"]}
    assert "homoglyph_substitution" in techs
    assert "zero_width_zwsp" in techs


def test_feedback_report_fix_suggestions_present(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    _invoke(runner, [_fail("homoglyph_substitution")],
            extra_args=["--feedback-report", str(report_path)])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert len(data["fix_suggestions"]) == 1
    s = data["fix_suggestions"][0]
    assert s["technique"] == "homoglyph_substitution"
    assert "suggested_fix" in s
    assert "description" in s


def test_feedback_report_regression_code_is_valid_python(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    _invoke(runner, [_fail()],
            extra_args=["--feedback-report", str(report_path)])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    code = data["regression_test_code"]
    assert "def test_" in code
    ast.parse(code)  # raises SyntaxError if invalid


def test_feedback_report_no_evasions_empty_lists(tmp_path):
    report_path = tmp_path / "feedback.json"
    runner = CliRunner()
    _invoke(runner, [_pass(), _pass()],
            extra_args=["--feedback-report", str(report_path)])
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["meta"]["total_evasions"] == 0
    assert data["techniques"] == []
    assert data["fix_suggestions"] == []
    assert data["regression_test_code"] == ""


def test_feedback_report_bad_path_exits_with_error():
    runner = CliRunner()
    result = _invoke(runner, [_fail()],
                     extra_args=["--feedback-report", "/nonexistent_dir/sub/feedback.json"])
    assert result.exit_code == 1
    assert "Cannot write" in result.output


# ── Regression file ───────────────────────────────────────────────────────────

def test_regression_file_written_on_evasion():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _invoke(runner, [_fail()])
        assert Path("evadex_regressions.py").exists()


def test_regression_file_contains_valid_python():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _invoke(runner, [_fail()])
        code = Path("evadex_regressions.py").read_text(encoding="utf-8")
        ast.parse(code)


def test_regression_file_has_test_function():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _invoke(runner, [_fail()])
        code = Path("evadex_regressions.py").read_text(encoding="utf-8")
        assert "def test_" in code
        assert "InputGuard" in code
        assert "assert not result.is_clean" in code


def test_regression_file_not_written_when_all_pass():
    runner = CliRunner()
    with runner.isolated_filesystem():
        _invoke(runner, [_pass(), _pass()])
        assert not Path("evadex_regressions.py").exists()


def test_regression_file_path_mentioned_in_output():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = _invoke(runner, [_fail()])
    assert "evadex_regressions.py" in result.output


# ── Fix suggestions ───────────────────────────────────────────────────────────

def test_suggestions_printed_on_evasion():
    runner = CliRunner()
    result = _invoke(runner, [_fail("homoglyph_substitution")])
    assert result.exit_code == 0
    assert "Fix Suggestion" in result.output


def test_suggestions_contain_technique_name():
    runner = CliRunner()
    result = _invoke(runner, [_fail("homoglyph_substitution")])
    assert "homoglyph_substitution" in result.output


def test_suggestions_contain_actionable_fix():
    runner = CliRunner()
    result = _invoke(runner, [_fail("homoglyph_substitution")])
    # The fix mentions Cyrillic/homoglyph normalisation
    assert "homoglyph" in result.output.lower() or "cyrillic" in result.output.lower()


def test_no_suggestions_block_when_all_pass():
    runner = CliRunner()
    result = _invoke(runner, [_pass(), _pass()])
    assert result.exit_code == 0
    assert "Fix Suggestion" not in result.output


def test_multiple_techniques_multiple_suggestions():
    runner = CliRunner()
    result = _invoke(runner, [
        _fail("homoglyph_substitution"),
        _fail("zero_width_zwsp"),
    ])
    assert result.exit_code == 0
    assert "homoglyph_substitution" in result.output
    assert "zero_width_zwsp" in result.output
