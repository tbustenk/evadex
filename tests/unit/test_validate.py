"""Unit tests for evadex validate command."""

import json
import pytest
from click.testing import CliRunner
from pathlib import Path
from unittest.mock import patch, MagicMock

from evadex.cli.app import main
from evadex.cli.commands.validate import _check_file_integrity, _validate_one, _ALL_TEMPLATES


# ── _check_file_integrity ──────────────────────────────────────────────────────

def test_check_integrity_csv_valid(tmp_path):
    f = tmp_path / "out.csv"
    f.write_text("value,category\n4111111111111111,credit_card\n", encoding="utf-8")
    _check_file_integrity(f, "csv")  # should not raise


def test_check_integrity_json_valid(tmp_path):
    f = tmp_path / "out.json"
    f.write_text(json.dumps([{"value": "test"}]), encoding="utf-8")
    _check_file_integrity(f, "json")  # should not raise


def test_check_integrity_json_invalid_raises(tmp_path):
    f = tmp_path / "out.json"
    f.write_text("not valid json {{", encoding="utf-8")
    with pytest.raises(Exception):
        _check_file_integrity(f, "json")


def test_check_integrity_pdf_valid(tmp_path):
    f = tmp_path / "out.pdf"
    f.write_bytes(b"%PDF-1.4 fake content")
    _check_file_integrity(f, "pdf")  # should not raise


def test_check_integrity_pdf_invalid_raises(tmp_path):
    f = tmp_path / "out.pdf"
    f.write_bytes(b"not a pdf at all")
    with pytest.raises(ValueError, match="PDF"):
        _check_file_integrity(f, "pdf")


# ── CLI tests ─────────────────────────────────────────────────────────────────

def test_validate_requires_template_or_all():
    runner = CliRunner()
    result = runner.invoke(main, ["validate"])
    assert result.exit_code != 0 or "Specify" in result.output or "Specify" in (result.output + str(result.exception or ""))


def _mock_validate_one(template, fmt, count, do_scan, tmp_dir):
    return {
        "template": template,
        "format": fmt,
        "ok": True,
        "error": None,
        "file_size_kb": 42.0,
        "entry_count": count,
        "elapsed_s": 0.1,
    }


def test_validate_single_template_ok(tmp_path):
    runner = CliRunner()
    with patch("evadex.cli.commands.validate._validate_one", side_effect=_mock_validate_one):
        result = runner.invoke(main, ["validate", "--template", "generic", "--format", "csv"])
    assert result.exit_code == 0


def test_validate_json_output(tmp_path):
    out = tmp_path / "report.json"
    runner = CliRunner()
    with patch("evadex.cli.commands.validate._validate_one", side_effect=_mock_validate_one):
        result = runner.invoke(
            main,
            ["validate", "--template", "invoice", "--format", "csv", "--output", str(out)],
        )
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data[0]["template"] == "invoice"


def test_validate_error_template_exits_nonzero():
    def fail_validate(template, fmt, count, do_scan, tmp_dir):
        return {
            "template": template,
            "format": fmt,
            "ok": False,
            "error": "writer failed",
            "file_size_kb": 0.0,
            "entry_count": 0,
            "elapsed_s": 0.0,
        }

    runner = CliRunner()
    with patch("evadex.cli.commands.validate._validate_one", side_effect=fail_validate):
        result = runner.invoke(main, ["validate", "--template", "generic", "--format", "docx"])
    assert result.exit_code != 0
