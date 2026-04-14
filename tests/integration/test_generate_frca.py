"""Integration tests for evadex generate — fr-CA language and edge cases."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest
from click.testing import CliRunner

from evadex.cli.app import main


def _invoke(runner, args):
    return runner.invoke(main, ["generate"] + args)


# ── fr-CA language ────────────────────────────────────────────────────────────

class TestFrCaGenerate:
    def _args(self, fmt: str, output: str, category: str = "credit_card", count: int = 5) -> list:
        return [
            "--format", fmt,
            "--category", category,
            "--count", str(count),
            "--seed", "42",
            "--language", "fr-ca",
            "--output", output,
        ]

    def test_csv_frca_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.csv")
        result = _invoke(runner, self._args("csv", out))
        assert result.exit_code == 0, result.output

    def test_csv_frca_file_created(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "out.csv"
        _invoke(runner, self._args("csv", str(out)))
        assert out.exists()

    def test_csv_frca_embedded_text_is_utf8(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "out.csv"
        _invoke(runner, self._args("csv", str(out), count=10))
        with open(out, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        # At least some embedded_text rows should be non-empty
        non_empty = [r for r in rows if r.get("embedded_text", "").strip()]
        assert len(non_empty) > 0

    def test_txt_frca_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.txt")
        result = _invoke(runner, self._args("txt", out))
        assert result.exit_code == 0, result.output

    def test_xlsx_frca_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.xlsx")
        result = _invoke(runner, self._args("xlsx", out))
        assert result.exit_code == 0, result.output

    def test_docx_frca_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.docx")
        result = _invoke(runner, self._args("docx", out))
        assert result.exit_code == 0, result.output

    def test_pdf_frca_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.pdf")
        result = _invoke(runner, self._args("pdf", out))
        assert result.exit_code == 0, result.output

    def test_pdf_frca_valid_magic(self, tmp_path):
        """PDF must start with %PDF even when French templates contain non-Latin-1 chars."""
        runner = CliRunner()
        out = tmp_path / "out.pdf"
        _invoke(runner, self._args("pdf", str(out)))
        assert out.read_bytes()[:4] == b"%PDF"

    def test_sin_frca_csv_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.csv")
        result = _invoke(runner, self._args("csv", out, category="sin"))
        assert result.exit_code == 0, result.output

    def test_iban_frca_csv_exits_zero(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.csv")
        result = _invoke(runner, self._args("csv", out, category="iban"))
        assert result.exit_code == 0, result.output


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestGenerateEdgeCases:
    def test_count_one_csv(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "out.csv"
        result = _invoke(runner, [
            "--format", "csv", "--category", "ssn",
            "--count", "1", "--seed", "1",
            "--output", str(out),
        ])
        assert result.exit_code == 0
        with open(out, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1

    def test_evasion_rate_zero_csv(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "out.csv"
        _invoke(runner, [
            "--format", "csv", "--category", "credit_card",
            "--count", "10", "--seed", "1", "--evasion-rate", "0.0",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert all(r["technique"] == "" for r in rows)

    def test_evasion_rate_one_csv(self, tmp_path):
        runner = CliRunner()
        out = tmp_path / "out.csv"
        _invoke(runner, [
            "--format", "csv", "--category", "credit_card",
            "--count", "10", "--seed", "1", "--evasion-rate", "1.0",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert all(r["technique"] != "" for r in rows)

    def test_all_formats_produce_non_empty_files(self, tmp_path):
        runner = CliRunner()
        for fmt, ext in [("csv", "csv"), ("txt", "txt"), ("xlsx", "xlsx"),
                          ("docx", "docx"), ("pdf", "pdf")]:
            out = tmp_path / f"out.{ext}"
            result = _invoke(runner, [
                "--format", fmt, "--category", "credit_card",
                "--count", "3", "--seed", "42",
                "--output", str(out),
            ])
            assert result.exit_code == 0, f"{fmt}: {result.output}"
            assert out.stat().st_size > 0, f"{fmt} file is empty"

    def test_multicategory_frca_xlsx(self, tmp_path):
        runner = CliRunner()
        out = str(tmp_path / "out.xlsx")
        result = _invoke(runner, [
            "--format", "xlsx",
            "--category", "credit_card",
            "--category", "sin",
            "--count", "5", "--seed", "42", "--language", "fr-ca",
            "--output", out,
        ])
        assert result.exit_code == 0, result.output
