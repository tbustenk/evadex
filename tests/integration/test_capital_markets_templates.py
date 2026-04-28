"""Integration tests for the five capital-markets generate templates (v3.25.0)."""
from __future__ import annotations

import csv
from pathlib import Path

import pytest
from click.testing import CliRunner

from evadex.cli.app import main


def _gen(runner: CliRunner, fmt: str, template: str, output: str,
         count: int = 5, tier: str = "banking") -> object:
    return runner.invoke(main, [
        "generate",
        "--format", fmt,
        "--template", template,
        "--tier", tier,
        "--count", str(count),
        "--seed", "42",
        "--output", output,
    ])


# ── trade_confirmation ────────────────────────────────────────────────────────

class TestTradeConfirmation:
    def test_exits_zero(self, tmp_path):
        result = _gen(CliRunner(), "docx", "trade_confirmation", str(tmp_path / "out.docx"))
        assert result.exit_code == 0, result.output

    def test_file_nonempty(self, tmp_path):
        out = tmp_path / "out.docx"
        _gen(CliRunner(), "docx", "trade_confirmation", str(out))
        assert out.stat().st_size > 0

    def test_txt_contains_trade_keywords(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "trade_confirmation", str(out))
        content = out.read_text(encoding="utf-8").upper()
        # Must mention BUY/SELL or French ACHAT/VENTE
        assert any(kw in content for kw in ("BUY", "SELL", "ACHAT", "VENTE"))

    def test_txt_contains_capital_markets_identifiers(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "trade_confirmation", str(out), count=10)
        content = out.read_text(encoding="utf-8")
        # Must reference ISIN or CUSIP or SEDOL somewhere
        assert any(kw in content.upper() for kw in ("ISIN", "CUSIP", "SEDOL", "LEI"))


# ── swift_mt103 ───────────────────────────────────────────────────────────────

class TestSwiftMt103:
    def test_exits_zero(self, tmp_path):
        result = _gen(CliRunner(), "docx", "swift_mt103", str(tmp_path / "out.docx"))
        assert result.exit_code == 0, result.output

    def test_file_nonempty(self, tmp_path):
        out = tmp_path / "out.docx"
        _gen(CliRunner(), "docx", "swift_mt103", str(out))
        assert out.stat().st_size > 0

    def test_txt_contains_mt103_block_markers(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "swift_mt103", str(out))
        content = out.read_text(encoding="utf-8")
        # SWIFT MT103 blocks start with {1: or {4:
        assert "{4:" in content or ":32A:" in content or ":50K:" in content

    def test_txt_contains_bic_or_iban(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "swift_mt103", str(out), count=10)
        content = out.read_text(encoding="utf-8")
        # IBAN (starts with country code + digits) or BIC (8-11 alpha) should appear
        assert ":52A:" in content or ":57A:" in content or ":59:" in content


# ── settlement_instruction ────────────────────────────────────────────────────

class TestSettlementInstruction:
    def test_exits_zero(self, tmp_path):
        result = _gen(CliRunner(), "docx", "settlement_instruction", str(tmp_path / "out.docx"))
        assert result.exit_code == 0, result.output

    def test_file_nonempty(self, tmp_path):
        out = tmp_path / "out.docx"
        _gen(CliRunner(), "docx", "settlement_instruction", str(out))
        assert out.stat().st_size > 0

    def test_txt_contains_settlement_keywords(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "settlement_instruction", str(out))
        content = out.read_text(encoding="utf-8").upper()
        assert any(kw in content for kw in ("SETTL", "DELIVER", "BIC", "ISIN", "CUSIP"))

    def test_txt_frca_accepted(self, tmp_path):
        out = tmp_path / "out.txt"
        result = _gen(CliRunner(), "txt", "settlement_instruction", str(out),
                      count=5, tier="banking")
        result_fr = runner = CliRunner()
        r = runner.invoke(main, [
            "generate", "--format", "txt", "--template", "settlement_instruction",
            "--tier", "banking", "--count", "5", "--seed", "42",
            "--language", "fr-CA", "--output", str(tmp_path / "out_fr.txt"),
        ])
        assert r.exit_code == 0, r.output


# ── bloomberg_export ──────────────────────────────────────────────────────────

class TestBloombergExport:
    def test_exits_zero_csv(self, tmp_path):
        result = _gen(CliRunner(), "csv", "bloomberg_export", str(tmp_path / "out.csv"), count=10)
        assert result.exit_code == 0, result.output

    def test_csv_file_nonempty(self, tmp_path):
        out = tmp_path / "out.csv"
        _gen(CliRunner(), "csv", "bloomberg_export", str(out), count=10)
        assert out.stat().st_size > 0

    def test_csv_contains_bloomberg_columns(self, tmp_path):
        out = tmp_path / "out.csv"
        _gen(CliRunner(), "csv", "bloomberg_export", str(out), count=10)
        content = out.read_text(encoding="utf-8")
        # bloomberg_export CSV format should have ISIN or SEDOL or FIGI column headers
        assert any(col in content.upper() for col in ("ISIN", "SEDOL", "FIGI", "CUSIP", "TICKER"))

    def test_csv_has_multiple_lines(self, tmp_path):
        out = tmp_path / "out.csv"
        _gen(CliRunner(), "csv", "bloomberg_export", str(out), count=10)
        lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) >= 2  # at least header + one data row

    def test_exits_zero_docx(self, tmp_path):
        result = _gen(CliRunner(), "docx", "bloomberg_export", str(tmp_path / "out.docx"), count=5)
        assert result.exit_code == 0, result.output


# ── risk_report ───────────────────────────────────────────────────────────────

class TestRiskReport:
    def test_exits_zero(self, tmp_path):
        result = _gen(CliRunner(), "docx", "risk_report", str(tmp_path / "out.docx"))
        assert result.exit_code == 0, result.output

    def test_file_nonempty(self, tmp_path):
        out = tmp_path / "out.docx"
        _gen(CliRunner(), "docx", "risk_report", str(out))
        assert out.stat().st_size > 0

    def test_txt_contains_risk_keywords(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "risk_report", str(out))
        content = out.read_text(encoding="utf-8").upper()
        assert any(kw in content for kw in ("LEI", "COUNTERPARTY", "CREDIT", "RISK",
                                             "CONTREPARTIE", "CRÉDIT", "RISQUE"))

    def test_txt_contains_iban_or_lei(self, tmp_path):
        out = tmp_path / "out.txt"
        _gen(CliRunner(), "txt", "risk_report", str(out), count=10)
        content = out.read_text(encoding="utf-8")
        # Risk report embeds LEI and/or IBAN
        assert "LEI" in content.upper() or "IBAN" in content.upper()


# ── template choice validation ────────────────────────────────────────────────

class TestTemplateChoices:
    @pytest.mark.parametrize("template", [
        "trade_confirmation", "swift_mt103", "settlement_instruction",
        "bloomberg_export", "risk_report",
    ])
    def test_template_accepted_by_cli(self, tmp_path, template):
        out = tmp_path / f"{template}.txt"
        result = CliRunner().invoke(main, [
            "generate", "--format", "txt", "--template", template,
            "--tier", "banking", "--count", "3", "--seed", "99",
            "--output", str(out),
        ])
        assert result.exit_code == 0, f"Template {template!r} rejected: {result.output}"
        assert out.stat().st_size > 0

    def test_unknown_template_rejected(self, tmp_path):
        result = CliRunner().invoke(main, [
            "generate", "--format", "txt", "--template", "not_a_real_template",
            "--tier", "banking", "--count", "3",
            "--output", str(tmp_path / "out.txt"),
        ])
        assert result.exit_code != 0

    def test_five_templates_produce_structurally_different_output(self, tmp_path):
        templates = [
            "trade_confirmation", "swift_mt103", "settlement_instruction",
            "bloomberg_export", "risk_report",
        ]
        outputs = {}
        for t in templates:
            out = tmp_path / f"{t}.txt"
            CliRunner().invoke(main, [
                "generate", "--format", "txt", "--template", t,
                "--tier", "banking", "--count", "5", "--seed", "42",
                "--output", str(out),
            ])
            outputs[t] = out.read_text(encoding="utf-8")
        # Each template must produce distinct output
        values = list(outputs.values())
        for i in range(len(values)):
            for j in range(i + 1, len(values)):
                assert values[i] != values[j], (
                    f"Templates {templates[i]!r} and {templates[j]!r} produced identical output"
                )
