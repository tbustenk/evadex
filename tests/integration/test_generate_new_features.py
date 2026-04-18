"""Integration tests for new evadex generate features — formats, granular options, templates."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

import pytest
from click.testing import CliRunner

from evadex.cli.app import main


# ── Helpers ────────────────────────────────────────────────────────────────────

def _invoke(runner: CliRunner, args: list[str]):
    return runner.invoke(main, ["generate"] + args)


def _base_args(fmt: str, output: str, count: int = 5) -> list[str]:
    return [
        "--format", fmt,
        "--category", "credit_card",
        "--count", str(count),
        "--seed", "42",
        "--output", output,
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Part 1 — New file format tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEmlFormat:
    def test_exits_zero(self, tmp_path):
        result = _invoke(CliRunner(), _base_args("eml", str(tmp_path / "out.eml")))
        assert result.exit_code == 0, result.output

    def test_file_created_nonempty(self, tmp_path):
        out = tmp_path / "out.eml"
        _invoke(CliRunner(), _base_args("eml", str(out)))
        assert out.exists()
        assert out.stat().st_size > 0

    def test_contains_email_headers(self, tmp_path):
        out = tmp_path / "out.eml"
        _invoke(CliRunner(), _base_args("eml", str(out)))
        content = out.read_text(encoding="utf-8")
        assert "From:" in content
        assert "To:" in content
        assert "Subject:" in content

    def test_contains_sensitive_value(self, tmp_path):
        out = tmp_path / "out.eml"
        _invoke(CliRunner(), _base_args("eml", str(out), count=3))
        content = out.read_text(encoding="utf-8")
        # Should contain at least one card-like value (digits)
        assert any(c.isdigit() for c in content)


class TestMsgFormat:
    def test_exits_zero(self, tmp_path):
        result = _invoke(CliRunner(), _base_args("msg", str(tmp_path / "out.msg")))
        assert result.exit_code == 0, result.output

    def test_file_created_nonempty(self, tmp_path):
        out = tmp_path / "out.msg"
        _invoke(CliRunner(), _base_args("msg", str(out)))
        assert out.exists()
        assert out.stat().st_size > 0


class TestJsonFormat:
    def test_exits_zero(self, tmp_path):
        result = _invoke(CliRunner(), _base_args("json", str(tmp_path / "out.json")))
        assert result.exit_code == 0, result.output

    def test_file_is_valid_json(self, tmp_path):
        out = tmp_path / "out.json"
        _invoke(CliRunner(), _base_args("json", str(out), count=3))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == 3

    def test_records_have_expected_fields(self, tmp_path):
        out = tmp_path / "out.json"
        _invoke(CliRunner(), _base_args("json", str(out), count=2))
        data = json.loads(out.read_text(encoding="utf-8"))
        for rec in data:
            assert "customer_id" in rec
            assert "name" in rec
            assert "card_number" in rec


class TestXmlFormat:
    def test_exits_zero(self, tmp_path):
        result = _invoke(CliRunner(), _base_args("xml", str(tmp_path / "out.xml")))
        assert result.exit_code == 0, result.output

    def test_file_is_valid_xml(self, tmp_path):
        import xml.etree.ElementTree as ET
        out = tmp_path / "out.xml"
        _invoke(CliRunner(), _base_args("xml", str(out), count=2))
        tree = ET.parse(str(out))
        root = tree.getroot()
        assert "Document" in root.tag

    def test_contains_payment_elements(self, tmp_path):
        out = tmp_path / "out.xml"
        _invoke(CliRunner(), _base_args("xml", str(out), count=2))
        content = out.read_text(encoding="utf-8")
        assert "<PmtInf>" in content
        assert "<Amt" in content


class TestSqlFormat:
    def test_exits_zero(self, tmp_path):
        result = _invoke(CliRunner(), _base_args("sql", str(tmp_path / "out.sql")))
        assert result.exit_code == 0, result.output

    def test_file_contains_insert_statements(self, tmp_path):
        out = tmp_path / "out.sql"
        _invoke(CliRunner(), _base_args("sql", str(out), count=3))
        content = out.read_text(encoding="utf-8")
        assert "INSERT INTO customers" in content
        assert "CREATE TABLE" in content

    def test_correct_row_count(self, tmp_path):
        out = tmp_path / "out.sql"
        _invoke(CliRunner(), _base_args("sql", str(out), count=5))
        content = out.read_text(encoding="utf-8")
        assert "5 rows inserted" in content


class TestLogFormat:
    def test_exits_zero(self, tmp_path):
        result = _invoke(CliRunner(), _base_args("log", str(tmp_path / "out.log")))
        assert result.exit_code == 0, result.output

    def test_file_has_log_lines(self, tmp_path):
        out = tmp_path / "out.log"
        _invoke(CliRunner(), _base_args("log", str(out), count=5))
        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 5

    def test_contains_timestamps(self, tmp_path):
        out = tmp_path / "out.log"
        _invoke(CliRunner(), _base_args("log", str(out), count=3))
        content = out.read_text(encoding="utf-8")
        assert "2026-04-17" in content


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2 — Granular amount option tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCountPerCategory:
    def test_overrides_correctly(self, tmp_path):
        out = tmp_path / "out.csv"
        _invoke(CliRunner(), [
            "--format", "csv",
            "--category", "credit_card", "--category", "sin",
            "--count", "5", "--seed", "42",
            "--count-per-category", "credit_card:10",
            "--count-per-category", "sin:3",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        cats = Counter(r["category"] for r in rows)
        assert cats["credit_card"] == 10
        assert cats["sin"] == 3


class TestTotal:
    def test_distributes_correctly(self, tmp_path):
        out = tmp_path / "out.csv"
        _invoke(CliRunner(), [
            "--format", "csv",
            "--category", "credit_card", "--category", "sin",
            "--total", "20", "--seed", "42",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 20
        cats = Counter(r["category"] for r in rows)
        assert cats["credit_card"] == 10
        assert cats["sin"] == 10

    def test_odd_total_distributes(self, tmp_path):
        out = tmp_path / "out.csv"
        _invoke(CliRunner(), [
            "--format", "csv",
            "--category", "credit_card", "--category", "sin",
            "--total", "7", "--seed", "42",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 7


class TestDensity:
    def test_density_flag_accepted(self, tmp_path):
        out = tmp_path / "out.csv"
        result = _invoke(CliRunner(), [
            "--format", "csv", "--category", "credit_card",
            "--count", "5", "--seed", "42",
            "--density", "high",
            "--output", str(out),
        ])
        assert result.exit_code == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Part 3 — Granular evasion option tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTechniqueGroup:
    def test_filters_to_single_generator(self, tmp_path):
        out = tmp_path / "out.csv"
        _invoke(CliRunner(), [
            "--format", "csv", "--category", "credit_card",
            "--count", "20", "--seed", "42",
            "--evasion-rate", "1.0",
            "--technique-group", "delimiter",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        generators = {r["generator"] for r in rows if r["generator"]}
        assert generators == {"delimiter"}


class TestTechniqueMix:
    def test_validates_sum(self, tmp_path):
        out = tmp_path / "out.csv"
        result = _invoke(CliRunner(), [
            "--format", "csv", "--category", "credit_card",
            "--count", "5",
            "--technique-mix", "unicode_encoding:0.5,delimiter:0.3",
            "--output", str(out),
        ])
        assert result.exit_code != 0
        assert "sum to 1.0" in result.output

    def test_valid_mix_accepted(self, tmp_path):
        out = tmp_path / "out.csv"
        result = _invoke(CliRunner(), [
            "--format", "csv", "--category", "credit_card",
            "--count", "20", "--seed", "42",
            "--evasion-rate", "1.0",
            "--technique-mix", "unicode_encoding:0.5,delimiter:0.3,encoding:0.2",
            "--output", str(out),
        ])
        assert result.exit_code == 0


class TestEvasionPerCategory:
    def test_different_rates(self, tmp_path):
        out = tmp_path / "out.csv"
        _invoke(CliRunner(), [
            "--format", "csv",
            "--category", "credit_card", "--category", "sin",
            "--count", "30", "--seed", "42",
            "--evasion-rate", "0.0",
            "--evasion-per-category", "credit_card:1.0",
            "--output", str(out),
        ])
        with open(out, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        cc = [r for r in rows if r["category"] == "credit_card"]
        sin = [r for r in rows if r["category"] == "sin"]
        # CC should all have evasion, SIN should have none
        assert all(r["technique"] != "" for r in cc)
        assert all(r["technique"] == "" for r in sin)


# ═══════════════════════════════════════════════════════════════════════════════
# Part 4 — Template and noise tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTemplates:
    @pytest.mark.parametrize("template", [
        "invoice", "statement", "hr_record", "audit_report",
        "source_code", "config_file", "chat_log", "medical_record",
    ])
    def test_template_produces_nonempty_output(self, tmp_path, template):
        out = tmp_path / f"{template}.txt"
        result = _invoke(CliRunner(), [
            "--format", "txt", "--category", "credit_card",
            "--count", "3", "--seed", "42",
            "--template", template,
            "--output", str(out),
        ])
        assert result.exit_code == 0, result.output
        assert out.stat().st_size > 0

    def test_templates_produce_structurally_different_output(self, tmp_path):
        outputs = {}
        for template in ["generic", "invoice", "source_code", "chat_log"]:
            out = tmp_path / f"{template}.txt"
            _invoke(CliRunner(), [
                "--format", "txt", "--category", "credit_card",
                "--count", "3", "--seed", "42",
                "--template", template,
                "--output", str(out),
            ])
            outputs[template] = out.read_text(encoding="utf-8")
        # All outputs should be different from each other
        values = list(outputs.values())
        for i in range(len(values)):
            for j in range(i + 1, len(values)):
                assert values[i] != values[j]


class TestNoiseLevel:
    def test_noise_levels_accepted(self, tmp_path):
        for level in ["low", "medium", "high"]:
            out = tmp_path / f"noise_{level}.txt"
            result = _invoke(CliRunner(), [
                "--format", "txt", "--category", "credit_card",
                "--count", "3", "--seed", "42",
                "--template", "audit_report",
                "--noise-level", level,
                "--output", str(out),
            ])
            assert result.exit_code == 0, f"noise-level={level} failed: {result.output}"
