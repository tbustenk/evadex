"""Unit tests for evadex techniques command — --export and --compare flags."""
import csv
import io
import json
import pytest
from click.testing import CliRunner
from evadex.cli.app import main


def _write_audit(tmp_path, entries: list[dict]) -> str:
    p = tmp_path / "audit.jsonl"
    lines = [json.dumps(e) for e in entries]
    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)


def _audit_entry(scanner_label: str, rates: dict) -> dict:
    return {
        "timestamp": "2026-05-25T12:00:00+00:00",
        "scanner_label": scanner_label,
        "tool": "siphon-cli",
        "technique_success_rates": rates,
    }


class TestTechniquesExport:
    def test_export_csv_created(self, tmp_path):
        log = _write_audit(tmp_path, [
            _audit_entry("v1", {"unicode_zwsp": 0.8, "encoding_base64": 0.4}),
        ])
        out = str(tmp_path / "techs.csv")
        runner = CliRunner()
        result = runner.invoke(
            main, ["techniques", "--audit-log", log, "--export", out]
        )
        assert result.exit_code == 0
        content = open(out, encoding="utf-8").read()
        rows = list(csv.reader(io.StringIO(content)))
        assert rows[0] == ["technique", "latest_rate", "avg_rate", "runs", "trend_delta"]
        assert len(rows) == 3  # header + 2 techniques

    def test_export_csv_values(self, tmp_path):
        log = _write_audit(tmp_path, [
            _audit_entry("v1", {"encoding_base64": 0.5}),
        ])
        out = str(tmp_path / "out.csv")
        runner = CliRunner()
        runner.invoke(main, ["techniques", "--audit-log", log, "--export", out])
        content = open(out, encoding="utf-8").read()
        rows = list(csv.reader(io.StringIO(content)))
        data_row = rows[1]
        assert data_row[0] == "encoding_base64"
        assert float(data_row[1]) == pytest.approx(50.0)


class TestTechniquesCompare:
    def test_compare_shows_both_labels(self, tmp_path):
        log = _write_audit(tmp_path, [
            _audit_entry("pre-fix", {"unicode_zwsp": 0.3}),
            _audit_entry("post-fix", {"unicode_zwsp": 0.8}),
        ])
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["techniques", "--audit-log", log, "--compare", "pre-fix", "post-fix"],
        )
        assert result.exit_code == 0
        assert "pre-fix" in result.output
        assert "post-fix" in result.output

    def test_compare_shows_technique_name(self, tmp_path):
        log = _write_audit(tmp_path, [
            _audit_entry("a", {"encoding_base64": 0.4}),
            _audit_entry("b", {"encoding_base64": 0.9}),
        ])
        runner = CliRunner()
        result = runner.invoke(
            main, ["techniques", "--audit-log", log, "--compare", "a", "b"]
        )
        assert result.exit_code == 0
        assert "encoding_base64" in result.output

    def test_compare_no_history_exits_cleanly(self, tmp_path):
        log = _write_audit(tmp_path, [
            _audit_entry("other", {"encoding_base64": 0.4}),
        ])
        runner = CliRunner()
        result = runner.invoke(
            main, ["techniques", "--audit-log", log, "--compare", "x", "y"]
        )
        assert result.exit_code == 0
        assert "No technique history" in result.output

    def test_compare_export_csv(self, tmp_path):
        log = _write_audit(tmp_path, [
            _audit_entry("pre", {"unicode_zwsp": 0.3}),
            _audit_entry("post", {"unicode_zwsp": 0.7}),
        ])
        out = str(tmp_path / "compare.csv")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["techniques", "--audit-log", log, "--compare", "pre", "post",
             "--export", out],
        )
        assert result.exit_code == 0
        content = open(out, encoding="utf-8").read()
        rows = list(csv.reader(io.StringIO(content)))
        assert rows[0][0] == "technique"
        assert "pre_rate" in rows[0][1]
        assert "post_rate" in rows[0][2]


class TestTechniqueHistoryScanner:
    def test_scanner_label_filter(self, tmp_path):
        from evadex.feedback.technique_history import load_technique_history
        log = _write_audit(tmp_path, [
            _audit_entry("siphon-pre", {"tech_a": 0.2}),
            _audit_entry("siphon-post", {"tech_a": 0.8}),
        ])
        stats_pre = load_technique_history(str(log), scanner_label="siphon-pre")
        stats_post = load_technique_history(str(log), scanner_label="siphon-post")
        assert stats_pre["tech_a"].latest_success == pytest.approx(0.2)
        assert stats_post["tech_a"].latest_success == pytest.approx(0.8)

    def test_no_filter_aggregates_all(self, tmp_path):
        from evadex.feedback.technique_history import load_technique_history
        log = _write_audit(tmp_path, [
            _audit_entry("a", {"tech_x": 0.4}),
            _audit_entry("b", {"tech_x": 0.6}),
        ])
        stats = load_technique_history(str(log))
        assert stats["tech_x"].runs == 2
