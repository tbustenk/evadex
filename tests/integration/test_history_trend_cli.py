"""Integration tests for evadex history and evadex trend commands."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from evadex.cli.app import main


# ── Helpers ────────────────────────────────────────────────────────────────────

def _invoke(runner: CliRunner, args: list[str]):
    return runner.invoke(main, args)


def _write_audit(results_dir: Path, entries: list[dict]) -> None:
    audit = results_dir / "audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    with open(audit, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def _scan_entry(**kwargs) -> dict:
    defaults = {
        "timestamp": "2026-04-14T12:00:00+00:00",
        "type": "scan",
        "evadex_version": "3.2.0",
        "scanner_label": "test-scanner",
        "tool": "dlpscan-cli",
        "categories": ["credit_card"],
        "strategies": ["text"],
        "total": 100,
        "pass": 80,
        "fail": 20,
        "pass_rate": 80.0,
        "commit_hash": None,
        "archive_file": "results/scans/scan_20260414.json",
    }
    defaults.update(kwargs)
    return defaults


def _falsepos_entry(**kwargs) -> dict:
    defaults = {
        "timestamp": "2026-04-14T12:00:00+00:00",
        "type": "falsepos",
        "evadex_version": "3.2.0",
        "scanner_label": "test-scanner",
        "tool": "dlpscan-cli",
        "categories": ["credit_card"],
        "total_tested": 50,
        "total_flagged": 45,
        "fp_rate": 90.0,
        "commit_hash": None,
        "archive_file": "results/falsepos/fp_20260414.json",
    }
    defaults.update(kwargs)
    return defaults


# ── history command ─────────────────────────────────────────────────────────────

class TestHistory:
    def test_exits_zero_with_entries(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry()])
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir)])
        assert result.exit_code == 0, result.output

    def test_shows_scanner_label(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry(scanner_label="my-scanner-v2")])
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir)])
        assert "my-scanner-v2" in result.output

    def test_shows_pass_rate(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry(pass_rate=77.9)])
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir)])
        assert "77.9" in result.output

    def test_shows_type_column(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry(), _falsepos_entry()])
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir)])
        assert "scan" in result.output
        assert "falsepos" in result.output

    def test_filter_by_type_scan(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry(), _falsepos_entry()])
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir), "--type", "scan"])
        assert "scan" in result.output
        assert "falsepos" not in result.output

    def test_filter_by_type_falsepos(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry(), _falsepos_entry()])
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir), "--type", "falsepos"])
        assert "falsepos" in result.output
        # scan entries should not appear (they would show the word "scan" in type column)
        lines = [l for l in result.output.splitlines() if "scan" in l and "falsepos" not in l]
        assert len(lines) == 0

    def test_last_limits_entries(self, tmp_path):
        results_dir = tmp_path / "results"
        entries = [
            _scan_entry(timestamp=f"2026-04-{i:02d}T12:00:00+00:00", pass_rate=float(i))
            for i in range(1, 16)
        ]
        _write_audit(results_dir, entries)
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir), "--last", "5"])
        # Should show "5 entr" in the footer
        assert "5 entr" in result.output

    def test_no_audit_file_exits_zero(self, tmp_path):
        results_dir = tmp_path / "results"
        results_dir.mkdir(parents=True)
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir)])
        assert result.exit_code == 0

    def test_most_recent_first(self, tmp_path):
        """The --last N entries should be the most recent ones."""
        results_dir = tmp_path / "results"
        entries = [
            _scan_entry(
                timestamp=f"2026-04-{i:02d}T12:00:00+00:00",
                scanner_label=f"scanner-{i:02d}",
                pass_rate=float(i),
            )
            for i in range(1, 6)
        ]
        _write_audit(results_dir, entries)
        runner = CliRunner()
        result = _invoke(runner, ["history", "--results-dir", str(results_dir), "--last", "2"])
        # Most recent two are day 04 and 05
        assert "scanner-05" in result.output
        assert "scanner-04" in result.output
        assert "scanner-01" not in result.output


# ── trend command ────────────────────────────────────────────────────────────────

class TestTrend:
    def test_exits_zero_with_scan_entries(self, tmp_path):
        results_dir = tmp_path / "results"
        entries = [
            _scan_entry(timestamp=f"2026-04-{i:02d}T12:00:00+00:00", pass_rate=float(70 + i))
            for i in range(1, 6)
        ]
        _write_audit(results_dir, entries)
        runner = CliRunner()
        result = _invoke(runner, ["trend", "--results-dir", str(results_dir)])
        assert result.exit_code == 0, result.output

    def test_chart_title_mentions_detection_rate(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry()])
        runner = CliRunner()
        result = _invoke(runner, ["trend", "--results-dir", str(results_dir)])
        assert "Detection Rate" in result.output

    def test_falsepos_chart_title(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_falsepos_entry()])
        runner = CliRunner()
        result = _invoke(runner, ["trend", "--results-dir", str(results_dir), "--type", "falsepos"])
        assert "False Positive" in result.output

    def test_chart_contains_data_marker(self, tmp_path):
        results_dir = tmp_path / "results"
        entries = [
            _scan_entry(timestamp=f"2026-04-{i:02d}T12:00:00+00:00", pass_rate=float(70 + i))
            for i in range(1, 6)
        ]
        _write_audit(results_dir, entries)
        runner = CliRunner()
        result = _invoke(runner, ["trend", "--results-dir", str(results_dir)])
        assert "●" in result.output

    def test_scanner_label_filter(self, tmp_path):
        results_dir = tmp_path / "results"
        entries = [
            _scan_entry(scanner_label="rust", pass_rate=80.0),
            _scan_entry(scanner_label="python", pass_rate=90.0),
        ]
        _write_audit(results_dir, entries)
        runner = CliRunner()
        result = _invoke(runner, [
            "trend", "--results-dir", str(results_dir), "--scanner-label", "rust",
        ])
        assert result.exit_code == 0
        # Should report 1 data point (only the rust entry)
        assert "1 data point" in result.output

    def test_no_entries_after_filter_exits_zero(self, tmp_path):
        results_dir = tmp_path / "results"
        _write_audit(results_dir, [_scan_entry(scanner_label="python")])
        runner = CliRunner()
        result = _invoke(runner, [
            "trend", "--results-dir", str(results_dir), "--scanner-label", "rust",
        ])
        assert result.exit_code == 0

    def test_no_audit_file_exits_zero(self, tmp_path):
        results_dir = tmp_path / "results"
        results_dir.mkdir(parents=True)
        runner = CliRunner()
        result = _invoke(runner, ["trend", "--results-dir", str(results_dir)])
        assert result.exit_code == 0

    def test_last_limits_data_points(self, tmp_path):
        results_dir = tmp_path / "results"
        entries = [
            _scan_entry(timestamp=f"2026-04-{i:02d}T12:00:00+00:00", pass_rate=float(70 + i))
            for i in range(1, 11)
        ]
        _write_audit(results_dir, entries)
        runner = CliRunner()
        result = _invoke(runner, [
            "trend", "--results-dir", str(results_dir), "--last", "4",
        ])
        assert "4 data point" in result.output
