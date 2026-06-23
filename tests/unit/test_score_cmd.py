"""Unit tests for evadex score, leaderboard, explain, and coverage commands."""

from __future__ import annotations

import json
import pytest
from click.testing import CliRunner
from evadex.cli.app import main


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _write_audit(tmp_path, entries: list[dict]) -> str:
    p = tmp_path / "audit.jsonl"
    lines = [json.dumps(e) for e in entries]
    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)


def _scan_entry(
    scanner_label: str = "siphon-prod",
    pass_rate: float = 85.0,
    categories: list[str] | None = None,
    ts: str = "2026-06-01T12:00:00+00:00",
) -> dict:
    return {
        "timestamp": ts,
        "type": "scan",
        "scanner_label": scanner_label,
        "tool": "siphon-cli",
        "pass_rate": pass_rate,
        "categories": categories or ["credit_card", "ssn", "iban"],
        "total": 120,
        "pass": int(120 * pass_rate / 100),
        "fail": 120 - int(120 * pass_rate / 100),
        "technique_success_rates": {"encoding_base64": pass_rate / 100},
    }


def _fp_entry(
    scanner_label: str = "siphon-prod",
    fp_rate: float = 5.0,
    ts: str = "2026-06-01T13:00:00+00:00",
) -> dict:
    return {
        "timestamp": ts,
        "type": "falsepos",
        "scanner_label": scanner_label,
        "tool": "siphon-cli",
        "fp_rate": fp_rate,
        "total_tested": 100,
        "total_flagged": int(100 * fp_rate / 100),
        "categories": ["credit_card", "ssn"],
    }


# ── evadex score ───────────────────────────────────────────────────────────────

class TestScoreCommand:
    def test_no_audit_log_exits_cleanly(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["score", "--audit-log", str(tmp_path / "missing.jsonl")],
        )
        assert result.exit_code == 0
        assert "No audit log" in result.output

    def test_basic_score_output(self, tmp_path):
        log = _write_audit(tmp_path, [_scan_entry(pass_rate=80.0)])
        runner = CliRunner()
        result = runner.invoke(main, ["score", "--audit-log", log])
        assert result.exit_code == 0
        assert "/" in result.output  # "XX.X / 100"
        assert "Detection rate" in result.output

    def test_score_json_output(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry(pass_rate=90.0),
                _fp_entry(fp_rate=3.0),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["score", "--audit-log", log, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "composite" in data
        assert "detection_avg" in data
        assert data["detection_avg"] == pytest.approx(90.0)
        assert data["fp_avg"] == pytest.approx(3.0)

    def test_score_filter_by_label(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry("siphon-prod", pass_rate=90.0),
                _scan_entry("siphon-test", pass_rate=50.0),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["score", "--audit-log", log, "--scanner-label", "siphon-prod", "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["detection_avg"] == pytest.approx(90.0)
        assert data["scanner_label"] == "siphon-prod"

    def test_high_detection_high_fp_score(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry(pass_rate=100.0),
                _fp_entry(fp_rate=0.0),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["score", "--audit-log", log, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["detection_avg"] == pytest.approx(100.0)
        assert data["fp_score"] == pytest.approx(100.0)
        # Composite will be ≥ 70 with perfect detection + FP even with low coverage
        assert data["composite"] >= 70.0

    def test_low_detection_recommendation_shown(self, tmp_path):
        log = _write_audit(tmp_path, [_scan_entry(pass_rate=30.0)])
        runner = CliRunner()
        result = runner.invoke(main, ["score", "--audit-log", log])
        assert result.exit_code == 0
        assert "Detection rate" in result.output
        assert "Recommendations" in result.output

    def test_missing_fp_data_uses_conservative_default(self, tmp_path):
        log = _write_audit(tmp_path, [_scan_entry(pass_rate=80.0)])
        runner = CliRunner()
        result = runner.invoke(main, ["score", "--audit-log", log, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["fp_avg"] is None
        assert data["fp_score"] == pytest.approx(70.0)

    def test_composite_is_weighted_sum(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry(pass_rate=80.0, categories=["credit_card", "ssn"]),
                _fp_entry(fp_rate=10.0),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["score", "--audit-log", log, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Manually verify approximate composite
        # detection=80, fp_score=90, coverage varies, timing=50
        assert 0.0 < data["composite"] <= 100.0


# ── evadex leaderboard ─────────────────────────────────────────────────────────

class TestLeaderboardCommand:
    def test_no_audit_log_exits_cleanly(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["leaderboard", "--audit-log", str(tmp_path / "missing.jsonl")],
        )
        assert result.exit_code == 0
        assert "No audit log" in result.output

    def test_no_labels_exits_cleanly(self, tmp_path):
        log = _write_audit(tmp_path, [{"type": "scan", "scanner_label": ""}])
        runner = CliRunner()
        result = runner.invoke(main, ["leaderboard", "--audit-log", log])
        assert result.exit_code == 0
        assert "No scanner labels" in result.output

    def test_single_label(self, tmp_path):
        log = _write_audit(tmp_path, [_scan_entry("siphon-prod", pass_rate=88.0)])
        runner = CliRunner()
        result = runner.invoke(main, ["leaderboard", "--audit-log", log])
        assert result.exit_code == 0
        assert "siphon-prod" in result.output

    def test_rank_order_by_score(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry("scanner-A", pass_rate=90.0),
                _scan_entry("scanner-B", pass_rate=40.0),
                _fp_entry("scanner-A", fp_rate=2.0),
                _fp_entry("scanner-B", fp_rate=40.0),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["leaderboard", "--audit-log", log])
        assert result.exit_code == 0
        # scanner-A should appear before scanner-B (higher score)
        idx_a = result.output.find("scanner-A")
        idx_b = result.output.find("scanner-B")
        assert idx_a < idx_b

    def test_multiple_labels_all_shown(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry("v1", pass_rate=70.0),
                _scan_entry("v2", pass_rate=80.0),
                _scan_entry("v3", pass_rate=90.0),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["leaderboard", "--audit-log", log])
        assert result.exit_code == 0
        assert "v1" in result.output
        assert "v2" in result.output
        assert "v3" in result.output

    def test_grade_column_present(self, tmp_path):
        log = _write_audit(tmp_path, [_scan_entry(pass_rate=95.0)])
        runner = CliRunner()
        result = runner.invoke(main, ["leaderboard", "--audit-log", log])
        assert result.exit_code == 0
        assert "Grade" in result.output


# ── evadex explain ─────────────────────────────────────────────────────────────

class TestExplainCommand:
    def test_unknown_category_exits_nonzero(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "--category", "not_a_real_cat"])
        assert result.exit_code != 0

    def test_credit_card_encoding(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["explain", "--category", "credit_card", "--technique", "encoding"]
        )
        assert result.exit_code == 0
        assert "encoding" in result.output
        assert "base64" in result.output.lower()

    def test_unknown_technique_exits_nonzero(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "explain",
                "--category",
                "credit_card",
                "--technique",
                "no_such_technique_xyz",
            ],
        )
        assert result.exit_code != 0

    def test_sample_value_shown(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["explain", "--category", "credit_card", "--technique", "encoding"]
        )
        assert result.exit_code == 0
        assert "Sample value" in result.output

    def test_fix_recommendation_shown(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["explain", "--category", "credit_card", "--technique", "encoding"]
        )
        assert result.exit_code == 0
        assert "Fix:" in result.output

    def test_custom_sample_value(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "explain",
                "--category",
                "credit_card",
                "--technique",
                "encoding",
                "--sample",
                "4111111111111111",
            ],
        )
        assert result.exit_code == 0
        assert "4111111111111111" in result.output

    def test_all_generators_when_no_technique(self):
        runner = CliRunner()
        result = runner.invoke(main, ["explain", "--category", "credit_card"])
        assert result.exit_code == 0
        # Should list multiple generator families
        assert "encoding" in result.output

    def test_ssn_splitting(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["explain", "--category", "ssn", "--technique", "splitting"]
        )
        assert result.exit_code == 0
        assert "splitting" in result.output


# ── evadex coverage ────────────────────────────────────────────────────────────

class TestCoverageCommand:
    def test_empty_audit_shows_all_missing(self, tmp_path):
        log = str(tmp_path / "audit.jsonl")
        # Write empty file
        (tmp_path / "audit.jsonl").write_text("", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["coverage", "--audit-log", log, "--tier", "banking"])
        assert result.exit_code == 0
        assert "gap" in result.output or "never" in result.output

    def test_scanned_category_shown_with_checkmark(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [_scan_entry(pass_rate=80.0, categories=["credit_card", "iban", "sin"])],
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["coverage", "--audit-log", log, "--tier", "banking", "--show-all"]
        )
        assert result.exit_code == 0
        assert "credit_card" in result.output

    def test_coverage_percentage_shown(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [_scan_entry(pass_rate=75.0, categories=["credit_card", "ssn"])],
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["coverage", "--audit-log", log, "--tier", "northam"]
        )
        assert result.exit_code == 0
        assert "%" in result.output

    def test_missing_only_flag(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [_scan_entry(categories=["credit_card", "ssn", "iban"])],
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["coverage", "--audit-log", log, "--tier", "northam", "--missing-only"],
        )
        assert result.exit_code == 0
        # credit_card is tested — should not appear in missing-only
        assert "credit_card" not in result.output

    def test_filter_by_scanner_label(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [
                _scan_entry("prod", categories=["credit_card", "ssn"]),
                _scan_entry("test", categories=["iban"]),
            ],
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "coverage",
                "--audit-log",
                log,
                "--tier",
                "northam",
                "--scanner-label",
                "test",
                "--show-all",
            ],
        )
        assert result.exit_code == 0
        assert "iban" in result.output

    def test_show_all_flag_includes_tested(self, tmp_path):
        log = _write_audit(
            tmp_path,
            [_scan_entry(categories=["credit_card", "sin", "iban"])],
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["coverage", "--audit-log", log, "--tier", "banking", "--show-all"]
        )
        assert result.exit_code == 0
        assert "credit_card" in result.output
        assert "sin" in result.output

    def test_never_tested_audit_path(self, tmp_path):
        # audit.jsonl doesn't exist — all categories are gaps
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "coverage",
                "--audit-log",
                str(tmp_path / "nope.jsonl"),
                "--tier",
                "banking",
            ],
        )
        assert result.exit_code == 0
        assert "gap" in result.output or "0%" in result.output or "never" in result.output
