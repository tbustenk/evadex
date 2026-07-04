"""Unit tests for evadex report — risk rating, compliance, and trend section."""

from __future__ import annotations

import json

from click.testing import CliRunner

from evadex.cli.app import main
from evadex.cli.commands.report import (
    _risk_rating,
    _trend_section,
)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _scan_doc(pass_rate: float = 80.0, scanner: str = "siphon-prod") -> dict:
    total = 100
    passes = int(total * pass_rate / 100)
    fails = total - passes
    return {
        "meta": {
            "scanner": scanner,
            "total": total,
            "pass": passes,
            "fail": fails,
            "error": 0,
            "pass_rate": pass_rate,
            "timestamp": "2026-06-01T12:00:00+00:00",
            "summary_by_category": {
                "credit_card": {"pass": 3, "fail": 7, "error": 0},
                "iban": {"pass": 9, "fail": 1, "error": 0},
            },
            "summary_by_technique": {
                "zwsp_mid": {"pass": 1, "fail": 19, "error": 0},
            },
        },
        "results": [],
    }


def _audit_scan_entry(pass_rate: float, ts: str, label: str = "siphon-prod") -> dict:
    return {
        "timestamp": ts,
        "type": "scan",
        "scanner_label": label,
        "pass_rate": pass_rate,
        "total": 100,
        "pass": int(pass_rate),
        "fail": 100 - int(pass_rate),
    }


# ── Risk rating ─────────────────────────────────────────────────────────────


class TestRiskRating:
    def test_low_risk_high_detection(self):
        assert _risk_rating(95.0) == ("LOW", "good")

    def test_medium_risk(self):
        # 60% detection → 40% bypass → MEDIUM
        assert _risk_rating(60.0)[0] == "MEDIUM"

    def test_high_risk(self):
        assert _risk_rating(40.0)[0] == "HIGH"

    def test_critical_risk(self):
        assert _risk_rating(20.0)[0] == "CRITICAL"


# ── Trend section ───────────────────────────────────────────────────────────


class TestTrendSection:
    def test_empty_when_no_audit_file(self, tmp_path):
        assert _trend_section(tmp_path / "missing.jsonl", "siphon-prod") == ""

    def test_empty_with_single_run(self, tmp_path):
        audit = tmp_path / "audit.jsonl"
        audit.write_text(
            json.dumps(_audit_scan_entry(80.0, "2026-06-01T00:00:00+00:00")),
            encoding="utf-8",
        )
        assert _trend_section(audit, "siphon-prod") == ""

    def test_renders_svg_with_two_runs(self, tmp_path):
        audit = tmp_path / "audit.jsonl"
        audit.write_text(
            "\n".join(
                json.dumps(e)
                for e in [
                    _audit_scan_entry(70.0, "2026-06-01T00:00:00+00:00"),
                    _audit_scan_entry(82.0, "2026-06-02T00:00:00+00:00"),
                ]
            ),
            encoding="utf-8",
        )
        html = _trend_section(audit, "siphon-prod")
        assert "<svg" in html
        assert "<polyline" in html
        # 82 - 70 = +12.0, detection improved
        assert "▲ 12.0%" in html
        assert "improved" in html

    def test_regression_shows_down_arrow(self, tmp_path):
        audit = tmp_path / "audit.jsonl"
        audit.write_text(
            "\n".join(
                json.dumps(e)
                for e in [
                    _audit_scan_entry(82.0, "2026-06-01T00:00:00+00:00"),
                    _audit_scan_entry(70.0, "2026-06-02T00:00:00+00:00"),
                ]
            ),
            encoding="utf-8",
        )
        html = _trend_section(audit, "siphon-prod")
        assert "▼" in html
        assert "regressed" in html

    def test_falls_back_to_all_labels(self, tmp_path):
        # Only one run for the requested scanner, but two overall → still draws.
        audit = tmp_path / "audit.jsonl"
        audit.write_text(
            "\n".join(
                json.dumps(e)
                for e in [
                    _audit_scan_entry(70.0, "2026-06-01T00:00:00+00:00", "other"),
                    _audit_scan_entry(82.0, "2026-06-02T00:00:00+00:00", "siphon-prod"),
                ]
            ),
            encoding="utf-8",
        )
        html = _trend_section(audit, "siphon-prod")
        assert "<svg" in html


# ── End-to-end CLI ──────────────────────────────────────────────────────────


class TestReportCli:
    def test_report_includes_trend_when_history_present(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            scan_path = "scan.json"
            with open(scan_path, "w", encoding="utf-8") as fh:
                json.dump(_scan_doc(pass_rate=40.0), fh)
            audit_path = "audit.jsonl"
            with open(audit_path, "w", encoding="utf-8") as fh:
                fh.write(
                    "\n".join(
                        json.dumps(e)
                        for e in [
                            _audit_scan_entry(35.0, "2026-05-01T00:00:00+00:00"),
                            _audit_scan_entry(40.0, "2026-06-01T00:00:00+00:00"),
                        ]
                    )
                )
            result = runner.invoke(
                main,
                ["report", scan_path, "--history", audit_path, "-o", "out.html"],
            )
            assert result.exit_code == 0, result.output
            html = open("out.html", encoding="utf-8").read()
            assert "Detection Trend" in html
            assert "Risk Rating" in html
            assert "HIGH" in html  # 40% detection → 60% bypass → HIGH
            assert "Compliance Mapping" in html

    def test_report_without_history_omits_trend(self, tmp_path):
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            scan_path = "scan.json"
            with open(scan_path, "w", encoding="utf-8") as fh:
                json.dump(_scan_doc(pass_rate=90.0), fh)
            result = runner.invoke(main, ["report", scan_path, "-o", "out.html"])
            assert result.exit_code == 0, result.output
            html = open("out.html", encoding="utf-8").read()
            assert "Detection Trend" not in html
