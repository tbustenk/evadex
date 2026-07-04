"""Unit tests for evadex export command."""
import csv
import io
import json
import pytest
from click.testing import CliRunner
from evadex.cli.app import main


def _make_result(detected: bool, category: str = "credit_card",
                 technique: str = "uppercase", confidence: float | None = None) -> dict:
    r = {
        "payload": {"value": "4532015112830366", "category": category,
                    "category_type": "structured", "label": "Visa"},
        "variant": {"value": "4532015112830366", "generator": "structural",
                    "technique": technique, "transform_name": "Upper", "strategy": "text"},
        "detected": detected,
        "severity": "pass" if detected else "fail",
        "duration_ms": 1.0,
        "error": None,
        "raw_response": {},
    }
    if confidence is not None:
        r["confidence"] = confidence
    return r


def _make_scan_file(tmp_path, results: list[dict]) -> str:
    data = {
        "meta": {
            "scanner": "test-scanner",
            "total": len(results),
            "pass": sum(1 for r in results if r["detected"]),
            "fail": sum(1 for r in results if not r["detected"]),
            "error": 0,
            "pass_rate": 50.0,
        },
        "results": results,
    }
    p = tmp_path / "scan.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


class TestExportCsv:
    def test_csv_header(self, tmp_path):
        f = _make_scan_file(tmp_path, [_make_result(True)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", f, "--format", "csv"])
        assert result.exit_code == 0
        rows = list(csv.reader(io.StringIO(result.output)))
        assert rows[0] == ["category", "technique", "value", "detected", "confidence"]

    def test_csv_row_count(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True), _make_result(False)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "csv"])
        assert result.exit_code == 0
        rows = list(csv.reader(io.StringIO(result.output)))
        assert len(rows) == 3  # header + 2 data rows

    def test_csv_detected_column(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True), _make_result(False)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "csv"])
        assert result.exit_code == 0
        rows = list(csv.reader(io.StringIO(result.output)))
        assert rows[1][3] == "True"
        assert rows[2][3] == "False"

    def test_csv_confidence_present(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True, confidence=0.95)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "csv"])
        assert result.exit_code == 0
        rows = list(csv.reader(io.StringIO(result.output)))
        assert rows[1][4] == "0.95"

    def test_csv_write_to_file(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True)])
        out = str(tmp_path / "out.csv")
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "csv", "--output", out])
        assert result.exit_code == 0
        content = open(out, encoding="utf-8").read()
        assert "category" in content

    def test_only_bypassed_filters_detected(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True), _make_result(False)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "csv", "--only-bypassed"])
        assert result.exit_code == 0
        rows = list(csv.reader(io.StringIO(result.output)))
        # header + 1 bypassed row
        assert len(rows) == 2
        assert rows[1][3] == "False"


class TestExportMarkdown:
    def test_markdown_has_table(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "markdown"])
        assert result.exit_code == 0
        assert "| Category |" in result.output
        assert "|---|" in result.output

    def test_markdown_has_header_line(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "markdown"])
        assert result.exit_code == 0
        assert "# evadex Export" in result.output

    def test_markdown_shows_detection_rate(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "markdown"])
        assert result.exit_code == 0
        assert "Detection rate:" in result.output

    def test_markdown_confidence_dash_when_absent(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True)])
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "markdown"])
        assert result.exit_code == 0
        assert "—" in result.output


class TestExportParquet:
    @pytest.fixture(autouse=True)
    def _require_parquet_deps(self):
        # Parquet export lives behind the optional `data-formats` extra
        # (pyarrow + pandas). The default `.[dev]` CI install omits it, so
        # skip these cases cleanly instead of failing with ModuleNotFoundError.
        pytest.importorskip("pandas")
        pytest.importorskip("pyarrow")

    def test_parquet_creates_file(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True), _make_result(False)])
        out = str(tmp_path / "out.parquet")
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "parquet", "--output", out])
        assert result.exit_code == 0
        import pathlib
        assert pathlib.Path(out).exists()

    def test_parquet_row_count(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True), _make_result(False), _make_result(True)])
        out = str(tmp_path / "out.parquet")
        runner = CliRunner()
        result = runner.invoke(main, ["export", scan, "--format", "parquet", "--output", out])
        assert result.exit_code == 0
        import pandas as pd
        df = pd.read_parquet(out)
        assert len(df) == 3

    def test_parquet_detected_column(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True), _make_result(False)])
        out = str(tmp_path / "out.parquet")
        runner = CliRunner()
        runner.invoke(main, ["export", scan, "--format", "parquet", "--output", out])
        import pandas as pd
        df = pd.read_parquet(out)
        assert df["detected"].dtype == bool
        assert list(df["detected"]) == [True, False]

    def test_parquet_default_filename(self, tmp_path):
        scan = _make_scan_file(tmp_path, [_make_result(True)])
        runner = CliRunner()
        import os
        orig = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = runner.invoke(main, ["export", scan, "--format", "parquet"])
        finally:
            os.chdir(orig)
        assert result.exit_code == 0
        assert (tmp_path / "evadex_export.parquet").exists()


class TestExportErrors:
    def test_missing_file_exits_nonzero(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["export", str(tmp_path / "nope.json")])
        assert result.exit_code != 0

    def test_invalid_json_exits_nonzero(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["export", str(p)])
        assert result.exit_code != 0

    def test_non_evadex_file_exits_nonzero(self, tmp_path):
        p = tmp_path / "other.json"
        p.write_text('{"foo": "bar"}', encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["export", str(p)])
        assert result.exit_code != 0
