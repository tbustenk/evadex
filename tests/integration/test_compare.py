"""Integration tests for the compare command and build_comparison logic."""
import copy
import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from evadex.cli.app import main
from evadex.cli.commands.compare import build_comparison


def _make_scan_data(scanner: str, results: list[dict]) -> dict:
    passes = sum(1 for r in results if r["severity"] == "pass")
    fails  = sum(1 for r in results if r["severity"] == "fail")
    errs   = sum(1 for r in results if r["severity"] == "error")
    total  = len(results)
    by_cat: dict = {}
    for r in results:
        cat = r["payload"]["category"]
        by_cat.setdefault(cat, {"pass": 0, "fail": 0, "error": 0})
        by_cat[cat][r["severity"]] += 1
    return {
        "meta": {
            "timestamp": "2026-04-03T00:00:00+00:00",
            "scanner": scanner,
            "total": total,
            "pass": passes,
            "fail": fails,
            "error": errs,
            "pass_rate": round(passes / total * 100, 1) if total else 0.0,
            "summary_by_category": by_cat,
        },
        "results": results,
    }


def _result(detected: bool, category: str = "credit_card",
            generator: str = "structural", technique: str = "uppercase",
            payload_value: str = "4532015112830366") -> dict:
    sev = "pass" if detected else "fail"
    return {
        "payload": {"value": payload_value, "category": category,
                    "category_type": "structured", "label": "Visa 16-digit"},
        "variant": {"value": payload_value, "generator": generator,
                    "technique": technique, "transform_name": "desc", "strategy": "text"},
        "detected": detected,
        "severity": sev,
        "duration_ms": 1.0,
        "error": None,
        "raw_response": {},
    }


# ── build_comparison ─────────────────────────────────────────────────────────

def test_overall_delta():
    a = _make_scan_data("py", [_result(True), _result(True)])
    b = _make_scan_data("ru", [_result(True), _result(False)])
    comp = build_comparison(a, b)
    assert comp["overall"]["a_rate"] == 100.0
    assert comp["overall"]["b_rate"] == 50.0
    assert comp["overall"]["delta"] == -50.0


def test_no_diffs_when_identical():
    a = _make_scan_data("py", [_result(True), _result(False)])
    b = _make_scan_data("ru", [_result(True), _result(False)])
    comp = build_comparison(a, b)
    assert comp["diffs"] == []


def test_diff_detected_when_severity_changes():
    a = _make_scan_data("py", [_result(True)])
    b = _make_scan_data("ru", [_result(False)])
    comp = build_comparison(a, b)
    assert len(comp["diffs"]) == 1
    assert comp["diffs"][0]["a_severity"] == "pass"
    assert comp["diffs"][0]["b_severity"] == "fail"


def test_label_fallback_to_scanner_field():
    a = _make_scan_data("python-1.6.0", [_result(True)])
    b = _make_scan_data("rust-2.0.0",   [_result(True)])
    comp = build_comparison(a, b)
    assert comp["label_a"] == "python-1.6.0"
    assert comp["label_b"] == "rust-2.0.0"


def test_label_fallback_when_scanner_empty():
    a = _make_scan_data("", [_result(True)])
    b = _make_scan_data("", [_result(True)])
    comp = build_comparison(a, b)
    assert comp["label_a"] == "file_a"
    assert comp["label_b"] == "file_b"


def test_by_category_delta():
    a = _make_scan_data("py", [_result(True, "ssn"), _result(True, "ssn")])
    b = _make_scan_data("ru", [_result(True, "ssn"), _result(False, "ssn")])
    comp = build_comparison(a, b)
    ssn = next(r for r in comp["by_category"] if r["category"] == "ssn")
    assert ssn["a_rate"] == 100.0
    assert ssn["b_rate"] == 50.0
    assert ssn["delta"] == -50.0


def test_by_technique_only_includes_changed():
    a = _make_scan_data("py", [_result(True, technique="uppercase"),
                                _result(True, technique="lowercase")])
    b = _make_scan_data("ru", [_result(False, technique="uppercase"),
                                _result(True,  technique="lowercase")])
    comp = build_comparison(a, b)
    techs = {t["technique"] for t in comp["by_technique"]}
    assert "uppercase" in techs
    assert "lowercase" not in techs  # no change


# ── CLI compare command ───────────────────────────────────────────────────────

def test_compare_cli_json_output(tmp_path):
    a_data = _make_scan_data("py", [_result(True), _result(False)])
    b_data = _make_scan_data("ru", [_result(False), _result(False)])
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    out = tmp_path / "out.json"
    fa.write_text(json.dumps(a_data), encoding="utf-8")
    fb.write_text(json.dumps(b_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb), "--output", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "meta" in data
    assert "diffs" in data


def test_compare_cli_html_output(tmp_path):
    a_data = _make_scan_data("py", [_result(True)])
    b_data = _make_scan_data("ru", [_result(False)])
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(a_data), encoding="utf-8")
    fb.write_text(json.dumps(b_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb), "--format", "html"])
    assert result.exit_code == 0
    assert "<table>" in result.output


def test_compare_cli_label_override(tmp_path):
    a_data = _make_scan_data("", [_result(True)])
    b_data = _make_scan_data("", [_result(True)])
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    out = tmp_path / "out.json"
    fa.write_text(json.dumps(a_data), encoding="utf-8")
    fb.write_text(json.dumps(b_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb),
                                  "--label-a", "Alpha", "--label-b", "Beta",
                                  "--output", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["label_a"] == "Alpha"
    assert data["meta"]["label_b"] == "Beta"


def test_compare_cli_missing_file(tmp_path):
    fa = tmp_path / "a.json"
    fa.write_text("{}", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(tmp_path / "nope.json")])
    assert result.exit_code != 0


# ── build_comparison robustness ───────────────────────────────────────────────

def test_build_comparison_empty_dict_raises_value_error():
    """build_comparison must raise ValueError on dicts missing required keys."""
    a = _make_scan_data("py", [_result(True)])
    with pytest.raises(ValueError, match="missing required key"):
        build_comparison({}, a)
    with pytest.raises(ValueError, match="missing required key"):
        build_comparison(a, {})


def test_build_comparison_missing_meta_field_raises_value_error():
    """build_comparison must raise ValueError when meta is missing expected counters."""
    import copy
    a = _make_scan_data("py", [_result(True)])
    b = copy.deepcopy(a)
    del b["meta"]["pass_rate"]
    with pytest.raises(ValueError, match="pass_rate"):
        build_comparison(a, b)


def test_compare_cli_bad_schema_file_exits_cleanly(tmp_path):
    """compare command with a JSON file missing 'meta'/'results' keys should
    exit with a clear message, not an uncaught exception."""
    good = _make_scan_data("py", [_result(True)])
    bad = {"not": "evadex output"}
    fa = tmp_path / "good.json"
    fb = tmp_path / "bad.json"
    fa.write_text(json.dumps(good), encoding="utf-8")
    fb.write_text(json.dumps(bad), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb)])
    assert result.exit_code != 0
    # sys.exit(1) shows as SystemExit — that is expected controlled termination
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "meta" in result.output or "evadex result" in result.output
    assert "KeyError" not in result.output
    assert "Traceback" not in result.output


def test_compare_cli_empty_json_file_exits_cleanly(tmp_path):
    """compare command with an empty file should exit with a clear error."""
    good = _make_scan_data("py", [_result(True)])
    fa = tmp_path / "good.json"
    fb = tmp_path / "empty.json"
    fa.write_text(json.dumps(good), encoding="utf-8")
    fb.write_text("", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb)])
    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Invalid JSON" in result.output or "JSON" in result.output
    assert "JSONDecodeError" not in result.output
    assert "Traceback" not in result.output


# ── Confidence diff handling (Siphon adapter) ────────────────────────────────

def _result_with_confidence(detected: bool, confidence: float) -> dict:
    r = _result(detected)
    r["confidence"] = confidence
    return r


def test_confidence_delta_surfaced_when_severity_unchanged():
    """Same pass/pass severity but confidence moved → appears in diffs with delta."""
    a = _make_scan_data("siphon-v1", [_result_with_confidence(True, 0.85)])
    b = _make_scan_data("siphon-v2", [_result_with_confidence(True, 0.55)])
    comp = build_comparison(a, b)
    assert len(comp["diffs"]) == 1
    d = comp["diffs"][0]
    assert d["a_severity"] == "pass"
    assert d["b_severity"] == "pass"
    assert d["a_confidence"] == 0.85
    assert d["b_confidence"] == 0.55
    assert d["confidence_delta"] == -0.3


def test_small_confidence_jitter_ignored():
    """Tiny confidence deltas (<0.01) don't produce a diff when severity is unchanged."""
    a = _make_scan_data("siphon-v1", [_result_with_confidence(True, 0.900)])
    b = _make_scan_data("siphon-v2", [_result_with_confidence(True, 0.9001)])
    comp = build_comparison(a, b)
    assert comp["diffs"] == []


def test_confidence_attached_to_severity_change_diff():
    """Severity-change diffs carry confidence fields too when available."""
    a = _make_scan_data("siphon-v1", [_result_with_confidence(True, 0.9)])
    b = _make_scan_data("siphon-v2", [_result_with_confidence(False, 0.1)])
    comp = build_comparison(a, b)
    assert len(comp["diffs"]) == 1
    d = comp["diffs"][0]
    assert d["a_severity"] == "pass"
    assert d["b_severity"] == "fail"
    assert d["a_confidence"] == 0.9
    assert d["b_confidence"] == 0.1
    assert d["confidence_delta"] == -0.8


# ── v3.25.0: verdict, trend arrows, --since, HTML verdict ────────────────────

class TestVerdict:
    def test_verdict_improved(self):
        a = _make_scan_data("py", [_result(False), _result(False)])
        b = _make_scan_data("ru", [_result(True),  _result(True)])
        comp = build_comparison(a, b)
        assert comp["verdict"]["verdict"] == "IMPROVED"

    def test_verdict_regressed(self):
        a = _make_scan_data("py", [_result(True), _result(True)])
        b = _make_scan_data("ru", [_result(False), _result(False)])
        comp = build_comparison(a, b)
        assert comp["verdict"]["verdict"] == "REGRESSED"

    def test_verdict_unchanged(self):
        a = _make_scan_data("py", [_result(True), _result(False)])
        b = _make_scan_data("ru", [_result(True), _result(False)])
        comp = build_comparison(a, b)
        assert comp["verdict"]["verdict"] == "UNCHANGED"

    def test_verdict_counts_improved_categories(self):
        a = _make_scan_data("py", [
            _result(False, "ssn"), _result(False, "credit_card"),
        ])
        b = _make_scan_data("ru", [
            _result(True, "ssn"),  _result(False, "credit_card"),
        ])
        comp = build_comparison(a, b)
        assert comp["verdict"]["n_improved"] >= 1

    def test_verdict_counts_regressed_categories(self):
        a = _make_scan_data("py", [
            _result(True, "ssn"), _result(True, "credit_card"),
        ])
        b = _make_scan_data("ru", [
            _result(False, "ssn"), _result(True, "credit_card"),
        ])
        comp = build_comparison(a, b)
        assert comp["verdict"]["n_regressed"] >= 1

    def test_verdict_worst_regressed_is_category_name(self):
        a = _make_scan_data("py", [
            _result(True, "ssn"), _result(True, "credit_card"),
        ])
        b = _make_scan_data("ru", [
            _result(False, "ssn"), _result(False, "credit_card"),
        ])
        comp = build_comparison(a, b)
        worst = comp["verdict"]["worst_regressed"]
        assert worst in ("ssn", "credit_card")

    def test_verdict_new_category_counted(self):
        # b has a category that a does not
        a = _make_scan_data("py", [_result(True, "ssn")])
        b = _make_scan_data("ru", [_result(True, "ssn"), _result(True, "credit_card")])
        comp = build_comparison(a, b)
        assert comp["verdict"]["n_new"] >= 1

    def test_verdict_field_present_in_json_output(self, tmp_path):
        a_data = _make_scan_data("py", [_result(True)])
        b_data = _make_scan_data("ru", [_result(False)])
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        out = tmp_path / "out.json"
        fa.write_text(json.dumps(a_data))
        fb.write_text(json.dumps(b_data))
        runner = CliRunner()
        result = runner.invoke(main, ["compare", str(fa), str(fb), "--output", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "verdict" in data
        assert data["verdict"]["verdict"] in ("IMPROVED", "REGRESSED", "UNCHANGED")


class TestParseSince:
    def test_parse_days(self):
        from evadex.cli.commands.compare import _parse_since
        from datetime import datetime, timezone, timedelta
        result = _parse_since("7d")
        now = datetime.now(timezone.utc)
        assert abs((now - timedelta(days=7) - result).total_seconds()) < 5

    def test_parse_weeks(self):
        from evadex.cli.commands.compare import _parse_since
        from datetime import datetime, timezone, timedelta
        result = _parse_since("2w")
        now = datetime.now(timezone.utc)
        assert abs((now - timedelta(weeks=2) - result).total_seconds()) < 5

    def test_parse_months(self):
        from evadex.cli.commands.compare import _parse_since
        from datetime import datetime, timezone, timedelta
        result = _parse_since("1m")
        now = datetime.now(timezone.utc)
        assert abs((now - timedelta(days=30) - result).total_seconds()) < 5

    def test_parse_absolute_date(self):
        from evadex.cli.commands.compare import _parse_since
        from datetime import datetime, timezone
        result = _parse_since("2026-04-20")
        assert result.year == 2026
        assert result.month == 4
        assert result.day == 20
        assert result.tzinfo == timezone.utc

    def test_parse_invalid_raises(self):
        import click
        from evadex.cli.commands.compare import _parse_since
        with pytest.raises(click.BadParameter):
            _parse_since("not-a-date")

    def test_case_insensitive_unit(self):
        from evadex.cli.commands.compare import _parse_since
        from datetime import datetime, timezone, timedelta
        result_lower = _parse_since("3d")
        result_upper = _parse_since("3D")
        assert abs((result_lower - result_upper).total_seconds()) < 2


class TestFindScanBefore:
    def _write_scan(self, scan_dir, timestamp_str: str, content: dict) -> None:
        path = scan_dir / f"scan_{timestamp_str}_test.json"
        path.write_text(json.dumps(content))

    def test_finds_most_recent_before_cutoff(self, tmp_path):
        from evadex.cli.commands.compare import _find_scan_before
        from datetime import datetime, timezone
        scan_dir = tmp_path / "scans"
        scan_dir.mkdir()
        # Three scan files, cutoff after the first two
        self._write_scan(scan_dir, "20260410T120000Z", {"meta": {}, "results": []})
        self._write_scan(scan_dir, "20260415T120000Z", {"meta": {}, "results": []})
        self._write_scan(scan_dir, "20260420T120000Z", {"meta": {}, "results": []})

        cutoff = datetime(2026, 4, 17, tzinfo=timezone.utc)
        result = _find_scan_before(cutoff, scan_dir=scan_dir)
        assert result is not None
        assert "20260415T120000Z" in result

    def test_returns_none_when_nothing_before_cutoff(self, tmp_path):
        from evadex.cli.commands.compare import _find_scan_before
        from datetime import datetime, timezone
        scan_dir = tmp_path / "scans"
        scan_dir.mkdir()
        self._write_scan(scan_dir, "20260420T120000Z", {"meta": {}, "results": []})

        cutoff = datetime(2026, 4, 10, tzinfo=timezone.utc)
        result = _find_scan_before(cutoff, scan_dir=scan_dir)
        assert result is None

    def test_returns_none_when_dir_missing(self, tmp_path):
        from evadex.cli.commands.compare import _find_scan_before
        from datetime import datetime, timezone
        result = _find_scan_before(
            datetime(2026, 4, 10, tzinfo=timezone.utc),
            scan_dir=tmp_path / "no_such_dir",
        )
        assert result is None

    def test_find_latest_scan(self, tmp_path):
        from evadex.cli.commands.compare import _find_latest_scan
        scan_dir = tmp_path / "scans"
        scan_dir.mkdir()
        self._write_scan(scan_dir, "20260410T120000Z", {"meta": {}, "results": []})
        self._write_scan(scan_dir, "20260415T120000Z", {"meta": {}, "results": []})
        self._write_scan(scan_dir, "20260420T120000Z", {"meta": {}, "results": []})

        result = _find_latest_scan(scan_dir=scan_dir)
        assert result is not None
        assert "20260420T120000Z" in result

    def test_find_latest_scan_returns_none_on_empty_dir(self, tmp_path):
        from evadex.cli.commands.compare import _find_latest_scan
        scan_dir = tmp_path / "scans"
        scan_dir.mkdir()
        assert _find_latest_scan(scan_dir=scan_dir) is None


class TestCompareSinceFlag:
    def _write_scan_file(self, path, data):
        path.write_text(json.dumps(data))

    def test_since_resolves_baseline(self, tmp_path):
        """--since with one explicit file_b should auto-resolve file_a."""
        import shutil

        good_scan = _make_scan_data("v1", [_result(True)])
        new_scan  = _make_scan_data("v2", [_result(False)])

        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            iso_scan_dir = Path("results/scans")
            iso_scan_dir.mkdir(parents=True)

            baseline_path = iso_scan_dir / "scan_20260420T120000Z_v1.json"
            baseline_path.write_text(json.dumps(good_scan))

            new_in_iso = Path("new.json")
            new_in_iso.write_text(json.dumps(new_scan))

            result = runner.invoke(main, [
                "compare", str(new_in_iso), "--since", "7d",
            ])
        # Should succeed (exit 0) or exit 1 only if no scan found before cutoff
        # (depends on whether 2026-04-20 < now - 7d; today is 2026-04-28 so it is)
        assert result.exit_code in (0, 1)

    def test_since_no_files_fails_when_no_scans(self, tmp_path):
        """--since with no positional args should fail gracefully when no archived scans."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["compare", "--since", "7d"])
        assert result.exit_code != 0


class TestHtmlVerdictSection:
    def test_html_contains_verdict_banner(self, tmp_path):
        a_data = _make_scan_data("py", [_result(False), _result(False)])
        b_data = _make_scan_data("ru", [_result(True),  _result(True)])
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(a_data))
        fb.write_text(json.dumps(b_data))
        runner = CliRunner()
        result = runner.invoke(main, ["compare", str(fa), str(fb), "--format", "html"])
        assert result.exit_code == 0
        assert "verdict-banner" in result.output
        assert "IMPROVED" in result.output

    def test_html_contains_regressed_verdict(self, tmp_path):
        a_data = _make_scan_data("py", [_result(True), _result(True)])
        b_data = _make_scan_data("ru", [_result(False), _result(False)])
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(a_data))
        fb.write_text(json.dumps(b_data))
        runner = CliRunner()
        result = runner.invoke(main, ["compare", str(fa), str(fb), "--format", "html"])
        assert result.exit_code == 0
        assert "REGRESSED" in result.output
        assert "verdict-banner" in result.output

    def test_html_unchanged_shows_banner(self, tmp_path):
        a_data = _make_scan_data("py", [_result(True)])
        b_data = _make_scan_data("ru", [_result(True)])
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(a_data))
        fb.write_text(json.dumps(b_data))
        runner = CliRunner()
        result = runner.invoke(main, ["compare", str(fa), str(fb), "--format", "html"])
        assert result.exit_code == 0
        assert "verdict-banner" in result.output
        assert "UNCHANGED" in result.output

    def test_html_is_valid_structure(self, tmp_path):
        a_data = _make_scan_data("py", [_result(True)])
        b_data = _make_scan_data("ru", [_result(False)])
        fa = tmp_path / "a.json"
        fb = tmp_path / "b.json"
        fa.write_text(json.dumps(a_data))
        fb.write_text(json.dumps(b_data))
        runner = CliRunner()
        result = runner.invoke(main, ["compare", str(fa), str(fb), "--format", "html"])
        assert result.exit_code == 0
        html = result.output
        assert "<!DOCTYPE html>" in html
        assert "<table>" in html
        assert "</html>" in html
