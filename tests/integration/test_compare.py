"""Integration tests for the compare command and build_comparison logic."""
import copy
import json
import pytest
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
    fa.write_text(json.dumps(a_data), encoding="utf-8")
    fb.write_text(json.dumps(b_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
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
    fa.write_text(json.dumps(a_data), encoding="utf-8")
    fb.write_text(json.dumps(b_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(fa), str(fb),
                                  "--label-a", "Alpha", "--label-b", "Beta"])
    assert result.exit_code == 0
    data = json.loads(result.output)
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
