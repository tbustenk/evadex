"""Unit tests for evadex diff command (variant-level comparison)."""

import json
import pytest
from click.testing import CliRunner

from evadex.cli.commands.diff import build_variant_diff, _top_by_category_technique
from evadex.cli.app import main


def _make_result(
    payload_value: str,
    category: str,
    generator: str,
    technique: str,
    strategy: str,
    variant_value: str,
    severity: str,
) -> dict:
    return {
        "payload": {"value": payload_value, "category": category, "label": "test"},
        "variant": {
            "value": variant_value,
            "generator": generator,
            "technique": technique,
            "transform_name": technique,
            "strategy": strategy,
        },
        "detected": severity == "PASS",
        "severity": severity,
        "duration_ms": 10.0,
        "error": None,
        "raw_response": {},
    }


def _make_scan(results: list[dict]) -> dict:
    return {"meta": {"scanner": "test", "total": len(results), "pass": 0, "fail": 0, "error": 0, "pass_rate": 0.0}, "results": results}


# ── build_variant_diff ────────────────────────────────────────────────────────

def test_newly_detected_when_fail_becomes_pass():
    r = _make_result("4111111111111111", "credit_card", "unicode_encoding", "homoglyph", "text", "4１１１111111111111", "FAIL")
    a = _make_scan([r])
    r2 = dict(r)
    r2["severity"] = "PASS"
    r2["detected"] = True
    b = _make_scan([r2])
    diff = build_variant_diff(a, b)
    assert len(diff["newly_detected"]) == 1
    assert len(diff["newly_missed"]) == 0


def test_newly_missed_when_pass_becomes_fail():
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDExMTExMTEx", "PASS")
    a = _make_scan([r])
    r2 = dict(r)
    r2["severity"] = "FAIL"
    r2["detected"] = False
    b = _make_scan([r2])
    diff = build_variant_diff(a, b)
    assert len(diff["newly_missed"]) == 1
    assert len(diff["newly_detected"]) == 0


def test_unchanged_detected_when_pass_in_both():
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDExMTEx", "PASS")
    a = _make_scan([r])
    b = _make_scan([r])
    diff = build_variant_diff(a, b)
    assert len(diff["unchanged_detected"]) == 1
    assert len(diff["newly_detected"]) == 0
    assert len(diff["newly_missed"]) == 0


def test_unchanged_missed_when_fail_in_both():
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDExMTEx", "FAIL")
    a = _make_scan([r])
    b = _make_scan([r])
    diff = build_variant_diff(a, b)
    assert len(diff["unchanged_missed"]) == 1
    assert len(diff["newly_detected"]) == 0


def test_absent_in_a_treated_as_fail():
    # Present only in B as PASS => newly detected
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDExMTEx", "PASS")
    a = _make_scan([])
    b = _make_scan([r])
    diff = build_variant_diff(a, b)
    assert len(diff["newly_detected"]) == 1


def test_absent_in_b_treated_as_fail():
    # Present only in A as PASS => newly missed
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDExMTEx", "PASS")
    a = _make_scan([r])
    b = _make_scan([])
    diff = build_variant_diff(a, b)
    assert len(diff["newly_missed"]) == 1


def test_top_by_category_technique_ordering():
    entries = [
        {"category": "ssn", "technique": "base64", "variant_value": "x"},
        {"category": "ssn", "technique": "base64", "variant_value": "y"},
        {"category": "credit_card", "technique": "homoglyph", "variant_value": "z"},
    ]
    top = _top_by_category_technique(entries, n=5)
    assert top[0]["category"] == "ssn"
    assert top[0]["count"] == 2


def test_build_variant_diff_returns_top_entries():
    results = []
    for i in range(10):
        r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", f"variant{i}", "FAIL")
        results.append(r)
    a = _make_scan(results)
    results2 = []
    for i in range(10):
        r = dict(results[i])
        r["severity"] = "PASS"
        r["detected"] = True
        results2.append(r)
    b = _make_scan(results2)
    diff = build_variant_diff(a, b)
    assert len(diff["top_newly_detected"]) >= 1
    assert diff["top_newly_detected"][0]["count"] == 10


def test_diff_cli_runs_and_exits_zero(tmp_path):
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDEx", "PASS")
    a = _make_scan([r])
    r2 = dict(r)
    r2["severity"] = "FAIL"
    r2["detected"] = False
    b = _make_scan([r2])
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    fa.write_text(json.dumps(a), encoding="utf-8")
    fb.write_text(json.dumps(b), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(fa), str(fb)])
    assert result.exit_code == 0


def test_diff_cli_json_output(tmp_path):
    r = _make_result("4111111111111111", "credit_card", "encoding", "base64", "text", "NDEx", "FAIL")
    a = _make_scan([r])
    r2 = dict(r)
    r2["severity"] = "PASS"
    r2["detected"] = True
    b = _make_scan([r2])
    fa = tmp_path / "a.json"
    fb = tmp_path / "b.json"
    out = tmp_path / "diff.json"
    fa.write_text(json.dumps(a), encoding="utf-8")
    fb.write_text(json.dumps(b), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(fa), str(fb), "--format", "json", "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["newly_detected_count"] == 1
    assert data["newly_missed_count"] == 0
