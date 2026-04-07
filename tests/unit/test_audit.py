"""Unit tests for evadex.audit — append_audit_entry()."""

import json
from pathlib import Path
import pytest
from evadex.audit import append_audit_entry


def _entry(**overrides):
    base = dict(
        scanner_label="test-scanner",
        tool="dlpscan-cli",
        strategies=["text"],
        categories=["credit_card"],
        include_heuristic=False,
        total=10,
        passes=8,
        fails=2,
        errors=0,
        pass_rate=80.0,
        output_file=None,
        baseline_saved=None,
        compare_baseline=None,
        min_detection_rate=None,
        exit_code=0,
    )
    base.update(overrides)
    return base


def test_creates_file_and_appends_json(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    append_audit_entry(log, **_entry())
    lines = Path(log).read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "dlpscan-cli"
    assert record["pass"] == 8
    assert record["exit_code"] == 0


def test_multiple_runs_append_separate_lines(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    append_audit_entry(log, **_entry(scanner_label="run-1"))
    append_audit_entry(log, **_entry(scanner_label="run-2"))
    append_audit_entry(log, **_entry(scanner_label="run-3"))
    lines = Path(log).read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    labels = [json.loads(l)["scanner_label"] for l in lines]
    assert labels == ["run-1", "run-2", "run-3"]


def test_creates_parent_directories(tmp_path):
    log = str(tmp_path / "deep" / "nested" / "audit.jsonl")
    append_audit_entry(log, **_entry())
    assert Path(log).exists()


def test_record_contains_required_fields(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    append_audit_entry(log, **_entry(
        output_file="results.json",
        baseline_saved="baseline.json",
        compare_baseline=None,
        min_detection_rate=85.0,
        exit_code=1,
    ))
    record = json.loads(Path(log).read_text(encoding="utf-8"))
    for field in (
        "timestamp", "evadex_version", "operator",
        "scanner_label", "tool", "strategies", "categories",
        "include_heuristic", "total", "pass", "fail", "error",
        "pass_rate", "output_file", "baseline_saved",
        "compare_baseline", "min_detection_rate", "exit_code",
    ):
        assert field in record, f"Missing field: {field}"
    assert record["output_file"] == "results.json"
    assert record["min_detection_rate"] == 85.0
    assert record["exit_code"] == 1


def test_silently_ignores_bad_path():
    # Writing to an invalid path (root-owned directory) must not raise
    append_audit_entry("/proc/evadex_audit.jsonl", **_entry())  # always fails on any OS


def test_timestamp_is_iso8601(tmp_path):
    from datetime import datetime
    log = str(tmp_path / "audit.jsonl")
    append_audit_entry(log, **_entry())
    record = json.loads(Path(log).read_text(encoding="utf-8"))
    # Should parse without error
    datetime.fromisoformat(record["timestamp"])


def test_operator_field_present_and_string(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    append_audit_entry(log, **_entry())
    record = json.loads(Path(log).read_text(encoding="utf-8"))
    assert isinstance(record["operator"], str)
    assert len(record["operator"]) > 0
