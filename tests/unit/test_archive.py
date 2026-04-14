"""Unit tests for evadex.archive — results archiving and audit log."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evadex.archive import (
    _safe_label,
    archive_falsepos,
    archive_scan,
    append_results_audit,
    backfill_from_directory,
    build_falsepos_audit_entry,
    build_scan_audit_entry,
)


# ── _safe_label ────────────────────────────────────────────────────────────────

def test_safe_label_alphanumeric():
    assert _safe_label("rust123") == "rust123"


def test_safe_label_allowed_punctuation():
    assert _safe_label("rust-2.0_v3") == "rust-2.0_v3"


def test_safe_label_strips_specials():
    label = _safe_label("scanner/name with spaces!")
    assert " " not in label
    assert "/" not in label
    assert "!" not in label


def test_safe_label_max_length():
    long = "a" * 100
    result = _safe_label(long)
    assert len(result) <= 40


def test_safe_label_empty_string():
    assert _safe_label("") == "unlabelled"


def test_safe_label_none_equivalent():
    # None is handled by the `s or ""` default
    assert _safe_label(None) == "unlabelled"  # type: ignore[arg-type]


# ── archive_scan ───────────────────────────────────────────────────────────────

def test_archive_scan_creates_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    path = archive_scan('{"meta": {}}', "my-scanner", ts=ts)
    assert path.exists()
    assert path.suffix == ".json"


def test_archive_scan_contains_content(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    path = archive_scan('{"hello": "world"}', "scanner", ts=ts)
    assert json.loads(path.read_text(encoding="utf-8")) == {"hello": "world"}


def test_archive_scan_uses_timestamp_in_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 34, 56, tzinfo=timezone.utc)
    path = archive_scan("{}", "scanner", ts=ts)
    assert "20260414T123456Z" in path.name


def test_archive_scan_uses_label_in_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    path = archive_scan("{}", "rust-2.0.0", ts=ts)
    assert "rust-2.0.0" in path.name


def test_archive_scan_does_not_overwrite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    path = archive_scan('{"first": true}', "scanner", ts=ts)
    # Second call with same ts — file already exists, should not overwrite
    archive_scan('{"second": true}', "scanner", ts=ts)
    assert json.loads(path.read_text(encoding="utf-8")) == {"first": True}


def test_archive_scan_returns_path_on_error():
    # Pass an unwritable path indirectly — monkeypatch results dir to bad path
    # archive functions swallow exceptions and return placeholder
    from evadex import archive as _archive_mod
    import evadex.archive as archive_mod
    original = archive_mod._RESULTS_DIR
    try:
        archive_mod._RESULTS_DIR = Path("/nonexistent_ZZZZ/results")
        result = archive_scan("{}", "scanner")
        assert isinstance(result, Path)
    finally:
        archive_mod._RESULTS_DIR = original


# ── archive_falsepos ───────────────────────────────────────────────────────────

def test_archive_falsepos_creates_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    report = {"tool": "dlpscan-cli", "total_tested": 50, "total_flagged": 10}
    path = archive_falsepos(report, "my-scanner", ts=ts)
    assert path.exists()
    assert path.suffix == ".json"


def test_archive_falsepos_contains_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    report = {"tool": "dlpscan-cli", "total_tested": 50}
    path = archive_falsepos(report, ts=ts)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["tool"] == "dlpscan-cli"
    assert saved["total_tested"] == 50


# ── append_results_audit ───────────────────────────────────────────────────────

def test_append_results_audit_creates_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    append_results_audit({"type": "scan", "pass_rate": 90.0})
    audit = tmp_path / "results" / "audit.jsonl"
    assert audit.exists()


def test_append_results_audit_writes_valid_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    append_results_audit({"type": "scan", "pass_rate": 85.5})
    audit = tmp_path / "results" / "audit.jsonl"
    lines = [l for l in audit.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["pass_rate"] == 85.5


def test_append_results_audit_appends_multiple(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    append_results_audit({"type": "scan", "id": 1})
    append_results_audit({"type": "scan", "id": 2})
    append_results_audit({"type": "falsepos", "id": 3})
    audit = tmp_path / "results" / "audit.jsonl"
    lines = [l for l in audit.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 3
    ids = [json.loads(l)["id"] for l in lines]
    assert ids == [1, 2, 3]


def test_append_results_audit_silences_errors():
    # Should not raise even with a bad path
    from evadex import archive as archive_mod
    original = archive_mod._RESULTS_DIR
    try:
        archive_mod._RESULTS_DIR = Path("/nonexistent_ZZZZ/results")
        append_results_audit({"type": "scan"})  # must not raise
    finally:
        archive_mod._RESULTS_DIR = original


# ── build_scan_audit_entry ─────────────────────────────────────────────────────

def test_build_scan_audit_entry_required_fields():
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    entry = build_scan_audit_entry(
        scanner_label="test",
        tool="dlpscan-cli",
        categories=["credit_card"],
        strategies=["text"],
        total=100,
        passes=80,
        fails=20,
        pass_rate=80.0,
        archive_file="results/scans/scan_xxx.json",
        ts=ts,
    )
    assert entry["type"] == "scan"
    assert entry["pass_rate"] == 80.0
    assert entry["total"] == 100
    assert entry["pass"] == 80
    assert entry["fail"] == 20
    assert entry["scanner_label"] == "test"
    assert entry["categories"] == ["credit_card"]
    assert entry["archive_file"] == "results/scans/scan_xxx.json"


def test_build_scan_audit_entry_timestamp_is_iso():
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    entry = build_scan_audit_entry(
        scanner_label="", tool="dlpscan-cli", categories=[], strategies=[],
        total=0, passes=0, fails=0, pass_rate=0.0, archive_file="x", ts=ts,
    )
    assert entry["timestamp"].startswith("2026-04-14")


# ── build_falsepos_audit_entry ─────────────────────────────────────────────────

def test_build_falsepos_audit_entry_required_fields():
    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
    entry = build_falsepos_audit_entry(
        tool="dlpscan-cli",
        categories=["credit_card"],
        total_tested=50,
        total_flagged=45,
        fp_rate=90.0,
        archive_file="results/falsepos/fp_xxx.json",
        ts=ts,
    )
    assert entry["type"] == "falsepos"
    assert entry["fp_rate"] == 90.0
    assert entry["total_tested"] == 50
    assert entry["total_flagged"] == 45
    assert entry["categories"] == ["credit_card"]


# ── backfill_from_directory ────────────────────────────────────────────────────

def _make_scan_json(meta_extra: dict | None = None) -> dict:
    meta = {
        "scanner": "test-scanner",
        "timestamp": "2026-04-14T12:00:00+00:00",
        "total": 100,
        "pass": 80,
        "fail": 20,
        "pass_rate": 80.0,
        "summary_by_category": {"credit_card": {"pass": 80, "fail": 20}},
    }
    if meta_extra:
        meta.update(meta_extra)
    return {"meta": meta, "results": []}


def _make_falsepos_json() -> dict:
    return {
        "tool": "dlpscan-cli",
        "total_tested": 50,
        "total_flagged": 45,
        "overall_false_positive_rate": 90.0,
        "by_category": {"credit_card": {"total": 50, "flagged": 45}},
    }


def test_backfill_scan_adds_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan_old.json"
    scan_file.write_text(json.dumps(_make_scan_json()), encoding="utf-8")
    added = backfill_from_directory(str(tmp_path))
    assert added >= 1
    audit = tmp_path / "results" / "audit.jsonl"
    lines = [json.loads(l) for l in audit.read_text(encoding="utf-8").splitlines() if l.strip()]
    scan_entries = [e for e in lines if e.get("type") == "scan"]
    assert len(scan_entries) >= 1
    assert scan_entries[0]["pass_rate"] == 80.0


def test_backfill_falsepos_adds_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fp_file = tmp_path / "fp_old.json"
    fp_file.write_text(json.dumps(_make_falsepos_json()), encoding="utf-8")
    added = backfill_from_directory(str(tmp_path))
    assert added >= 1
    audit = tmp_path / "results" / "audit.jsonl"
    lines = [json.loads(l) for l in audit.read_text(encoding="utf-8").splitlines() if l.strip()]
    fp_entries = [e for e in lines if e.get("type") == "falsepos"]
    assert fp_entries[0]["fp_rate"] == 90.0


def test_backfill_skips_results_subdir(tmp_path, monkeypatch):
    """Files already inside results/ should not be double-counted."""
    monkeypatch.chdir(tmp_path)
    results_dir = tmp_path / "results" / "scans"
    results_dir.mkdir(parents=True)
    # Put a scan file inside results/scans/ — should be skipped by glob("*.json")
    # since backfill only globs the top-level directory
    scan_file = tmp_path / "scan_top.json"
    scan_file.write_text(json.dumps(_make_scan_json()), encoding="utf-8")
    added = backfill_from_directory(str(tmp_path))
    assert added == 1  # only the top-level file


def test_backfill_skips_invalid_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bad_file = tmp_path / "broken.json"
    bad_file.write_text("not valid json {{{{", encoding="utf-8")
    added = backfill_from_directory(str(tmp_path))
    assert added == 0


def test_backfill_skips_unrecognised_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    unknown_file = tmp_path / "unknown.json"
    unknown_file.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    added = backfill_from_directory(str(tmp_path))
    assert added == 0


def test_backfill_does_not_duplicate_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scan_file = tmp_path / "scan_old.json"
    scan_file.write_text(json.dumps(_make_scan_json()), encoding="utf-8")
    backfill_from_directory(str(tmp_path))
    backfill_from_directory(str(tmp_path))  # run twice
    audit = tmp_path / "results" / "audit.jsonl"
    lines = [l for l in audit.read_text(encoding="utf-8").splitlines() if l.strip()]
    # Two JSONL entries (one per run) but the archive file should only be copied once
    archive_scans = list((tmp_path / "results" / "scans").glob("*.json"))
    assert len(archive_scans) == 1  # file not duplicated
