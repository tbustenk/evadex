"""End-to-end tests for the `evadex edm` command.

Siphon's EDM HTTP surface is mocked with respx so tests run without a
real scanner. We exercise:

- registration + verification against /v1/edm/register and /v1/scan
- the EDM evasion probe (transforms → per-transform detection rate)
- corpus generation (--generate-corpus) without touching the server
- graceful 403 handling for non-admin keys
- the 50k hash limit warning
- the edm_json generate format
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from evadex.cli.app import main


URL = "http://siphon.test"
KEY = "test-key"


# ── Corpus-only path (no network) ─────────────────────────────────────────

def test_generate_corpus_json(tmp_path):
    out = tmp_path / "corpus.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "edm", "--generate-corpus",
        "--category", "credit_card",
        "--limit", "3",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    body = json.loads(out.read_text(encoding="utf-8"))
    assert "values" in body and len(body["values"]) == 3
    for entry in body["values"]:
        assert entry.keys() == {"value", "category", "label"}
        assert entry["category"] == "credit_card"


def test_generate_corpus_csv(tmp_path):
    out = tmp_path / "corpus.csv"
    runner = CliRunner()
    result = runner.invoke(main, [
        "edm", "--generate-corpus",
        "--corpus-format", "csv",
        "--category", "credit_card",
        "--limit", "3",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    rows = list(csv.reader(out.read_text(encoding="utf-8").splitlines()))
    assert rows[0] == ["category", "label", "value"]
    assert len(rows) == 4  # header + 3 rows


def test_generate_corpus_requires_output(tmp_path):
    result = CliRunner().invoke(main, [
        "edm", "--generate-corpus",
        "--category", "credit_card",
    ])
    assert result.exit_code != 0
    assert "--output" in result.output


# ── Live registration + verification ──────────────────────────────────────

def _mk_ok_register(category: str, n: int) -> httpx.Response:
    return httpx.Response(200, json={
        "category": category, "registered": n, "total_hashes": n,
    })


@respx.mock
def test_register_and_verify_detects_exact_values(tmp_path):
    # Siphon returns an EDM match whenever the submitted text matches a known value.
    # We mock: register endpoint always 200, scan endpoint returns an EDM
    # finding iff the body text matches a known payload.
    known_values: set[str] = set()

    def _register(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        for v in body["values"]:
            known_values.add(v)
        return _mk_ok_register(body["category"], len(body["values"]))

    def _scan(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        text = body["text"]
        if text in known_values:
            return httpx.Response(200, json={
                "is_clean": False, "finding_count": 1,
                "categories_found": ["EDM: evadex_test_credit_card"],
                "redacted_text": None,
                "findings": [{
                    "text": "****",
                    "category": "EDM: evadex_test_credit_card",
                    "sub_category": "Exact Data Match",
                    "confidence": 1.0, "has_context": True,
                    "span": [0, len(text)],
                }],
            })
        return httpx.Response(200, json={
            "is_clean": True, "finding_count": 0,
            "categories_found": [], "redacted_text": None, "findings": [],
        })

    respx.post(f"{URL}/v1/edm/register").mock(side_effect=_register)
    respx.post(f"{URL}/v1/scan").mock(side_effect=_scan)

    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(main, [
        "edm",
        "--url", URL, "--api-key", KEY,
        "--category", "credit_card", "--limit", "3",
        "--no-test-evasion",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    # Every registered value should come back detected in verification.
    assert report["verification"], "expected verification rows"
    assert all(v["edm_detected"] for v in report["verification"])
    assert report["exact_match_rate_pct"] == 100.0
    # The evadex-test namespace is used (so production categories stay untouched)
    assert all(
        cat.startswith("evadex_test_") for cat in report["categories"]
    )


@respx.mock
def test_403_on_register_exits_with_clear_error(tmp_path):
    respx.post(f"{URL}/v1/edm/register").mock(
        return_value=httpx.Response(403, json={"detail": "Admin role required"})
    )
    runner = CliRunner()
    result = runner.invoke(main, [
        "edm", "--url", URL, "--api-key", KEY,
        "--category", "credit_card", "--limit", "2",
        "--no-test-evasion",
    ])
    assert result.exit_code != 0
    assert "Admin" in result.output or "403" in result.output


@respx.mock
def test_evasion_probe_measures_per_transform_detection(tmp_path):
    # The key behaviour under test: EDM's normaliser absorbs delimiters /
    # whitespace / case, but NOT homoglyph Unicode. The mock must mirror
    # Siphon's real normalisation so the probe's conclusions are accurate.
    import re

    def _normalise(s: str) -> str:
        import unicodedata
        s = unicodedata.normalize("NFKC", s).lower().strip()
        return re.sub(r"[\s\-./()]+", "", s)

    known_hashes: set[str] = set()

    def _register(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        for v in body["values"]:
            known_hashes.add(_normalise(v))
        return _mk_ok_register(body["category"], len(body["values"]))

    def _scan(request: httpx.Request) -> httpx.Response:
        text = json.loads(request.content)["text"]
        if _normalise(text) in known_hashes:
            return httpx.Response(200, json={
                "is_clean": False, "finding_count": 1,
                "categories_found": ["EDM: evadex_test_credit_card"],
                "redacted_text": None,
                "findings": [{
                    "text": "***", "category": "EDM: evadex_test_credit_card",
                    "sub_category": "Exact Data Match", "confidence": 1.0,
                    "has_context": True, "span": [0, len(text)],
                }],
            })
        return httpx.Response(200, json={
            "is_clean": True, "finding_count": 0, "categories_found": [],
            "redacted_text": None, "findings": [],
        })

    respx.post(f"{URL}/v1/edm/register").mock(side_effect=_register)
    respx.post(f"{URL}/v1/scan").mock(side_effect=_scan)

    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, [
        "edm", "--url", URL, "--api-key", KEY,
        "--category", "credit_card", "--limit", "2",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    stats = report["evasion_stats"]

    # Normalisation-absorbed transforms should hit 100% — Siphon's regex
    # strips them before hashing.
    for transform in ("exact", "uppercase", "lowercase", "dashes", "spaces", "dots", "slashes"):
        s = stats[transform]
        assert s["detected"] == s["tested"], (
            f"{transform} should be absorbed by Siphon's normaliser "
            f"(detected {s['detected']}/{s['tested']})"
        )
    # NFKC does not fold Cyrillic → Latin: homoglyph variants must evade
    # IF the transform actually changed the string. For credit-card payloads
    # there's no 'o' to substitute, so homoglyph_o is a no-op and still
    # matches — that's a real, useful property we surface in the harness.
    # Test only homoglyph_0 (digit-0 substitution applies to card numbers).
    s = stats["homoglyph_0"]
    if s["tested"] > 0:
        assert s["detected"] == 0, (
            "homoglyph_0 should NOT be caught (Cyrillic О isn't NFKC-folded to ASCII 0)"
        )


# ── 50k hash warning ──────────────────────────────────────────────────────

def test_warning_threshold_exposed():
    """The warning constant should match Siphon's MAX_CONSTANT_TIME_HASHES."""
    from evadex.cli.commands.edm import SIPHON_EDM_HASH_WARN_THRESHOLD
    assert SIPHON_EDM_HASH_WARN_THRESHOLD == 50_000


@respx.mock
def test_warning_printed_when_registration_crosses_50k(tmp_path, monkeypatch):
    """Surface Siphon's constant-time performance warning at 50k+ hashes."""
    # Force the threshold low so we don't have to register 50k values in a test.
    monkeypatch.setattr(
        "evadex.cli.commands.edm.SIPHON_EDM_HASH_WARN_THRESHOLD", 3,
    )
    respx.post(f"{URL}/v1/edm/register").mock(
        return_value=httpx.Response(200, json={
            "category": "evadex_test_credit_card",
            "registered": 5, "total_hashes": 5,
        })
    )
    respx.post(f"{URL}/v1/scan").mock(
        return_value=httpx.Response(200, json={
            "is_clean": True, "finding_count": 0, "categories_found": [],
            "redacted_text": None, "findings": [],
        })
    )
    result = CliRunner().invoke(main, [
        "edm", "--url", URL, "--api-key", KEY,
        "--category", "credit_card", "--limit", "5",
        "--no-test-evasion",
    ])
    assert result.exit_code == 0, result.output
    assert "constant-time" in result.output or "recommended" in result.output


# ── Dry run ───────────────────────────────────────────────────────────────

def test_dry_run_does_not_hit_server(tmp_path):
    # No respx routes registered → any HTTP call would raise.
    result = CliRunner().invoke(main, [
        "edm", "--url", URL, "--api-key", KEY,
        "--category", "credit_card", "--limit", "2",
        "--dry-run",
    ])
    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output


# ── edm_json generate format ──────────────────────────────────────────────

def test_generate_edm_json_format(tmp_path):
    out = tmp_path / "bulk.edm_json"
    result = CliRunner().invoke(main, [
        "generate", "--format", "edm_json",
        "--category", "credit_card", "--count", "3",
        "--evasion-rate", "0.0",
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    body = json.loads(out.read_text(encoding="utf-8"))
    assert "values" in body and isinstance(body["values"], list)
    assert len(body["values"]) >= 1
    for entry in body["values"]:
        assert entry.keys() >= {"value", "category", "label"}


# ── Evasion transform shape ───────────────────────────────────────────────

def test_transform_helpers_preserve_content():
    """Sanity: every EVASION_TRANSFORM should produce a string derived from input."""
    from evadex.cli.commands.edm import EVASION_TRANSFORMS
    v = "4532015112830366"
    for name, fn in EVASION_TRANSFORMS.items():
        out = fn(v)
        assert isinstance(out, str) and out, f"{name} produced empty output"
