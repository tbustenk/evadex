"""Unit tests for `evadex replay` — re-running exact payloads from a past scan."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from evadex.cli.app import main
from evadex.cli.commands.replay import (
    NEWLY_DETECTED,
    NEWLY_FAILING,
    STILL_BYPASSING,
    UNCHANGED_DETECTED,
    _classify_outcome,
    _filter_results,
    _reconstruct,
    _tally,
)
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant


# ── A controllable in-memory adapter ────────────────────────────────────────
@register_adapter("fake-replay")
class FakeReplayAdapter:
    """Detects a variant when its value is in ``detect_values``.

    Class-level knobs let each test dial the current scanner's behaviour so we
    can force newly_detected / still_bypassing / newly_failing outcomes.
    """

    detect_values: set = set()
    default_detected: bool = False
    raise_on: set = set()

    def __init__(self, config):
        self.config = config

    async def setup(self):
        pass

    async def teardown(self):
        pass

    async def health_check(self) -> bool:
        return True

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        if variant.value in type(self).raise_on:
            raise RuntimeError("boom")
        detected = (
            variant.value in type(self).detect_values
            if type(self).detect_values
            else type(self).default_detected
        )
        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            confidence=1.0 if detected else None,
        )


@pytest.fixture(autouse=True)
def _reset_fake_adapter():
    FakeReplayAdapter.detect_values = set()
    FakeReplayAdapter.default_detected = False
    FakeReplayAdapter.raise_on = set()
    yield
    FakeReplayAdapter.detect_values = set()
    FakeReplayAdapter.default_detected = False
    FakeReplayAdapter.raise_on = set()


# ── Scan-file fixture builders ──────────────────────────────────────────────
def _result_dict(
    value: str,
    *,
    category: str = "credit_card",
    generator: str = "unicode_encoding",
    technique: str = "fullwidth_digits",
    detected: bool = False,
    strategy: str = "text",
    error=None,
):
    payload_value = "4532015112830366"
    return {
        "payload": {
            "value": payload_value,
            "category": category,
            "category_type": "structured",
            "label": "Visa 16-digit",
        },
        "variant": {
            "value": value,
            "generator": generator,
            "technique": technique,
            "transform_name": "test transform",
            "strategy": strategy,
        },
        "detected": detected,
        "severity": "error" if error else ("pass" if detected else "fail"),
        "error": error,
        "raw_response": {},
        **({"confidence": 1.0} if detected else {}),
    }


def _scan_doc(results: list[dict], scanner: str = "siphon-pre-fix") -> dict:
    passes = sum(1 for r in results if r["severity"] == "pass")
    fails = sum(1 for r in results if r["severity"] == "fail")
    errors = sum(1 for r in results if r["severity"] == "error")
    total = len(results)
    return {
        "meta": {
            "timestamp": "2026-05-24T20:36:51+00:00",
            "scanner": scanner,
            "total": total,
            "pass": passes,
            "fail": fails,
            "error": errors,
            "pass_rate": round(passes / total * 100, 1) if total else 0.0,
        },
        "results": results,
    }


def _write_scan(tmp_path, doc, name="scan.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


# ── Pure helpers ────────────────────────────────────────────────────────────
def test_classify_outcome_newly_detected():
    assert _classify_outcome(False, True) == NEWLY_DETECTED


def test_classify_outcome_still_bypassing():
    assert _classify_outcome(False, False) == STILL_BYPASSING


def test_classify_outcome_regression():
    assert _classify_outcome(True, False) == NEWLY_FAILING


def test_classify_outcome_unchanged_detected():
    assert _classify_outcome(True, True) == UNCHANGED_DETECTED


def test_reconstruct_from_results_key():
    doc = _scan_doc([_result_dict("AAA"), _result_dict("BBB", detected=True)])
    originals = _reconstruct(doc)
    assert len(originals) == 2
    assert originals[0].variant.value == "AAA"
    assert originals[0].payload.category == PayloadCategory.CREDIT_CARD
    assert originals[1].detected is True


def test_reconstruct_skips_corrupt_rows():
    doc = _scan_doc([_result_dict("AAA")])
    # A row with an unknown category and a plain non-dict row.
    doc["results"].append(_result_dict("BBB", category="not_a_real_category"))
    doc["results"].append("garbage")  # type: ignore[arg-type]
    originals = _reconstruct(doc)
    assert len(originals) == 1
    assert originals[0].variant.value == "AAA"


def test_reconstruct_preserves_strategy():
    doc = _scan_doc([_result_dict("AAA", strategy="docx")])
    originals = _reconstruct(doc)
    assert originals[0].variant.strategy == "docx"


def _originals(doc):
    return _reconstruct(doc)


def test_filter_failed_only_excludes_detected_and_errors():
    doc = _scan_doc(
        [
            _result_dict("bypassed", detected=False),
            _result_dict("caught", detected=True),
            _result_dict("errored", error="timeout"),
        ]
    )
    filtered = _filter_results(_originals(doc), True, None, None, None)
    assert [r.variant.value for r in filtered] == ["bypassed"]


def test_filter_category():
    doc = _scan_doc(
        [
            _result_dict("cc", category="credit_card"),
            _result_dict("ib", category="iban"),
        ]
    )
    filtered = _filter_results(_originals(doc), False, "iban", None, None)
    assert [r.variant.value for r in filtered] == ["ib"]


def test_filter_technique_matches_generator_too():
    doc = _scan_doc(
        [
            _result_dict("a", generator="unicode_encoding", technique="fullwidth"),
            _result_dict("b", generator="morse_code", technique="dots"),
        ]
    )
    by_tech = _filter_results(_originals(doc), False, None, "dots", None)
    by_gen = _filter_results(_originals(doc), False, None, "unicode_encoding", None)
    assert [r.variant.value for r in by_tech] == ["b"]
    assert [r.variant.value for r in by_gen] == ["a"]


def test_filter_limit():
    doc = _scan_doc([_result_dict(f"v{i}") for i in range(10)])
    filtered = _filter_results(_originals(doc), False, None, None, 3)
    assert len(filtered) == 3


def test_tally_counts_all_outcomes():
    def pair(orig_detected, new_detected, error=None):
        p = Payload("x", PayloadCategory.CREDIT_CARD, "l")
        v = Variant("val", "g", "t", "tn")
        orig = ScanResult(p, v, detected=orig_detected)
        new = ScanResult(p, v, detected=new_detected, error=error)
        return (orig, new)

    pairs = [
        pair(False, True),  # newly_detected
        pair(False, False),  # still_bypassing
        pair(True, False),  # newly_failing
        pair(True, True),  # unchanged_detected
        pair(False, False, error="boom"),  # error
    ]
    counts = _tally(pairs)
    assert counts[NEWLY_DETECTED] == 1
    assert counts[STILL_BYPASSING] == 1
    assert counts[NEWLY_FAILING] == 1
    assert counts[UNCHANGED_DETECTED] == 1
    assert counts["error"] == 1


# ── Command-level behaviour ─────────────────────────────────────────────────
def test_load_scan_rejects_non_result_file(tmp_path):
    bad = _write_scan(tmp_path, {"not": "a scan"}, name="bad.json")
    res = CliRunner().invoke(main, ["replay", bad, "--tool", "fake-replay"])
    assert res.exit_code == 1
    assert "does not look like an evadex scan file" in res.output


def test_replay_summary_runs(tmp_path):
    doc = _scan_doc([_result_dict("AAA"), _result_dict("BBB")])
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.default_detected = True  # everything now caught
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--format", "summary"]
    )
    assert res.exit_code == 0
    assert "Replay summary" in res.output
    assert "Newly detected" in res.output


def test_replay_failed_only_filters(tmp_path):
    doc = _scan_doc(
        [
            _result_dict("bypassed", detected=False),
            _result_dict("caught", detected=True),
        ]
    )
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.default_detected = True
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--failed-only"]
    )
    # Only the one bypassed variant is replayed, and it is now detected.
    assert res.exit_code == 0
    assert "Newly detected:    1/1" in res.output


def test_replay_still_bypassing_exits_1(tmp_path):
    doc = _scan_doc([_result_dict("bypassed", detected=False)])
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.default_detected = False  # still not caught
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--failed-only"]
    )
    assert res.exit_code == 1
    assert "Still bypassing" in res.output


def test_replay_regression_reported(tmp_path):
    doc = _scan_doc([_result_dict("was_caught", detected=True)])
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.default_detected = False  # now bypasses → regression
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--format", "summary"]
    )
    assert res.exit_code == 0
    assert "Newly failing" in res.output
    assert "Regression detected" in res.output


def test_replay_category_filter_end_to_end(tmp_path):
    doc = _scan_doc(
        [
            _result_dict("cc", category="credit_card"),
            _result_dict("ib", category="iban"),
        ]
    )
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.default_detected = True
    res = CliRunner().invoke(
        main,
        ["replay", path, "--tool", "fake-replay", "--category", "iban"],
    )
    assert res.exit_code == 0
    assert "Replaying 1 variant" in res.output


def test_replay_no_match_exits_0(tmp_path):
    doc = _scan_doc([_result_dict("cc", category="credit_card")])
    path = _write_scan(tmp_path, doc)
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--category", "iban"]
    )
    assert res.exit_code == 0
    assert "No variants match" in res.output


def test_replay_format_json_is_valid(tmp_path):
    doc = _scan_doc([_result_dict("AAA"), _result_dict("BBB")])
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.default_detected = True
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--format", "json"]
    )
    assert res.exit_code == 0
    parsed = json.loads(res.stdout)
    assert parsed["meta"]["total"] == 2
    assert parsed["meta"]["pass"] == 2
    assert len(parsed["results"]) == 2


def test_replay_output_file_feeds_compare(tmp_path):
    doc = _scan_doc([_result_dict("AAA"), _result_dict("BBB")], scanner="pre-fix")
    path = _write_scan(tmp_path, doc)
    out = str(tmp_path / "replay.json")
    FakeReplayAdapter.default_detected = True
    res = CliRunner().invoke(
        main,
        ["replay", path, "--tool", "fake-replay", "-o", out, "--scanner-label", "post"],
    )
    assert res.exit_code == 0
    written = json.loads(open(out, encoding="utf-8").read())
    assert written["meta"]["scanner"] == "post"
    assert written["meta"]["total"] == 2

    # The written file must be consumable by `evadex compare`.
    cmp_res = CliRunner().invoke(main, ["compare", path, out])
    assert cmp_res.exit_code == 0


def test_replay_handles_adapter_errors(tmp_path):
    doc = _scan_doc([_result_dict("AAA"), _result_dict("BBB")])
    path = _write_scan(tmp_path, doc)
    FakeReplayAdapter.raise_on = {"AAA"}
    FakeReplayAdapter.default_detected = True
    res = CliRunner().invoke(
        main, ["replay", path, "--tool", "fake-replay", "--format", "summary"]
    )
    assert res.exit_code == 0
    assert "Errors" in res.output
