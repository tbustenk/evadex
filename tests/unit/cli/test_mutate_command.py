"""Unit tests for `evadex mutate` — adaptive breeding of bypassing variants."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from evadex.cli.app import main
from evadex.cli.commands.mutate import (
    _evolve,
    _select_bypassed,
    _test_summary,
    _to_scan_results,
)
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant
from evadex.mutate.engine import (
    MUTATION_TYPES,
    MutatedVariant,
    MutationCandidate,
    MutationEngine,
)


# ── Helpers to build breeding stock ─────────────────────────────────────────
def _candidate(
    value: str = "4532015112830366",
    *,
    category: PayloadCategory = PayloadCategory.CREDIT_CARD,
    technique: str = "homoglyph_substitution",
    generation: int = 0,
) -> MutationCandidate:
    payload = Payload("4532015112830366", category, "Visa 16-digit")
    variant = Variant(value, "unicode_encoding", technique, "x", "text")
    return MutationCandidate.from_result(
        ScanResult(payload, variant, detected=False), generation=generation
    )


def _result_dict(
    value: str,
    *,
    category: str = "credit_card",
    detected: bool = False,
    error=None,
) -> dict:
    return {
        "payload": {
            "value": "4532015112830366",
            "category": category,
            "category_type": "structured",
            "label": "Visa 16-digit",
        },
        "variant": {
            "value": value,
            "generator": "unicode_encoding",
            "technique": "fullwidth_digits",
            "transform_name": "t",
            "strategy": "text",
        },
        "detected": detected,
        "severity": "error" if error else ("pass" if detected else "fail"),
        "error": error,
        "raw_response": {},
    }


def _scan_doc(results: list[dict]) -> dict:
    return {"meta": {"scanner": "siphon-pre"}, "results": results}


def _write_scan(tmp_path, results, name="scan.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(_scan_doc(results)), encoding="utf-8")
    return str(p)


# ── A controllable in-memory adapter for --test ─────────────────────────────
@register_adapter("fake-mutate")
class FakeMutateAdapter:
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
        return ScanResult(payload=payload, variant=variant, detected=detected)


@pytest.fixture(autouse=True)
def _reset_fake_adapter():
    FakeMutateAdapter.detect_values = set()
    FakeMutateAdapter.default_detected = False
    FakeMutateAdapter.raise_on = set()
    yield
    FakeMutateAdapter.detect_values = set()
    FakeMutateAdapter.default_detected = False
    FakeMutateAdapter.raise_on = set()


# ── Individual mutation strategies ──────────────────────────────────────────
def test_mutate_separator():
    eng = MutationEngine(seed=1)
    mv = eng._mutate_separator(_candidate("4532015112830366"))
    assert mv is not None
    assert mv.mutation_type == "perturbation"
    # Only digits + one separator char, and every digit preserved in order.
    assert "".join(ch for ch in mv.value if ch.isdigit()) == "4532015112830366"
    assert mv.value != "4532015112830366"


def test_mutate_separator_needs_eight_digits():
    eng = MutationEngine(seed=1)
    assert eng._mutate_separator(_candidate("12ab")) is None


def test_mutate_encoding_roundtrips():
    import base64

    eng = MutationEngine(seed=7)
    mv = eng._mutate_encoding(_candidate("4532015112830366"))
    assert mv is not None
    assert mv.mutation_type == "intensification"
    if mv.base_technique == "base64":
        assert base64.b64decode(mv.value).decode() == "4532015112830366"


def test_mutate_leet_intensity():
    eng = MutationEngine(seed=3)
    # A value rich in leet-mappable digits so at least one map changes it.
    mv = eng._mutate_leet_intensity(_candidate("100375894"))
    assert mv is not None
    assert mv.base_technique == "leet"
    assert mv.value != "100375894"


def test_mutate_regional_script():
    eng = MutationEngine(seed=2)
    mv = eng._mutate_regional_script(_candidate("4532015112830366"))
    assert mv is not None
    assert mv.base_technique.startswith("regional_")
    # No ASCII digits survive the shift.
    assert not any(ch.isdigit() and ch.isascii() for ch in mv.value)


def test_mutate_regional_script_needs_ascii_digits():
    eng = MutationEngine(seed=2)
    assert eng._mutate_regional_script(_candidate("ABCDEF")) is None


def test_mutate_zero_width_injection():
    eng = MutationEngine(seed=5)
    mv = eng._mutate_zero_width_injection(_candidate("4532015112830366"))
    assert mv is not None
    assert any(ord(ch) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF) for ch in mv.value)
    # Stripping the injected zero-width chars restores the original.
    zw = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
    assert "".join(ch for ch in mv.value if ord(ch) not in zw) == "4532015112830366"


def test_mutate_combine_techniques():
    eng = MutationEngine(seed=9)
    mv = eng._mutate_combine_techniques(_candidate("4532015112830366"))
    assert mv is not None
    assert mv.mutation_type == "combination"
    assert "chain" in mv.base_technique


def test_mutate_encoding_chain():
    eng = MutationEngine(seed=4)
    mv = eng._mutate_encoding_chain(_candidate("4532015112830366"))
    assert mv is not None
    assert mv.base_technique == "base64_rot13_hex_chain"
    # Triple-hex-encoded → all lowercase hex.
    assert all(ch in "0123456789abcdef" for ch in mv.value)


def test_mutate_case_variation():
    eng = MutationEngine(seed=6)
    mv = eng._mutate_case_variation(_candidate("4532015112830366"))
    assert mv is not None
    assert mv.mutation_type == "perturbation"


def test_mutate_skips_unchanged_and_dedupes():
    eng = MutationEngine(seed=42)
    muts = eng.mutate(_candidate("4532015112830366"), 8)
    values = [m.value for m in muts]
    assert "4532015112830366" not in values  # never the original
    assert len(values) == len(set(values))  # no dupes


def test_mutate_reproducible_with_seed():
    a = MutationEngine(seed=123).mutate(_candidate(), 8)
    b = MutationEngine(seed=123).mutate(_candidate(), 8)
    assert [m.value for m in a] == [m.value for m in b]


def test_mutate_different_seeds_diverge():
    a = MutationEngine(seed=1).mutate(_candidate(), 8)
    b = MutationEngine(seed=2).mutate(_candidate(), 8)
    # Order of drawn strategies differs → the value list differs.
    assert [m.value for m in a] != [m.value for m in b]


def test_mutation_engine_all_strategies_registered():
    eng = MutationEngine()
    # Every strategy name resolves to a bound method.
    assert len(eng._registry) == 8
    # A high-digit value exercises most strategies; each result is a valid type.
    muts = eng.mutate(_candidate("100375894012"), 8)
    assert all(m.mutation_type in MUTATION_TYPES for m in muts)
    assert all(m.generation == 1 for m in muts)


def test_crossover_mixes_lineage():
    eng = MutationEngine(seed=8)
    a = _candidate("4532015112830366", technique="base64_partial")
    b = _candidate("5500005555555559", technique="homoglyph_substitution")
    mv = eng.crossover(a, b)
    assert mv is not None
    assert mv.mutation_type == "crossover"
    assert "base64_partial" in mv.parent_techniques
    assert "homoglyph_substitution" in mv.parent_techniques


def test_candidate_from_mutated_propagates_payload_and_generation():
    eng = MutationEngine(seed=42)
    parent = _candidate("4532015112830366")
    mv = eng.mutate(parent, 8)[0]
    child = MutationCandidate.from_mutated(mv)
    assert child.payload.value == "4532015112830366"  # secret rides along
    assert child.generation == mv.generation
    assert mv.base_technique in child.techniques_used


def test_mutated_variant_to_variant_and_dict():
    mv = MutatedVariant(
        value="abc",
        category="credit_card",
        base_technique="base64",
        mutation_type="intensification",
        generation=1,
        parent_techniques=["homoglyph_substitution"],
        description="d",
    )
    v = mv.to_variant()
    assert v.generator == "mutate"
    assert v.technique == "base64"
    d = mv.to_dict()
    assert d["value"] == "abc" and d["generation"] == 1
    assert "source_payload" not in d  # plaintext secret never serialised


# ── CLI-layer helpers ───────────────────────────────────────────────────────
def test_select_bypassed_excludes_detected_and_errors():
    from evadex.cli.commands.replay import _reconstruct

    doc = _scan_doc(
        [
            _result_dict("bypassed", detected=False),
            _result_dict("caught", detected=True),
            _result_dict("errored", error="timeout"),
        ]
    )
    survivors = _select_bypassed(_reconstruct(doc), None, None)
    assert [s.variant.value for s in survivors] == ["bypassed"]


def test_select_bypassed_category_filter_and_limit():
    from evadex.cli.commands.replay import _reconstruct

    doc = _scan_doc(
        [
            _result_dict("cc1", category="credit_card"),
            _result_dict("cc2", category="credit_card"),
            _result_dict("ib", category="iban"),
        ]
    )
    recon = _reconstruct(doc)
    assert len(_select_bypassed(recon, "credit_card", None)) == 2
    assert len(_select_bypassed(recon, "credit_card", 1)) == 1
    assert len(_select_bypassed(recon, "iban", None)) == 1


def test_evolve_generation_growth():
    survivors = [_candidate("4532015112830366").result]
    muts = _evolve(
        survivors, generations=2, mutations_per_variant=5, crossover=False, seed=42
    )
    gens = {m.generation for m in muts}
    assert gens == {1, 2}
    # Every bred value is globally unique across generations.
    values = [m.value for m in muts]
    assert len(values) == len(set(values))


def test_evolve_crossover_adds_crossover_type():
    s1 = _candidate("4532015112830366", technique="base64_partial").result
    s2 = _candidate("5500005555555559", technique="noise_embedded").result
    muts = _evolve(
        [s1, s2], generations=1, mutations_per_variant=5, crossover=True, seed=42
    )
    assert any(m.mutation_type == "crossover" for m in muts)


def test_to_scan_results_untested_defaults_to_bypassed():
    survivors = [_candidate("4532015112830366").result]
    muts = _evolve(survivors, 1, 5, False, 42)
    results = _to_scan_results(muts, None)
    assert len(results) == len(muts)
    assert all(r.detected is False for r in results)
    assert all(r.variant.generator == "mutate" for r in results)


def test_test_summary_counts():
    p = Payload("x", PayloadCategory.CREDIT_CARD, "l")
    v = Variant("v", "mutate", "t", "d", "text")
    results = {
        "a": ScanResult(p, v, detected=True),
        "b": ScanResult(p, v, detected=False),
        "c": ScanResult(p, v, detected=False, error="boom"),
    }
    bypassed, detected, errors, rate = _test_summary(results)
    assert (bypassed, detected, errors) == (1, 1, 1)
    assert round(rate, 1) == 33.3


# ── End-to-end CLI ──────────────────────────────────────────────────────────
def test_cli_summary_runs(tmp_path):
    scan = _write_scan(
        tmp_path, [_result_dict("4532015112830366"), _result_dict("5500005555555559")]
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(main, ["mutate", scan, "--format", "summary"])
    assert res.exit_code == 0
    assert "Total bred" in res.output


def test_cli_no_bypassing_exits_cleanly(tmp_path):
    scan = _write_scan(tmp_path, [_result_dict("caught", detected=True)])
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(main, ["mutate", scan])
    assert res.exit_code == 0
    assert "No bypassing variants" in res.output


def test_cli_category_filter_no_match(tmp_path):
    scan = _write_scan(tmp_path, [_result_dict("4532015112830366")])
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(main, ["mutate", scan, "--category", "iban"])
    assert res.exit_code == 0
    assert "No bypassing variants" in res.output


def test_cli_json_format(tmp_path):
    scan = _write_scan(tmp_path, [_result_dict("4532015112830366")])
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(main, ["mutate", scan, "--format", "json", "--limit", "1"])
    assert res.exit_code == 0
    doc = json.loads(res.stdout)
    assert doc["meta"]["tested"] is False
    assert len(doc["mutations"]) == doc["meta"]["total"] > 0


def test_cli_output_file_is_scan_format(tmp_path):
    scan = _write_scan(tmp_path, [_result_dict("4532015112830366")])
    out = tmp_path / "muts" / "gen.json"
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(
            main, ["mutate", scan, "-o", str(out), "--format", "summary"]
        )
    assert res.exit_code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert "meta" in doc and "results" in doc
    assert doc["results"][0]["variant"]["generator"] == "mutate"


def test_cli_test_flag_bypass_rate(tmp_path):
    # Scanner catches nothing → every bred variant bypasses.
    FakeMutateAdapter.default_detected = False
    scan = _write_scan(tmp_path, [_result_dict("4532015112830366")])
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(
            main,
            ["mutate", scan, "--test", "--tool", "fake-mutate", "--format", "summary"],
        )
    assert res.exit_code == 0
    assert "Bypassed:" in res.output
    assert "100.0%" in res.output


def test_cli_test_flag_all_detected(tmp_path):
    FakeMutateAdapter.default_detected = True
    scan = _write_scan(tmp_path, [_result_dict("4532015112830366")])
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(
            main,
            ["mutate", scan, "--test", "--tool", "fake-mutate", "--format", "json"],
        )
    assert res.exit_code == 0
    doc = json.loads(res.stdout)
    assert doc["meta"]["tested"] is True
    assert doc["meta"]["bypass_rate"] == 0.0
