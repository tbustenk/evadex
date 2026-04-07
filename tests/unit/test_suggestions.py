"""Unit tests for fix suggestion logic."""
import pytest

from evadex.core.result import PayloadCategory, ScanResult, Payload, Variant
from evadex.feedback.suggestions import Suggestion, _lookup_fix, get_suggestions


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fail(technique: str, generator: str = "unicode_encoding") -> ScanResult:
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("variant", generator, technique, "Transform name", strategy="text")
    return ScanResult(payload=p, variant=v, detected=False, duration_ms=1.0)


def _pass() -> ScanResult:
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=True, duration_ms=1.0)


# ── get_suggestions ───────────────────────────────────────────────────────────

def test_no_evasions_returns_empty():
    assert get_suggestions([_pass(), _pass()]) == []


def test_single_technique_one_suggestion():
    suggestions = get_suggestions([_fail("homoglyph_substitution")])
    assert len(suggestions) == 1
    assert suggestions[0].technique == "homoglyph_substitution"


def test_duplicate_technique_deduplicated():
    results = [_fail("homoglyph_substitution")] * 5
    assert len(get_suggestions(results)) == 1


def test_multiple_techniques_multiple_suggestions():
    results = [
        _fail("homoglyph_substitution"),
        _fail("zero_width_zwsp"),
        _fail("base64_standard", generator="encoding"),
    ]
    suggestions = get_suggestions(results)
    assert len(suggestions) == 3
    techs = {s.technique for s in suggestions}
    assert techs == {"homoglyph_substitution", "zero_width_zwsp", "base64_standard"}


def test_suggestion_is_named_tuple():
    s = get_suggestions([_fail("homoglyph_substitution")])[0]
    assert isinstance(s, Suggestion)


def test_suggestion_fields_present():
    s = get_suggestions([_fail("homoglyph_substitution", generator="unicode_encoding")])[0]
    assert s.technique == "homoglyph_substitution"
    assert s.generator == "unicode_encoding"
    assert len(s.description) > 10
    assert len(s.suggested_fix) > 10


def test_generator_preserved_in_suggestion():
    s = get_suggestions([_fail("base64_standard", generator="encoding")])[0]
    assert s.generator == "encoding"


def test_homoglyph_fix_mentions_cyrillic():
    s = get_suggestions([_fail("homoglyph_substitution")])[0]
    text = s.suggested_fix.lower()
    assert "cyrillic" in text or "homoglyph" in text


def test_zero_width_fix_mentions_codepoint():
    s = get_suggestions([_fail("zero_width_zwsp")])[0]
    assert "U+200B" in s.suggested_fix


def test_zwnj_fix_mentions_codepoint():
    s = get_suggestions([_fail("zero_width_zwnj")])[0]
    assert "U+200C" in s.suggested_fix


def test_base64_fix_mentions_decode():
    s = get_suggestions([_fail("base64_standard", generator="encoding")])[0]
    assert "base64" in s.suggested_fix.lower()
    assert "decode" in s.suggested_fix.lower()


def test_morse_fix_mentions_decode():
    s = get_suggestions([_fail("space_separated", generator="morse_code")])[0]
    assert "morse" in s.suggested_fix.lower()


def test_soft_hyphen_fix_mentions_u00ad():
    s = get_suggestions([_fail("shy_group_boundaries", generator="soft_hyphen")])[0]
    assert "U+00AD" in s.suggested_fix


def test_bidi_fix_mentions_strip():
    s = get_suggestions([_fail("rlo_wrap", generator="bidirectional")])[0]
    assert "strip" in s.suggested_fix.lower() or "bidi" in s.suggested_fix.lower()


def test_nbsp_fix_mentions_normalise():
    s = get_suggestions([_fail("nbsp", generator="unicode_whitespace")])[0]
    text = s.suggested_fix.lower()
    assert "normalise" in text or "normalize" in text


def test_unknown_technique_gets_generic_suggestion():
    s = get_suggestions([_fail("some_future_technique_xyz")])[0]
    assert s.technique == "some_future_technique_xyz"
    assert isinstance(s.suggested_fix, str)
    assert len(s.suggested_fix) > 5


def test_regional_digit_prefix_match():
    s = get_suggestions([_fail("arabic_indic", generator="regional_digits")])[0]
    text = s.suggested_fix.lower()
    assert "digit" in text or "normalise" in text or "normalize" in text


def test_devanagari_prefix_match():
    s = get_suggestions([_fail("devanagari", generator="regional_digits")])[0]
    assert "devanagari" in s.suggested_fix.lower() or "ascii" in s.suggested_fix.lower()


def test_passes_ignored():
    results = [_pass(), _fail("homoglyph_substitution"), _pass()]
    suggestions = get_suggestions(results)
    assert len(suggestions) == 1


# ── _lookup_fix ───────────────────────────────────────────────────────────────

def test_lookup_known_technique():
    desc, fix = _lookup_fix("homoglyph_substitution")
    assert isinstance(desc, str) and len(desc) > 10
    assert isinstance(fix, str) and len(fix) > 10


def test_lookup_unknown_returns_generic_with_technique_name():
    desc, fix = _lookup_fix("totally_unknown_technique_abc")
    assert "totally unknown technique abc" in desc.lower()
    assert "'totally_unknown_technique_abc'" in fix


def test_lookup_all_zero_width_variants():
    for tech in ("zero_width_zwsp", "zero_width_zwnj", "zero_width_zwj", "zero_width_wj"):
        desc, fix = _lookup_fix(tech)
        assert "U+" in fix


def test_lookup_all_morse_variants():
    for tech in ("space_separated", "slash_separated", "no_separator", "newline_separated"):
        desc, fix = _lookup_fix(tech)
        assert "morse" in fix.lower()
