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
    # Actual technique names use morse_ prefix
    s = get_suggestions([_fail("morse_space_sep", generator="morse_code")])[0]
    assert "morse" in s.suggested_fix.lower()


def test_soft_hyphen_fix_mentions_u00ad():
    s = get_suggestions([_fail("shy_group_boundaries", generator="soft_hyphen")])[0]
    assert "U+00AD" in s.suggested_fix


def test_bidi_fix_mentions_strip():
    s = get_suggestions([_fail("rlo_wrap", generator="bidirectional")])[0]
    assert "strip" in s.suggested_fix.lower() or "bidi" in s.suggested_fix.lower()


def test_nbsp_fix_mentions_normalise():
    # Actual technique name is unicode_nbsp, not nbsp
    s = get_suggestions([_fail("unicode_nbsp", generator="unicode_whitespace")])[0]
    text = s.suggested_fix.lower()
    assert "normalise" in text or "normalize" in text


def test_unknown_technique_gets_generic_suggestion():
    s = get_suggestions([_fail("some_future_technique_xyz")])[0]
    assert s.technique == "some_future_technique_xyz"
    assert isinstance(s.suggested_fix, str)
    assert len(s.suggested_fix) > 5


def test_regional_digit_prefix_match():
    # Actual technique names use regional_ prefix
    s = get_suggestions([_fail("regional_arabic_indic", generator="regional_digits")])[0]
    text = s.suggested_fix.lower()
    assert "digit" in text or "normalise" in text or "normalize" in text


def test_devanagari_prefix_match():
    s = get_suggestions([_fail("regional_devanagari", generator="regional_digits")])[0]
    assert "ascii" in s.suggested_fix.lower() or "digit" in s.suggested_fix.lower()


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
    for tech in ("zero_width_zwsp", "zero_width_zwnj", "zero_width_zwj"):
        desc, fix = _lookup_fix(tech)
        assert "U+" in fix


def test_lookup_all_morse_variants():
    # Actual technique names from morse_code generator use morse_ prefix
    for tech in ("morse_space_sep", "morse_slash_sep", "morse_no_sep", "morse_newline_sep"):
        desc, fix = _lookup_fix(tech)
        assert "morse" in fix.lower()


def test_lookup_structural_noise_embedded():
    desc, fix = _lookup_fix("noise_embedded")
    assert "noise" in fix.lower() or "boundary" in fix.lower()


def test_lookup_structural_overlapping_prefix():
    desc, fix = _lookup_fix("overlapping_prefix")
    assert "prefix" in fix.lower() or "boundary" in fix.lower()


def test_lookup_base64_partial():
    desc, fix = _lookup_fix("base64_partial")
    assert "base64" in fix.lower() and "partial" in fix.lower() or "substring" in fix.lower()


def test_lookup_url_percent_encoding_full():
    desc, fix = _lookup_fix("url_percent_encoding_full")
    assert "url" in fix.lower() or "percent" in fix.lower() or "unquote" in fix.lower()


def test_lookup_unicode_whitespace_variants():
    for tech in ("unicode_nbsp", "unicode_en_space", "unicode_em_space", "unicode_mixed_spaces"):
        desc, fix = _lookup_fix(tech)
        assert "normalise" in fix.lower() or "normalize" in fix.lower()
