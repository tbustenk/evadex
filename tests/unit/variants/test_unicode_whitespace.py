import pytest
from evadex.variants.unicode_whitespace import UnicodeWhitespaceGenerator
from evadex.core.result import PayloadCategory

CC = "4111111111111111"
SSN = "123-45-6789"


def _variants(value=CC):
    return list(UnicodeWhitespaceGenerator().generate(value))


def test_generates_nbsp_variant():
    variants = _variants()
    nbsp = next(v for v in variants if v.technique == "unicode_nbsp")
    assert '\u00A0' in nbsp.value


def test_generates_en_space_variant():
    variants = _variants()
    v = next(v for v in variants if v.technique == "unicode_en_space")
    assert '\u2002' in v.value


def test_generates_em_space_variant():
    variants = _variants()
    v = next(v for v in variants if v.technique == "unicode_em_space")
    assert '\u2003' in v.value


def test_generates_mixed_spaces_variant():
    variants = _variants()
    mixed = next(v for v in variants if v.technique == "unicode_mixed_spaces")
    assert '\u00A0' in mixed.value
    assert '\u2009' in mixed.value


def test_raw_digits_preserved():
    # All alphanumeric chars from original value must appear in each variant
    raw = "4111111111111111"
    variants = _variants(raw)
    for v in variants:
        stripped = ''.join(c for c in v.value if c.isalnum())
        assert stripped == raw, f"Digits not preserved in {v.technique}: {v.value!r}"


def test_ssn_with_dashes():
    # Hyphens stripped, digits grouped and separated by Unicode spaces
    variants = _variants(SSN)
    nbsp = next(v for v in variants if v.technique == "unicode_nbsp")
    assert '\u00A0' in nbsp.value
    assert '-' not in nbsp.value  # original hyphens replaced


def test_generator_name():
    for v in _variants():
        assert v.generator == "unicode_whitespace"


def test_applicable_to_credit_card():
    gen = UnicodeWhitespaceGenerator()
    assert PayloadCategory.CREDIT_CARD in gen.applicable_categories


def test_applicable_to_ssn():
    gen = UnicodeWhitespaceGenerator()
    assert PayloadCategory.SSN in gen.applicable_categories


def test_not_applicable_to_jwt():
    gen = UnicodeWhitespaceGenerator()
    assert PayloadCategory.JWT not in gen.applicable_categories


def test_not_applicable_to_email():
    gen = UnicodeWhitespaceGenerator()
    assert PayloadCategory.EMAIL not in gen.applicable_categories


def test_technique_names_are_unique():
    techniques = [v.technique for v in _variants()]
    assert len(techniques) == len(set(techniques))
