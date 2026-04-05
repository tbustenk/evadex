"""Unit tests for the morse_code evasion generator."""
import pytest
from evadex.variants.morse_code import MorseCodeGenerator, MORSE_DIGITS, _encode
from evadex.core.result import PayloadCategory


@pytest.fixture
def gen():
    return MorseCodeGenerator()


# ---------------------------------------------------------------------------
# Digit encoding correctness
# ---------------------------------------------------------------------------

def test_all_digits_have_morse_symbol():
    assert set(MORSE_DIGITS.keys()) == set("0123456789")


def test_known_digit_encodings():
    assert MORSE_DIGITS["0"] == "-----"
    assert MORSE_DIGITS["1"] == ".----"
    assert MORSE_DIGITS["5"] == "....."
    assert MORSE_DIGITS["9"] == "----."


def test_space_separated_single_digit(gen):
    variants = {v.technique: v.value for v in gen.generate("5")}
    assert "morse_space_sep" in variants
    assert variants["morse_space_sep"] == "....."


def test_space_separated_ssn(gen):
    # 123-45-6789  →  digits encoded, hyphens passed through
    variants = {v.technique: v.value for v in gen.generate("123-45-6789")}
    space_val = variants["morse_space_sep"]
    # Every digit in "123456789" must appear as its Morse symbol somewhere
    for digit in "123456789":
        assert MORSE_DIGITS[digit] in space_val, f"Morse for {digit!r} missing"


def test_slash_separated_produces_slashes(gen):
    variants = {v.technique: v.value for v in gen.generate("42")}
    assert "morse_slash_sep" in variants
    assert "/" in variants["morse_slash_sep"]


def test_no_separator_contains_only_dots_dashes_and_passthrough(gen):
    variants = {v.technique: v.value for v in gen.generate("99")}
    assert "morse_no_sep" in variants
    val = variants["morse_no_sep"]
    # No spaces, only dots, dashes (digits are "99" → "----- -----" without sep)
    assert " " not in val
    assert set(val) <= set(".-")


def test_newline_separated_variant_present(gen):
    variants = {v.technique: v.value for v in gen.generate("12345")}
    assert "morse_newline_sep" in variants
    assert "\n" in variants["morse_newline_sep"]


# ---------------------------------------------------------------------------
# Applicable categories
# ---------------------------------------------------------------------------

def test_applicable_to_credit_card(gen):
    assert PayloadCategory.CREDIT_CARD in gen.applicable_categories


def test_applicable_to_ssn(gen):
    assert PayloadCategory.SSN in gen.applicable_categories


def test_applicable_to_iban(gen):
    assert PayloadCategory.IBAN in gen.applicable_categories


def test_not_applicable_to_email(gen):
    assert PayloadCategory.EMAIL not in gen.applicable_categories


def test_not_applicable_to_github_token(gen):
    assert PayloadCategory.GITHUB_TOKEN not in gen.applicable_categories


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_no_variants_for_no_digits(gen):
    # A string with no digits should produce no variants
    variants = list(gen.generate("no-digits-here"))
    assert variants == []


def test_empty_string_produces_no_variants(gen):
    assert list(gen.generate("")) == []


def test_all_four_techniques_generated(gen):
    techniques = {v.technique for v in gen.generate("123456789")}
    assert "morse_space_sep" in techniques
    assert "morse_slash_sep" in techniques
    assert "morse_no_sep" in techniques
    assert "morse_newline_sep" in techniques


def test_variants_differ_from_each_other(gen):
    variants = list(gen.generate("999-99-9999"))
    values = [v.value for v in variants]
    # All generated values should be distinct
    assert len(values) == len(set(values))


def test_generator_name():
    assert MorseCodeGenerator.name == "morse_code"


def test_encode_helper_space_sep():
    result = _encode("123", sep=" ", word_sep=" ")
    assert result == ".---- ..--- ...--"


def test_encode_helper_no_sep():
    # "1" = .---- (5 chars) + "0" = ----- (5 chars), no separator = 10 chars
    result = _encode("10", sep="", word_sep="")
    assert result == ".---------"  # .---- + -----
