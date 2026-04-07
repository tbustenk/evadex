"""Unit tests for regression test file generation."""
import ast

import pytest

from evadex.core.result import PayloadCategory, ScanResult, Payload, Variant
from evadex.feedback.regression_writer import _slug, generate_regression_code


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fail(
    technique: str = "homoglyph_substitution",
    generator: str = "unicode_encoding",
    label: str = "Visa 16-digit",
    category: PayloadCategory = PayloadCategory.CREDIT_CARD,
    value: str = "4532\u041e15112830366",
    transform_name: str = "Visually similar Cyrillic/Greek characters substituted",
) -> ScanResult:
    p = Payload("4532015112830366", category, label)
    v = Variant(value, generator, technique, transform_name, strategy="text")
    return ScanResult(payload=p, variant=v, detected=False, duration_ms=1.0)


def _pass() -> ScanResult:
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=True, duration_ms=1.0)


# ── _slug ─────────────────────────────────────────────────────────────────────

def test_slug_basic():
    assert _slug("Visa 16-digit") == "visa_16_digit"


def test_slug_ssn():
    assert _slug("US SSN") == "us_ssn"


def test_slug_aws():
    assert _slug("AWS Access Key") == "aws_access_key"


def test_slug_parens():
    assert _slug("UK IBAN (GB)") == "uk_iban_gb"


def test_slug_already_clean():
    assert _slug("no_delimiter") == "no_delimiter"


# ── generate_regression_code ──────────────────────────────────────────────────

def test_no_evasions_returns_empty():
    assert generate_regression_code([_pass(), _pass()]) == ""


def test_single_evasion_is_valid_python():
    code = generate_regression_code([_fail()])
    ast.parse(code)  # raises SyntaxError if invalid


def test_function_name_contains_label_and_technique():
    code = generate_regression_code([_fail(technique="homoglyph_substitution", label="Visa 16-digit")])
    assert "def test_visa_16_digit_homoglyph_substitution(" in code


def test_docstring_mentions_label_and_technique():
    code = generate_regression_code([_fail(technique="zero_width_zwsp", label="Canada SIN")])
    assert "Canada SIN" in code
    assert "zero_width_zwsp" in code


def test_credit_card_uses_pci_dss_preset():
    code = generate_regression_code([_fail(category=PayloadCategory.CREDIT_CARD)])
    assert "Preset.PCI_DSS" in code


def test_ssn_uses_pii_preset():
    code = generate_regression_code([_fail(category=PayloadCategory.SSN, label="US SSN")])
    assert "Preset.PII" in code


def test_aws_key_uses_credentials_preset():
    code = generate_regression_code([_fail(category=PayloadCategory.AWS_KEY, label="AWS Key")])
    assert "Preset.CREDENTIALS" in code


def test_iban_uses_pci_dss_preset():
    code = generate_regression_code([_fail(category=PayloadCategory.IBAN, label="UK IBAN")])
    assert "Preset.PCI_DSS" in code


def test_duplicate_names_get_numeric_suffix():
    r1 = _fail(value="val1")
    r2 = _fail(value="val2")
    code = generate_regression_code([r1, r2])
    assert "def test_visa_16_digit_homoglyph_substitution(" in code
    assert "def test_visa_16_digit_homoglyph_substitution_2(" in code


def test_variant_value_appears_as_repr():
    value = "4532\u041e15112830366"  # Cyrillic О
    code = generate_regression_code([_fail(value=value)])
    assert repr(value) in code


def test_transform_name_appears_as_comment():
    code = generate_regression_code([_fail(transform_name="Cyrillic lookalike substitution")])
    assert "# Cyrillic lookalike substitution" in code


def test_assert_statement_present():
    code = generate_regression_code([_fail()])
    assert "assert not result.is_clean" in code


def test_inputguard_import_inside_function():
    code = generate_regression_code([_fail()])
    assert "from dlpscan import InputGuard, Preset" in code


def test_passes_only_no_output():
    assert generate_regression_code([_pass(), _pass()]) == ""


def test_mixed_results_only_includes_fails():
    code = generate_regression_code([_pass(), _fail(), _pass()])
    assert code.count("def test_") == 1


def test_multiple_evasions_all_valid_python():
    results = [
        _fail(technique="homoglyph_substitution"),
        _fail(technique="zero_width_zwsp", value="4\u200b5\u200b3\u200b2"),
        _fail(technique="base64_standard", generator="encoding",
              value="NDUzMjAxNTExMjgzMDM2Ng==", transform_name="Standard base64"),
    ]
    code = generate_regression_code(results)
    ast.parse(code)
    assert code.count("def test_") == 3


def test_header_contains_run_instructions():
    code = generate_regression_code([_fail()])
    assert "pytest evadex_regressions.py" in code


def test_unknown_category_falls_back_to_pci_dss():
    code = generate_regression_code([_fail(category=PayloadCategory.UNKNOWN, label="Unknown")])
    assert "Preset.PCI_DSS" in code
