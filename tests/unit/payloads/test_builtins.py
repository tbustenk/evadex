from evadex.payloads.builtins import detect_category, get_payloads, BUILTIN_PAYLOADS
from evadex.core.result import PayloadCategory


def test_detect_visa():
    assert detect_category("4532015112830366") == PayloadCategory.CREDIT_CARD


def test_detect_amex():
    assert detect_category("378282246310005") == PayloadCategory.CREDIT_CARD


def test_detect_ssn():
    assert detect_category("123-45-6789") == PayloadCategory.SSN


def test_detect_sin():
    assert detect_category("046 454 286") == PayloadCategory.SIN


def test_detect_iban():
    assert detect_category("GB82WEST12345698765432") == PayloadCategory.IBAN


def test_detect_aws_key():
    assert detect_category("AKIAIOSFODNN7EXAMPLE") == PayloadCategory.AWS_KEY


def test_detect_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456ghi789"
    assert detect_category(jwt) == PayloadCategory.JWT


def test_detect_email():
    assert detect_category("user@example.com") == PayloadCategory.EMAIL


def test_detect_phone():
    assert detect_category("+1-555-867-5309") == PayloadCategory.PHONE


def test_detect_unknown():
    assert detect_category("hello world") == PayloadCategory.UNKNOWN


def test_get_payloads_all():
    payloads = get_payloads(include_heuristic=True)
    assert len(payloads) == len(BUILTIN_PAYLOADS)


def test_get_payloads_filtered():
    payloads = get_payloads({PayloadCategory.CREDIT_CARD})
    assert all(p.category == PayloadCategory.CREDIT_CARD for p in payloads)
    assert len(payloads) == 7  # Visa, Amex, Mastercard, Discover, JCB, UnionPay, Diners
