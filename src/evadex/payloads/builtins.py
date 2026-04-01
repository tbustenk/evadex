import re
from evadex.core.result import Payload, PayloadCategory


BUILTIN_PAYLOADS = [
    Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit"),
    Payload("378282246310005",  PayloadCategory.CREDIT_CARD, "Amex 15-digit"),
    Payload("5105105105105100", PayloadCategory.CREDIT_CARD, "Mastercard 16-digit"),
    Payload("123-45-6789",      PayloadCategory.SSN,         "US SSN"),
    Payload("046 454 286",      PayloadCategory.SIN,         "Canada SIN"),
    Payload("GB82WEST12345698765432", PayloadCategory.IBAN,  "UK IBAN"),
    Payload("AKIAIOSFODNN7EXAMPLE",   PayloadCategory.AWS_KEY, "AWS Access Key ID"),
    Payload(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        PayloadCategory.JWT,
        "Sample JWT",
    ),
    Payload("test.user@example.com", PayloadCategory.EMAIL, "Email address"),
    Payload("+1-555-867-5309",       PayloadCategory.PHONE, "US phone number"),
]


def detect_category(value: str) -> PayloadCategory:
    """Auto-detect payload category from value format."""
    v = value.strip()

    # JWT: three base64url segments
    if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', v):
        return PayloadCategory.JWT

    # AWS access key
    if re.match(r'^AKIA[0-9A-Z]{16}$', v):
        return PayloadCategory.AWS_KEY

    # Email
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        return PayloadCategory.EMAIL

    # IBAN: 2 letter country code + 2 digits + up to 30 alphanumeric
    if re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$', v):
        return PayloadCategory.IBAN

    # US SSN: NNN-NN-NNNN
    if re.match(r'^\d{3}-\d{2}-\d{4}$', v):
        return PayloadCategory.SSN

    # Canada SIN: NNN NNN NNN or NNN-NNN-NNN
    if re.match(r'^\d{3}[ -]\d{3}[ -]\d{3}$', v):
        return PayloadCategory.SIN

    # Phone: starts with + or has country code pattern
    digits_only = re.sub(r'[^\d]', '', v)
    if v.startswith('+') or (v.startswith('1') and len(digits_only) == 11):
        return PayloadCategory.PHONE

    # Credit card: Luhn check on 13-19 digit number
    if re.match(r'^[\d\s\-\.]{13,23}$', v):
        if _luhn_check(digits_only) and 13 <= len(digits_only) <= 19:
            return PayloadCategory.CREDIT_CARD

    return PayloadCategory.UNKNOWN


def _luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    if not number.isdigit():
        return False
    total = 0
    reverse = number[::-1]
    for i, digit in enumerate(reverse):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def get_payloads(categories=None) -> list[Payload]:
    if categories is None:
        return BUILTIN_PAYLOADS
    return [p for p in BUILTIN_PAYLOADS if p.category in categories]
