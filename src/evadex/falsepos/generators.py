"""False positive generators — values that are structurally similar to sensitive
data but are provably invalid (fail checksums, use reserved codes, etc.).

Use these to measure false positive rate: any value flagged by the scanner is
an incorrect match.
"""
from __future__ import annotations

import random
import string
from typing import Optional

from evadex.synthetic.validators import luhn_check_digit


# ── Credit card ───────────────────────────────────────────────────────────────

def generate_false_credit_cards(count: int, seed: Optional[int] = None) -> list[str]:
    """16-digit numbers with card-like prefixes that fail the Luhn check.

    The correct Luhn check digit is computed, then a different digit is chosen,
    so the number looks structurally valid but cannot pass checksum validation.
    """
    rng = random.Random(seed)
    prefixes = ["4", "51", "37", "6011"]  # Visa/MC/Amex/Discover-ish prefixes
    results = []
    while len(results) < count:
        prefix = rng.choice(prefixes)
        n_random = 15 - len(prefix)
        body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(n_random))
        correct_check = luhn_check_digit([int(d) for d in body])
        # Pick a check digit that is definitely wrong (offset by 1–8)
        wrong_check = (correct_check + rng.randint(1, 8)) % 10
        results.append(body + str(wrong_check))
    return results


# ── SSN ───────────────────────────────────────────────────────────────────────

# Area codes that the SSA has never assigned: 000, 666, and 900–999
_INVALID_SSN_AREAS = ["000", "666"] + [f"{n:03d}" for n in range(900, 1000)]


def generate_false_ssns(count: int, seed: Optional[int] = None) -> list[str]:
    """SSN-shaped NNN-NN-NNNN strings with reserved/invalid area codes.

    The SSA never issues numbers with area codes 000, 666, or 900–999.
    """
    rng = random.Random(seed)
    results = []
    for _ in range(count):
        area = rng.choice(_INVALID_SSN_AREAS)
        mid = f"{rng.randint(0, 99):02d}"
        last = f"{rng.randint(0, 9999):04d}"
        results.append(f"{area}-{mid}-{last}")
    return results


# ── SIN ───────────────────────────────────────────────────────────────────────

def generate_false_sins(count: int, seed: Optional[int] = None) -> list[str]:
    """SIN-shaped NNN NNN NNN strings that fail the Luhn checksum.

    A valid first digit (1–7) is used so the format looks correct, but the
    check digit is deliberately wrong.
    """
    rng = random.Random(seed)
    results = []
    while len(results) < count:
        first = rng.randint(1, 7)
        middle = [rng.randint(0, 9) for _ in range(7)]
        digits = [first] + middle
        correct_check = luhn_check_digit(digits)
        # Offset by 1–8 to guarantee wrong check digit
        wrong_check = (correct_check + rng.randint(1, 8)) % 10
        s = "".join(str(d) for d in digits) + str(wrong_check)
        results.append(f"{s[:3]} {s[3:6]} {s[6:]}")
    return results


# ── IBAN ──────────────────────────────────────────────────────────────────────

_IBAN_TEMPLATES = [
    # (country_code, bban_length, alpha_positions)
    ("GB", 18, {0, 1, 2, 3}),   # GB + 2 check + 4 alpha + 14 digits
    ("DE", 18, set()),           # DE + 2 check + 18 digits
    ("FR", 23, set()),           # FR + 2 check + 23 digits
]


def _iban_correct_check(country: str, bban: str) -> int:
    """Return the correct mod-97 check value (1-97) for this country+BBAN."""
    rearranged = bban + country + "00"
    numeric = "".join(
        str(ord(ch.upper()) - ord("A") + 10) if ch.isalpha() else ch
        for ch in rearranged
    )
    return (98 - int(numeric) % 97) % 97


def generate_false_ibans(count: int, seed: Optional[int] = None) -> list[str]:
    """IBAN-shaped strings with structurally valid country+BBAN but wrong check digits.

    The correct mod-97 check digit is computed, then a different value is used,
    guaranteeing the checksum always fails.
    """
    rng = random.Random(seed)
    results = []
    for _ in range(count):
        country, bban_len, alpha_pos = rng.choice(_IBAN_TEMPLATES)
        bban = "".join(
            rng.choice(string.ascii_uppercase) if i in alpha_pos
            else str(rng.randint(0, 9))
            for i in range(bban_len)
        )
        correct = _iban_correct_check(country, bban)
        # Offset by 1–96 to guarantee wrong check digit (mod-97 range is 0-96)
        wrong = (correct + rng.randint(1, 96)) % 97
        results.append(f"{country}{wrong:02d}{bban}")
    return results


# ── Email ─────────────────────────────────────────────────────────────────────

_INVALID_TLDS = [".invalid", ".test", ".example", ".localhost", ".local",
                 ".123", ".x"]
_DOMAINS = ["domain", "company", "example", "mailserver", "corp"]


def generate_false_emails(count: int, seed: Optional[int] = None) -> list[str]:
    """Email-shaped user@domain strings with invalid/reserved TLDs.

    IANA reserves .invalid, .test, .example, and .localhost as permanently
    non-resolvable TLDs.
    """
    rng = random.Random(seed)
    results = []
    for _ in range(count):
        user = "".join(
            rng.choice(string.ascii_lowercase + string.digits)
            for _ in range(rng.randint(4, 10))
        )
        domain = rng.choice(_DOMAINS)
        tld = rng.choice(_INVALID_TLDS)
        results.append(f"{user}@{domain}{tld}")
    return results


# ── Phone ─────────────────────────────────────────────────────────────────────

# North American Numbering Plan (NANP) reserves area codes starting with 0 or 1,
# and the 555 midrange is commonly used as a fictional/test number in the US.
_INVALID_AREA_CODES = [
    "000", "001", "011", "100", "101", "111",
    "200", "201", "211", "300", "400",
    "500", "555", "600", "700", "800",
    "900", "911",
]


def generate_false_phones(count: int, seed: Optional[int] = None) -> list[str]:
    """Phone-shaped +1-NPA-NXX-XXXX strings with invalid NANP area codes.

    Uses area codes that are reserved, unassigned, or commonly flagged as
    fictional (e.g. 555) in the North American Numbering Plan.
    """
    rng = random.Random(seed)
    results = []
    for _ in range(count):
        area = rng.choice(_INVALID_AREA_CODES)
        exchange = f"{rng.randint(200, 999):03d}"  # NXX: N must be 2-9
        subscriber = f"{rng.randint(0, 9999):04d}"
        results.append(f"+1-{area}-{exchange}-{subscriber}")
    return results


# ── CA RAMQ ───────────────────────────────────────────────────────────────────

_SURNAME_CHARS = "BCDFGHJKLMNPQRSTVWXYZ"
_ALL_LETTERS = string.ascii_uppercase
# Valid RAMQ months: 01–12 (male) and 51–62 (female).
# Invalid: 00, 13–50, 63–99.
_INVALID_MONTHS = [0] + list(range(13, 51)) + list(range(63, 100))


def generate_false_ramqs(count: int, seed: Optional[int] = None) -> list[str]:
    """RAMQ-shaped XXXX YYMM DDSS strings with invalid birth month codes.

    RAMQ uses months 01–12 (male) and 51–62 (female). Any other month value
    (00, 13–50, 63–99) produces a structurally plausible but invalid card number.
    """
    rng = random.Random(seed)
    results = []
    for _ in range(count):
        name = "".join(
            rng.choice(_SURNAME_CHARS if i % 2 == 0 else _ALL_LETTERS)
            for i in range(4)
        )
        year = rng.randint(0, 99)
        month = rng.choice(_INVALID_MONTHS)
        day = rng.randint(1, 28)
        seq = rng.randint(1, 99)
        digits = f"{year:02d}{month:02d}{day:02d}{seq:02d}"
        results.append(f"{name} {digits[:4]} {digits[4:]}")
    return results


# ── Registry ──────────────────────────────────────────────────────────────────

FALSEPOS_GENERATORS: dict[str, "Callable[[int, Optional[int]], list[str]]"] = {
    "credit_card": generate_false_credit_cards,
    "ssn":         generate_false_ssns,
    "sin":         generate_false_sins,
    "iban":        generate_false_ibans,
    "email":       generate_false_emails,
    "phone":       generate_false_phones,
    "ca_ramq":     generate_false_ramqs,
}
