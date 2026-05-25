"""Tests verifying improved false positive generators produce genuinely invalid values."""

import re
import pytest

from evadex.falsepos.generators import generate_false_ssns, generate_false_ramqs
from evadex.synthetic.validators import luhn_check_digit


# ── SSN validators ────────────────────────────────────────────────────────────

_SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_RESERVED_AREAS = {"000", "666"} | {f"{n:03d}" for n in range(900, 1000)}
# SSNs known to never be validly issued (published test fixtures, ITIN
# placeholder, etc.)
_KNOWN_TEST_SSNS = {
    "078-05-1120",  # Woolworth wallet insert — used en masse as "test" SSN
    "219-09-9999",  # widely cited test SSN
    "987-65-4321",  # ITIN placeholder published in SSA FAQ
}


def _ssn_is_invalid(ssn: str) -> bool:
    """Return True if the SSN is invalid per SSA rules or known test fixtures."""
    if not _SSN_RE.match(ssn):
        return True
    if ssn in _KNOWN_TEST_SSNS:
        return True
    area, group, serial = ssn.split("-")
    if area in _RESERVED_AREAS:
        return True
    if group == "00":
        return True
    if serial == "0000":
        return True
    return False


def test_generate_false_ssns_count():
    result = generate_false_ssns(20)
    assert len(result) == 20


def test_generate_false_ssns_all_invalid():
    ssns = generate_false_ssns(40, seed=42)
    for ssn in ssns:
        assert _ssn_is_invalid(ssn), f"SSN {ssn!r} should be invalid"


def test_generate_false_ssns_matches_pattern():
    ssns = generate_false_ssns(20, seed=0)
    for ssn in ssns:
        # Allow 00-XX-XXXX style (2-digit "area") from EIN misparse pattern
        assert re.match(r"^\d{2,3}-\d{1,2}-\d{4}$", ssn), f"Unexpected format: {ssn!r}"


def test_generate_false_ssns_covers_group_00():
    ssns = generate_false_ssns(40, seed=7)
    has_group_00 = any(s.split("-")[1] == "00" for s in ssns if len(s.split("-")) == 3)
    assert has_group_00, "Expected at least one SSN with group=00"


def test_generate_false_ssns_covers_serial_0000():
    ssns = generate_false_ssns(40, seed=7)
    has_serial_0000 = any(
        s.split("-")[2] == "0000" for s in ssns if len(s.split("-")) == 3
    )
    assert has_serial_0000, "Expected at least one SSN with serial=0000"


def test_generate_false_ssns_has_variety():
    ssns = generate_false_ssns(40, seed=99)
    unique = set(ssns)
    assert len(unique) >= 15, "Expected at least 15 distinct invalid SSN patterns"


# ── RAMQ validators ───────────────────────────────────────────────────────────

_RAMQ_RE = re.compile(r"^[A-Z]{4} \d{4} \d{4}$")


def _ramq_is_invalid(ramq: str) -> bool:
    """Return True if the RAMQ has an invalid month, day, or sequence."""
    if not _RAMQ_RE.match(ramq):
        return True
    # digits portion: YYMM DDSS → positions after 5-char name part
    digits = ramq[5:].replace(" ", "")  # 8 digits: YYMM DDSS
    month = int(digits[2:4])
    day = int(digits[4:6])
    seq = int(digits[6:8])
    # Valid months: 01-12 (male) and 51-62 (female)
    valid_months = set(range(1, 13)) | set(range(51, 63))
    if month not in valid_months:
        return True
    # Valid days: 01-31
    if day == 0 or day > 31:
        return True
    # Valid sequences: 01-99
    if seq == 0:
        return True
    return False


def test_generate_false_ramqs_count():
    result = generate_false_ramqs(12)
    assert len(result) == 12


def test_generate_false_ramqs_all_invalid():
    ramqs = generate_false_ramqs(36, seed=0)
    for r in ramqs:
        assert _ramq_is_invalid(r), f"RAMQ {r!r} should be invalid"


def test_generate_false_ramqs_covers_invalid_day():
    ramqs = generate_false_ramqs(36, seed=5)
    has_invalid_day = any(
        _RAMQ_RE.match(r) and int(r[5:].replace(" ", "")[4:6]) >= 32 for r in ramqs
    )
    assert has_invalid_day, "Expected at least one RAMQ with invalid day (32+)"


def test_generate_false_ramqs_covers_seq_zero():
    ramqs = generate_false_ramqs(36, seed=5)
    has_seq_zero = any(
        _RAMQ_RE.match(r) and int(r[5:].replace(" ", "")[6:8]) == 0 for r in ramqs
    )
    assert has_seq_zero, "Expected at least one RAMQ with sequence=00"
