"""Shared validation utilities for synthetic value generators."""
from __future__ import annotations


# ── Luhn (credit card + Canadian SIN) ─────────────────────────────────────────

def luhn_check(number: str) -> bool:
    """Return True if *number* (digits only) passes the Luhn algorithm."""
    if not number.isdigit():
        return False
    total = 0
    for i, digit in enumerate(reversed(number)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(digits: list[int]) -> int:
    """Return the Luhn check digit for a digit list (without the check digit).

    The check digit is appended to complete a number that passes Luhn.
    """
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:   # even from right → odd position (rightmost is pos 1)
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


# ── IBAN checksum ──────────────────────────────────────────────────────────────

def iban_check_digits(country: str, bban: str) -> str:
    """Compute the two IBAN check digits for *country* + *bban*.

    Follows ISO 13616: rearrange to ``bban + country + "00"``, replace
    letters A-Z with 10-35, compute ``98 - (numeric mod 97)``.

    Returns:
        Two-character check digit string, zero-padded (e.g. ``"03"``).
    """
    rearranged = bban + country + "00"
    numeric = "".join(
        str(ord(ch.upper()) - ord("A") + 10) if ch.isalpha() else ch
        for ch in rearranged
    )
    remainder = int(numeric) % 97
    check = 98 - remainder
    return f"{check:02d}"


def iban_valid(iban: str) -> bool:
    """Return True if *iban* has a valid ISO 13616 checksum."""
    iban = iban.replace(" ", "").upper()
    if len(iban) < 5:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(
        str(ord(ch) - ord("A") + 10) if ch.isalpha() else ch
        for ch in rearranged
    )
    return int(numeric) % 97 == 1


# ── Canadian SIN checksum ──────────────────────────────────────────────────────

def sin_valid(sin: str) -> bool:
    """Return True if *sin* passes the 9-digit Luhn check used for Canadian SINs.

    Digits 0 are accepted because legacy SINs (not currently issued but still
    detectable by DLP scanners) may start with 0.  The synthetic generator uses
    digits 1-7 for realistic output.
    """
    digits = sin.replace(" ", "").replace("-", "")
    if len(digits) != 9 or not digits.isdigit():
        return False
    return luhn_check(digits)
