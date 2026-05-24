"""Synthetic credit card number generator (Luhn-valid)."""

from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic
from evadex.synthetic.validators import luhn_check_digit

# BIN prefixes reserved by the major brands as "test" / sandbox ranges. These
# pass the same brand-detection regexes as real cards (so DLP scanners still
# classify them correctly), but they never correspond to a real issued card —
# safe to ship inside a bank's synthetic-test corpus without an accidental hit
# against a customer account.
#
# Sources:
#   * Visa:        4111 1111 1111 1111  (PCI test number, published by Visa)
#   * Mastercard:  5500 0000 0000 0004  (Mastercard sandbox)
#   * Amex:        3714 4963 5398 431   (Amex test) and 3782 8224 6310 005
#   * Discover:    6011 1111 1111 1117  (Discover sandbox)
#
# We only fix the BIN; remaining body digits are still randomised + Luhn-valid.
_PREFIXES: list[tuple[str, int]] = [
    ("4111", 16),  # Visa test BIN
    ("5500", 16),  # Mastercard test BIN
    ("3714", 15),  # Amex test BIN
    ("3782", 15),  # Amex test BIN (alt)
    ("6011", 16),  # Discover test BIN
]


def _generate_one(rng: random.Random) -> str:
    prefix, length = rng.choice(_PREFIXES)
    body_len = length - len(prefix) - 1
    body = [rng.randint(0, 9) for _ in range(body_len)]
    all_digits = [int(c) for c in prefix] + body
    check = luhn_check_digit(all_digits)
    return prefix + "".join(str(d) for d in body) + str(check)


@register_synthetic(PayloadCategory.CREDIT_CARD)
class CreditCardSyntheticGenerator(BaseSyntheticGenerator):
    """Generates Luhn-valid credit card numbers for Visa, Mastercard, Amex, Discover."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]
