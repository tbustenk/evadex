"""Synthetic credit card number generator (Luhn-valid)."""
from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic
from evadex.synthetic.validators import luhn_check_digit

# (prefix, total_length) for Visa, Mastercard, Amex, Discover
_PREFIXES: list[tuple[str, int]] = [
    ("4", 16),               # Visa
    ("51", 16), ("52", 16), ("53", 16), ("54", 16), ("55", 16),  # Mastercard
    ("34", 15), ("37", 15),  # Amex
    ("6011", 16),            # Discover
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
