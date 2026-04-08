"""Synthetic Canadian Social Insurance Number (SIN) generator.

SINs are 9-digit numbers that pass the Luhn algorithm.
The first digit is 1-7 (residents) or 9 (temporary workers).
First digit 0 and 8 are not assigned.
"""
from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic
from evadex.synthetic.validators import luhn_check_digit


def _generate_one(rng: random.Random) -> str:
    # First digit: 1-7 for permanent residents (most common)
    first = rng.randint(1, 7)
    # Next 7 digits are random
    middle = [rng.randint(0, 9) for _ in range(7)]
    digits_without_check = [first] + middle
    check = luhn_check_digit(digits_without_check)
    all_digits = digits_without_check + [check]
    # Format as NNN NNN NNN
    s = "".join(str(d) for d in all_digits)
    return f"{s[:3]} {s[3:6]} {s[6:]}"


@register_synthetic(PayloadCategory.SIN)
class SINSyntheticGenerator(BaseSyntheticGenerator):
    """Generates valid Canadian Social Insurance Numbers (SIN).

    Each value passes the Luhn checksum and uses a realistic first digit (1-7).
    Formatted as ``NNN NNN NNN``.
    """

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]
