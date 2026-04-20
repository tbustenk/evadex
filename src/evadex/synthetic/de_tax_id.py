"""Synthetic German Steuer-Identifikationsnummer (IdNr) generator.

Format: 11 digits, no separators (also commonly displayed as
``NN NNN NNN NNN``).

Validity rules per BZSt spec:

* digit[0] != 0
* In positions 0..9 (the first 10 digits) exactly one digit appears
  either two or three times, and every other digit appears at most
  once. (We always produce the "exactly twice" case, which is the
  common form.)
* digit[10] is the ISO 7064 MOD 11,10 check digit over digits 0..9.
"""
from __future__ import annotations

import random
from typing import Iterator, Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


def _iso7064_mod_11_10_check(digits: list[int]) -> int:
    """ISO 7064 MOD 11,10 check digit. Used by the German IdNr."""
    product = 10
    for d in digits:
        s = (product + d) % 10
        if s == 0:
            s = 10
        product = (s * 2) % 11
    check = (11 - product) % 10
    return check


def _generate_one(rng: random.Random) -> str:
    while True:
        # Pick the digit that will appear twice and 8 distinct other digits.
        all_digits = list(range(10))
        doubled = rng.choice(all_digits)
        others_pool = [d for d in all_digits if d != doubled]
        rng.shuffle(others_pool)
        # 8 distinct digits + the doubled digit appearing twice = 10 slots.
        slots = others_pool[:8] + [doubled, doubled]
        rng.shuffle(slots)
        if slots[0] != 0:
            break
    check = _iso7064_mod_11_10_check(slots)
    return "".join(str(d) for d in slots) + str(check)


@register_synthetic(PayloadCategory.DE_TAX_ID)
class DETaxIdSyntheticGenerator(BaseSyntheticGenerator):
    """Generates valid German Steuer-Identifikationsnummer values."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]

    def iter_generate(self, count: int, seed: Optional[int] = None) -> Iterator[str]:
        rng = random.Random(seed)
        for _ in range(count):
            yield _generate_one(rng)
