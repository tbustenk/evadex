"""Synthetic Australian Medicare card-number generator.

Format: ``NNNN NNNNN N`` — 10 digits total, presented as 4+5+1.

Layout::

    digits 1..8   : card number (first digit 2-6 per Services Australia)
    digit 9       : check digit  (weighted sum of d1..d8 mod 10)
    digit 10      : issue / individual reference number (1..9)

Check-digit weights follow the Services Australia spec
(weights for d1..d8 = 1, 3, 7, 9, 1, 3, 7, 9; check = sum mod 10).
"""
from __future__ import annotations

import random
from typing import Iterator, Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9)


def _generate_one(rng: random.Random) -> str:
    first = rng.randint(2, 6)
    rest = [rng.randint(0, 9) for _ in range(7)]
    base = [first] + rest
    check = sum(d * w for d, w in zip(base, _WEIGHTS)) % 10
    issue = rng.randint(1, 9)
    s = "".join(str(d) for d in base) + str(check) + str(issue)
    return f"{s[:4]} {s[4:9]} {s[9]}"


@register_synthetic(PayloadCategory.AU_MEDICARE)
class AUMedicareSyntheticGenerator(BaseSyntheticGenerator):
    """Generates valid Australian Medicare numbers (correct check digit)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]

    def iter_generate(self, count: int, seed: Optional[int] = None) -> Iterator[str]:
        rng = random.Random(seed)
        for _ in range(count):
            yield _generate_one(rng)
