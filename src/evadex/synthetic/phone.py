"""Synthetic Canadian phone number generator (E.164 format).

Generates Canadian numbers: +1 followed by a valid NPA (area code)
and a 7-digit subscriber number.

Canadian NPAs (area codes) are in the range 200-999 excluding special codes.
We use a representative sample of real Canadian area codes to keep
generated numbers realistic for DLP pattern matching.
"""
from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic

# Representative sample of real Canadian area codes
_CA_AREA_CODES = [
    # Ontario
    416, 647, 437, 905, 289, 365, 519, 226, 249, 343, 613, 807, 705, 249,
    # Quebec
    514, 438, 450, 579, 418, 581, 819, 873,
    # British Columbia
    604, 778, 236, 250, 672,
    # Alberta
    403, 587, 825, 780,
    # Manitoba
    204, 431,
    # Saskatchewan
    306, 639,
    # Nova Scotia / New Brunswick / PEI
    902, 782,
    # Newfoundland
    709,
    # Territories
    867,
]


def _generate_one(rng: random.Random) -> str:
    npa = rng.choice(_CA_AREA_CODES)
    # Subscriber number: NXX-XXXX where N is 2-9 (central office exchange rules)
    nxx = rng.randint(200, 999)
    xxxx = rng.randint(0, 9999)
    return f"+1-{npa}-{nxx}-{xxxx:04d}"


@register_synthetic(PayloadCategory.PHONE)
class CanadianPhoneSyntheticGenerator(BaseSyntheticGenerator):
    """Generates Canadian phone numbers in E.164 format: ``+1-NPA-NXX-XXXX``."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]
