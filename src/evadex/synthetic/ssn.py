"""Synthetic US Social Security Number (SSN) generator.

Format: ``AAA-BB-CCCC``

Validity rules enforced (Social Security Administration spec):
 * Area (AAA): cannot be ``000``, ``666``, or in ``900-999``
 * Group (BB): cannot be ``00``
 * Serial (CCCC): cannot be ``0000``
"""
from __future__ import annotations

import random
from typing import Iterator, Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


# Areas the SSA never assigns. 666 is folklore-driven; 9xx is reserved
# for ITIN / advertising / structurally-invalid placeholders.
_INVALID_AREA = {0, 666}


def _generate_one(rng: random.Random) -> str:
    while True:
        area = rng.randint(1, 899)
        if area not in _INVALID_AREA:
            break
    group = rng.randint(1, 99)
    serial = rng.randint(1, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"


@register_synthetic(PayloadCategory.SSN)
class SSNSyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally-valid US Social Security Numbers."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]

    def iter_generate(self, count: int, seed: Optional[int] = None) -> Iterator[str]:
        """Streaming variant — yields one SSN at a time so very large
        ``count`` values do not materialise the full list in memory."""
        rng = random.Random(seed)
        for _ in range(count):
            yield _generate_one(rng)
