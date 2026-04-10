"""Synthetic generators for remaining Canadian provincial health cards.

Each generator produces structurally valid values for:
  Manitoba (MB)         — 9 digits
  Saskatchewan (SK)     — 9 digits
  Nova Scotia (NS)      — 10 digits, displayed as NNNN NNN NNN
  New Brunswick (NB)    — 10 digits
  PEI                   — 12 digits
  Newfoundland (NL)     — 10 digits
"""
from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


def _n_digits(rng: random.Random, n: int) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


@register_synthetic(PayloadCategory.CA_MB_HEALTH)
class MBHealthSyntheticGenerator(BaseSyntheticGenerator):
    """Manitoba health card: 9 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 9) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_SK_HEALTH)
class SKHealthSyntheticGenerator(BaseSyntheticGenerator):
    """Saskatchewan health card: 9 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 9) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_NS_HEALTH)
class NSHealthSyntheticGenerator(BaseSyntheticGenerator):
    """Nova Scotia health card: 10 digits formatted as NNNN NNN NNN."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        results = []
        for _ in range(count):
            d = _n_digits(rng, 10)
            results.append(f"{d[:4]} {d[4:7]} {d[7:]}")
        return results


@register_synthetic(PayloadCategory.CA_NB_HEALTH)
class NBHealthSyntheticGenerator(BaseSyntheticGenerator):
    """New Brunswick health card: 10 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 10) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_PEI_HEALTH)
class PEIHealthSyntheticGenerator(BaseSyntheticGenerator):
    """PEI health card: 12 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 12) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_NL_HEALTH)
class NLHealthSyntheticGenerator(BaseSyntheticGenerator):
    """Newfoundland health card: 10 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 10) for _ in range(count)]
