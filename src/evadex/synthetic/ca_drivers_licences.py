"""Synthetic generators for remaining Canadian provincial driver's licences.

Each generator produces structurally valid values for:
  Manitoba (MB)         — LL-NNN-NNN-NNN (2 letters + 3×3 digit groups)
  Saskatchewan (SK)     — 8 digits
  Nova Scotia (NS)      — LLNNNNNNN (2 letters + 7 digits)
  New Brunswick (NB)    — 7 digits
  PEI                   — 6 digits
  Newfoundland (NL)     — L-NNNNNNNNN (1 letter + 9 digits)
"""

from __future__ import annotations

import random
import string
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


def _n_digits(rng: random.Random, n: int) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


def _n_letters(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(n))


@register_synthetic(PayloadCategory.CA_MB_DRIVERS)
class MBDriversSyntheticGenerator(BaseSyntheticGenerator):
    """Manitoba driver's licence: 13 characters, ``AKKKKAKXX9XX9``.

    Layout from the FMCSA Canadian licence reference: A is a letter, K a
    letter or ``*`` (padding when the surname is shorter than five letters),
    X a letter or digit, 9 a digit. The leading letters derive from the
    holder's name.
    """

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        alnum = string.ascii_uppercase + string.digits
        results = []
        for _ in range(count):
            surname = _n_letters(rng, rng.randint(2, 5)).ljust(5, "*")
            first = _n_letters(rng, 1)
            middle = rng.choice([_n_letters(rng, 1), "*"])
            x1 = "".join(rng.choice(alnum) for _ in range(2))
            x2 = "".join(rng.choice(alnum) for _ in range(2))
            results.append(
                f"{surname}{first}{middle}{x1}{_n_digits(rng, 1)}{x2}{_n_digits(rng, 1)}"
            )
        return results


@register_synthetic(PayloadCategory.CA_SK_DRIVERS)
class SKDriversSyntheticGenerator(BaseSyntheticGenerator):
    """Saskatchewan driver's licence: 8 digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 8) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_NS_DRIVERS)
class NSDriversSyntheticGenerator(BaseSyntheticGenerator):
    """Nova Scotia driver's licence: 2 letters + 7 digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_letters(rng, 2) + _n_digits(rng, 7) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_NB_DRIVERS)
class NBDriversSyntheticGenerator(BaseSyntheticGenerator):
    """New Brunswick driver's licence: 7 digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 7) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_PEI_DRIVERS)
class PEIDriversSyntheticGenerator(BaseSyntheticGenerator):
    """PEI driver's licence: 6 digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 6) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_NL_DRIVERS)
class NLDriversSyntheticGenerator(BaseSyntheticGenerator):
    """Newfoundland driver's licence: 1 letter + 9 digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_letters(rng, 1) + _n_digits(rng, 9) for _ in range(count)]
