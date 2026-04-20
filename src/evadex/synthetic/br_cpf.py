"""Synthetic Brazilian CPF (Cadastro de Pessoas Físicas) generator.

Format: ``NNN.NNN.NNN-DD``

Two check digits, computed sequentially:

* DV1: ``Σ digit[i] · (10 − i)`` for i in 0..8, mod 11. If <2, DV1 = 0;
  else DV1 = 11 − rem.
* DV2: ``Σ digit[i] · (11 − i)`` for i in 0..9 (where digit[9] = DV1),
  mod 11. If <2, DV2 = 0; else DV2 = 11 − rem.
"""
from __future__ import annotations

import random
from typing import Iterator, Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


def _check_digit(digits: list[int], multiplier_start: int) -> int:
    total = sum(d * (multiplier_start - i) for i, d in enumerate(digits))
    rem = total % 11
    return 0 if rem < 2 else 11 - rem


def _generate_one(rng: random.Random) -> str:
    base = [rng.randint(0, 9) for _ in range(9)]
    # Reject all-same-digit base (e.g. 111111111) — those CPFs are valid
    # by checksum but reserved as test/blocked values by Receita Federal.
    while len(set(base)) == 1:
        base = [rng.randint(0, 9) for _ in range(9)]
    dv1 = _check_digit(base, 10)
    dv2 = _check_digit(base + [dv1], 11)
    s = "".join(str(d) for d in base) + str(dv1) + str(dv2)
    return f"{s[:3]}.{s[3:6]}.{s[6:9]}-{s[9:]}"


@register_synthetic(PayloadCategory.BR_CPF)
class BRCPFSyntheticGenerator(BaseSyntheticGenerator):
    """Generates valid Brazilian CPF numbers (correct two-pass checksum)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]

    def iter_generate(self, count: int, seed: Optional[int] = None) -> Iterator[str]:
        rng = random.Random(seed)
        for _ in range(count):
            yield _generate_one(rng)
