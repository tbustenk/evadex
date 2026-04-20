"""Synthetic UK National Insurance Number (NIN) generator.

Format: ``XX NNNNNN X`` — two letters, six digits, one letter.

Validity rules per HMRC spec (CWG2 Appendix B):
 * First letter: not D, F, I, Q, U, V
 * Second letter: not D, F, I, O, Q, U, V
 * Disallowed full prefixes: BG, GB, NK, KN, NT, TN, ZZ
 * Suffix: A, B, C, or D
"""
from __future__ import annotations

import random
import string
from typing import Iterator, Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


_FIRST_LETTERS = [c for c in string.ascii_uppercase if c not in set("DFIQUV")]
_SECOND_LETTERS = [c for c in string.ascii_uppercase if c not in set("DFIOQUV")]
_DISALLOWED_PREFIXES = {"BG", "GB", "NK", "KN", "NT", "TN", "ZZ"}
_SUFFIXES = ["A", "B", "C", "D"]


def _generate_one(rng: random.Random) -> str:
    while True:
        a = rng.choice(_FIRST_LETTERS)
        b = rng.choice(_SECOND_LETTERS)
        if a + b not in _DISALLOWED_PREFIXES:
            break
    digits = "".join(str(rng.randint(0, 9)) for _ in range(6))
    suffix = rng.choice(_SUFFIXES)
    return f"{a}{b} {digits[:2]} {digits[2:4]} {digits[4:]} {suffix}"


@register_synthetic(PayloadCategory.UK_NIN)
class UKNINSyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally-valid UK National Insurance Numbers."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]

    def iter_generate(self, count: int, seed: Optional[int] = None) -> Iterator[str]:
        rng = random.Random(seed)
        for _ in range(count):
            yield _generate_one(rng)
