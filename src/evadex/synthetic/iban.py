"""Synthetic IBAN generator for GB, DE, and FR formats.

Each generated IBAN has a valid ISO 13616 mod-97 checksum.
"""
from __future__ import annotations

import random
import string
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic
from evadex.synthetic.validators import iban_check_digits


def _rand_digits(rng: random.Random, n: int) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


def _rand_alpha(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(n))


def _generate_gb(rng: random.Random) -> str:
    """GB IBAN: GB{cc}{4-letter bank code}{6-digit sort code}{8-digit account}."""
    bank = _rand_alpha(rng, 4)
    sort = _rand_digits(rng, 6)
    account = _rand_digits(rng, 8)
    bban = bank + sort + account
    cc = iban_check_digits("GB", bban)
    return f"GB{cc}{bban}"


def _generate_de(rng: random.Random) -> str:
    """DE IBAN: DE{cc}{8-digit BLZ}{10-digit account}."""
    blz = _rand_digits(rng, 8)
    account = _rand_digits(rng, 10)
    bban = blz + account
    cc = iban_check_digits("DE", bban)
    return f"DE{cc}{bban}"


def _generate_fr(rng: random.Random) -> str:
    """FR IBAN: FR{cc}{5-digit bank}{5-digit branch}{11-char account}{2-digit rib key}."""
    bank = _rand_digits(rng, 5)
    branch = _rand_digits(rng, 5)
    account = _rand_digits(rng, 11)
    rib = _rand_digits(rng, 2)
    bban = bank + branch + account + rib
    cc = iban_check_digits("FR", bban)
    return f"FR{cc}{bban}"


_GENERATORS = [_generate_gb, _generate_de, _generate_fr]


@register_synthetic(PayloadCategory.IBAN)
class IBANSyntheticGenerator(BaseSyntheticGenerator):
    """Generates valid IBANs for GB, DE, and FR with correct mod-97 checksums."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [rng.choice(_GENERATORS)(rng) for _ in range(count)]
