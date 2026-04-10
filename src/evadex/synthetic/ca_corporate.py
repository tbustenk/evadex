"""Synthetic generators for Canadian corporate identifiers.

  Business Number (BN)      — 9 digits (issued by CRA)
  GST/HST registration      — 9-digit BN + RT + 4 digits (e.g. 123456789RT0001)
  Transit/routing number    — NNNNN-NNN (5-digit branch + 3-digit institution)
  Bank account              — 7–12 random digits
"""
from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


def _n_digits(rng: random.Random, n: int) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


@register_synthetic(PayloadCategory.CA_BUSINESS_NUMBER)
class BusinessNumberSyntheticGenerator(BaseSyntheticGenerator):
    """Canadian Business Number (BN): 9 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_n_digits(rng, 9) for _ in range(count)]


@register_synthetic(PayloadCategory.CA_GST_HST)
class GSTHSTSyntheticGenerator(BaseSyntheticGenerator):
    """Canadian GST/HST registration: 9-digit BN + RT + 4-digit account number."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        results = []
        for _ in range(count):
            bn = _n_digits(rng, 9)
            account_num = f"{rng.randint(1, 9999):04d}"
            results.append(f"{bn}RT{account_num}")
        return results


@register_synthetic(PayloadCategory.CA_TRANSIT_NUMBER)
class TransitNumberSyntheticGenerator(BaseSyntheticGenerator):
    """Canadian transit/routing number: NNNNN-NNN (5-digit branch + 3-digit institution)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        results = []
        for _ in range(count):
            branch = _n_digits(rng, 5)
            institution = _n_digits(rng, 3)
            results.append(f"{branch}-{institution}")
        return results


@register_synthetic(PayloadCategory.CA_BANK_ACCOUNT)
class BankAccountSyntheticGenerator(BaseSyntheticGenerator):
    """Canadian bank account: 7–12 random digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        results = []
        for _ in range(count):
            length = rng.randint(7, 12)
            results.append(_n_digits(rng, length))
        return results
