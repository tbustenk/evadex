"""Seeds for check-digit identifiers must pass their check digit.

A seed that fails its own checksum can only be reported through a looser,
unvalidated sibling rule (Siphon's `Germany IBAN` or `US DEA Number`, say).
Anything that recovers an evaded value and then demands the check digit
rejects it, so every evasion of that seed looks like a scanner miss when
the seed is what is wrong.
"""
import pytest

from evadex.core.result import PayloadCategory
from evadex.payloads.builtins import BUILTIN_PAYLOADS


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def _luhn(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban(value: str) -> bool:
    s = value.replace(" ", "")
    s = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in s)) % 97 == 1


def _dea(value: str) -> bool:
    d = [int(c) for c in value[2:]]
    return (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]


def _seeds(category: PayloadCategory) -> list[str]:
    return [p.value for p in BUILTIN_PAYLOADS if p.category == category]


_IBAN_CATEGORIES = [c for c in PayloadCategory if c.name.endswith("IBAN")]


@pytest.mark.parametrize("category", _IBAN_CATEGORIES, ids=lambda c: c.value)
def test_iban_seeds_pass_mod97(category):
    for value in _seeds(category):
        assert _iban(value), f"{category.value} seed {value} fails mod-97"


def test_us_dea_seed_passes_check_digit():
    for value in _seeds(PayloadCategory.US_DEA):
        assert _dea(value), value


@pytest.mark.parametrize(
    "category",
    [PayloadCategory.CA_BUSINESS_NUMBER, PayloadCategory.CA_GST_HST],
    ids=lambda c: c.value,
)
def test_business_number_root_passes_luhn(category):
    # The GST/HST account is the 9-digit BN root plus `RT0001`.
    for value in _seeds(category):
        root = _digits(value)[:9]
        assert _luhn(root), f"{category.value} seed {value}: root {root} fails Luhn"


def test_sin_seed_passes_luhn():
    for value in _seeds(PayloadCategory.SIN):
        assert _luhn(_digits(value)), value
