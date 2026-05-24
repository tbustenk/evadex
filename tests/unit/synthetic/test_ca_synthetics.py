"""Format + reproducibility tests for the Canadian synthetic generators.

These modules (``ca_corporate.py``, ``ca_health_cards.py``,
``ca_drivers_licences.py``) are exercised indirectly through the scan
and falsepos flows but had no dedicated test file. Coverage here is
deliberately format/structure-focused — the underlying generators
don't carry checksums, so we verify shape, character class, length,
and the same-seed reproducibility contract.
"""

from __future__ import annotations

import re

import pytest

from evadex.synthetic.ca_corporate import (
    BankAccountSyntheticGenerator,
    BusinessNumberSyntheticGenerator,
    GSTHSTSyntheticGenerator,
    TransitNumberSyntheticGenerator,
)
from evadex.synthetic.ca_drivers_licences import (
    MBDriversSyntheticGenerator,
    NBDriversSyntheticGenerator,
    NLDriversSyntheticGenerator,
    NSDriversSyntheticGenerator,
    PEIDriversSyntheticGenerator,
    SKDriversSyntheticGenerator,
)
from evadex.synthetic.ca_health_cards import (
    MBHealthSyntheticGenerator,
    NBHealthSyntheticGenerator,
    NLHealthSyntheticGenerator,
    NSHealthSyntheticGenerator,
    PEIHealthSyntheticGenerator,
    SKHealthSyntheticGenerator,
)


# ── ca_corporate ─────────────────────────────────────────────────────────────


def test_business_number_is_9_digits():
    values = BusinessNumberSyntheticGenerator().generate(100, seed=1)
    assert len(values) == 100
    assert all(re.fullmatch(r"\d{9}", v) for v in values)


def test_gst_hst_has_rt_segment():
    values = GSTHSTSyntheticGenerator().generate(50, seed=2)
    assert all(re.fullmatch(r"\d{9}RT\d{4}", v) for v in values)
    # Account-number portion must never be 0000 — that suffix means
    # "primary registration"; downstream consumers expect a non-zero
    # branch account in synthetic data.
    for v in values:
        assert v[-4:] != "0000"


def test_transit_number_format():
    values = TransitNumberSyntheticGenerator().generate(30, seed=3)
    assert all(re.fullmatch(r"\d{5}-\d{3}", v) for v in values)


def test_bank_account_length_range():
    values = BankAccountSyntheticGenerator().generate(50, seed=4)
    for v in values:
        assert v.isdigit()
        assert 7 <= len(v) <= 12


# ── ca_health_cards (the six remaining provinces) ───────────────────────────

_HEALTH_CASES = [
    (MBHealthSyntheticGenerator, r"\d{9}"),
    (SKHealthSyntheticGenerator, r"\d{9}"),
    (NSHealthSyntheticGenerator, r"\d{4} \d{3} \d{3}"),
    (NBHealthSyntheticGenerator, r"\d{10}"),
    (PEIHealthSyntheticGenerator, r"\d{12}"),
    (NLHealthSyntheticGenerator, r"\d{10}"),
]


@pytest.mark.parametrize("cls,pattern", _HEALTH_CASES)
def test_health_card_format(cls, pattern):
    values = cls().generate(40, seed=5)
    assert len(values) == 40
    assert all(re.fullmatch(pattern, v) for v in values), values[:3]


# ── ca_drivers_licences (provinces not covered by dedicated files) ──────────

_DL_CASES = [
    MBDriversSyntheticGenerator,
    SKDriversSyntheticGenerator,
    NSDriversSyntheticGenerator,
    NBDriversSyntheticGenerator,
    PEIDriversSyntheticGenerator,
    NLDriversSyntheticGenerator,
]


@pytest.mark.parametrize("cls", _DL_CASES)
def test_drivers_licence_generates_correct_count(cls):
    values = cls().generate(20, seed=6)
    assert len(values) == 20
    # All DLs are non-empty and use only ASCII chars commonly found
    # in provincial DL formats (digits, uppercase letters, hyphens).
    for v in values:
        assert v
        assert re.fullmatch(r"[A-Z0-9 -]+", v), v


# ── Seeded reproducibility ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cls",
    [
        BusinessNumberSyntheticGenerator,
        GSTHSTSyntheticGenerator,
        TransitNumberSyntheticGenerator,
        BankAccountSyntheticGenerator,
        MBHealthSyntheticGenerator,
        NSHealthSyntheticGenerator,
        PEIHealthSyntheticGenerator,
        MBDriversSyntheticGenerator,
        NLDriversSyntheticGenerator,
    ],
)
def test_same_seed_same_output(cls):
    a = cls().generate(15, seed=999)
    b = cls().generate(15, seed=999)
    assert a == b
