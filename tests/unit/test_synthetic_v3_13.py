"""Tests for the synthetic generators introduced in v3.13.0
(SSN, UK NIN, BR CPF, AU Medicare, DE Tax ID, US DL)."""
from __future__ import annotations

import re
from collections import Counter

import pytest

from evadex.synthetic.au_medicare import AUMedicareSyntheticGenerator
from evadex.synthetic.br_cpf import BRCPFSyntheticGenerator
from evadex.synthetic.de_tax_id import (
    DETaxIdSyntheticGenerator,
    _iso7064_mod_11_10_check,
)
from evadex.synthetic.ssn import SSNSyntheticGenerator
from evadex.synthetic.uk_nin import UKNINSyntheticGenerator
from evadex.synthetic.us_dl import (
    USDriversLicenceSyntheticGenerator,
    _STATE_FORMATS,
)


# ── SSN ─────────────────────────────────────────────────────────────────────

_SSN_RE = re.compile(r"^(\d{3})-(\d{2})-(\d{4})$")


@pytest.mark.parametrize("count", [10, 100, 1000])
def test_ssn_format_and_reserved_ranges(count: int):
    values = SSNSyntheticGenerator().generate(count, seed=42)
    assert len(values) == count
    for v in values:
        m = _SSN_RE.match(v)
        assert m, f"SSN format violation: {v!r}"
        area, group, serial = m.group(1), m.group(2), m.group(3)
        assert area not in ("000", "666"), f"reserved area: {v!r}"
        assert not (900 <= int(area) <= 999), f"ITIN/9xx area: {v!r}"
        assert group != "00", f"reserved group 00: {v!r}"
        assert serial != "0000", f"reserved serial 0000: {v!r}"


def test_ssn_iter_generate_streams():
    """iter_generate yields one value at a time and matches generate()."""
    g = SSNSyntheticGenerator()
    a = g.generate(50, seed=99)
    b = list(g.iter_generate(50, seed=99))
    assert a == b


# ── UK NIN ──────────────────────────────────────────────────────────────────

_NIN_RE = re.compile(r"^([A-Z]{2}) (\d{2}) (\d{2}) (\d{2}) ([A-Z])$")
_DISALLOWED = {"BG", "GB", "NK", "KN", "NT", "TN", "ZZ"}
_FIRST_BAD = set("DFIQUV")
_SECOND_BAD = set("DFIOQUV")


@pytest.mark.parametrize("count", [10, 100, 1000])
def test_uk_nin_format_and_prefix_rules(count: int):
    values = UKNINSyntheticGenerator().generate(count, seed=42)
    assert len(values) == count
    for v in values:
        m = _NIN_RE.match(v)
        assert m, f"UK NIN format violation: {v!r}"
        prefix = m.group(1)
        assert prefix[0] not in _FIRST_BAD, f"bad first letter: {v!r}"
        assert prefix[1] not in _SECOND_BAD, f"bad second letter: {v!r}"
        assert prefix not in _DISALLOWED, f"reserved prefix: {v!r}"
        assert m.group(5) in {"A", "B", "C", "D"}, f"bad suffix: {v!r}"


# ── Brazilian CPF ───────────────────────────────────────────────────────────

_CPF_RE = re.compile(r"^(\d{3})\.(\d{3})\.(\d{3})-(\d{2})$")


def _cpf_check(digits: list[int], multiplier_start: int) -> int:
    """Independent re-implementation of the CPF check digit, used purely
    to verify the production generator's checksum from a different code
    path."""
    total = sum(d * (multiplier_start - i) for i, d in enumerate(digits))
    rem = total % 11
    return 0 if rem < 2 else 11 - rem


@pytest.mark.parametrize("count", [10, 100, 1000])
def test_cpf_checksum_and_format(count: int):
    values = BRCPFSyntheticGenerator().generate(count, seed=42)
    assert len(values) == count
    for v in values:
        m = _CPF_RE.match(v)
        assert m, f"CPF format violation: {v!r}"
        digits = [int(d) for d in v if d.isdigit()]
        base = digits[:9]
        # Two-pass checksum verification.
        assert digits[9] == _cpf_check(base, 10), f"DV1 invalid: {v!r}"
        assert digits[10] == _cpf_check(base + [digits[9]], 11), \
            f"DV2 invalid: {v!r}"
        assert len(set(base)) > 1, f"all-same-digit base: {v!r}"


# ── Australian Medicare ─────────────────────────────────────────────────────

_MEDICARE_RE = re.compile(r"^(\d{4}) (\d{5}) (\d)$")
_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9)


@pytest.mark.parametrize("count", [10, 100, 1000])
def test_medicare_check_digit(count: int):
    values = AUMedicareSyntheticGenerator().generate(count, seed=42)
    assert len(values) == count
    for v in values:
        m = _MEDICARE_RE.match(v)
        assert m, f"Medicare format violation: {v!r}"
        digits = [int(d) for d in v if d.isdigit()]
        base = digits[:8]
        check_expected = sum(d * w for d, w in zip(base, _WEIGHTS)) % 10
        assert digits[8] == check_expected, f"check digit invalid: {v!r}"
        assert 2 <= base[0] <= 6, f"first-digit out of range: {v!r}"
        assert 1 <= digits[9] <= 9, f"issue digit out of range: {v!r}"


# ── German Steuer-IdNr ──────────────────────────────────────────────────────

@pytest.mark.parametrize("count", [10, 100, 1000])
def test_de_tax_id_format_and_check_digit(count: int):
    values = DETaxIdSyntheticGenerator().generate(count, seed=42)
    assert len(values) == count
    for v in values:
        assert len(v) == 11 and v.isdigit(), f"format violation: {v!r}"
        assert v[0] != "0", f"first digit 0: {v!r}"
        digits = [int(d) for d in v]
        # Check digit (position 10) recomputable from positions 0..9.
        assert digits[10] == _iso7064_mod_11_10_check(digits[:10]), \
            f"check digit invalid: {v!r}"
        # Duplicate-digit rule: in positions 0..9, exactly one digit
        # appears more than once (production code emits "exactly twice").
        counts = Counter(digits[:10])
        repeated = [d for d, c in counts.items() if c > 1]
        assert len(repeated) == 1, f"duplicate-digit rule violated: {v!r}"
        assert counts[repeated[0]] == 2, f"expected exactly-twice: {v!r}"


# ── US Driver's licence ─────────────────────────────────────────────────────

def test_us_dl_states_present():
    """All 50 + DC formats are present in the cycle."""
    assert len(_STATE_FORMATS) == 51
    state_names = {s for s, _ in _STATE_FORMATS}
    for required in ("California", "DC", "Texas", "Wyoming"):
        assert required in state_names


@pytest.mark.parametrize("count", [10, 100, 1000])
def test_us_dl_format_conformance(count: int):
    values = USDriversLicenceSyntheticGenerator().generate(count, seed=42)
    assert len(values) == count
    # Every value must fit at least one state's format spec exactly.
    import string
    spec_to_re = {}
    for _, spec in _STATE_FORMATS:
        pattern = (spec.replace("D", r"\d")
                       .replace("L", "[A-Z]")
                       .replace("X", "[A-Z0-9]"))
        spec_to_re.setdefault(spec, re.compile(f"^{pattern}$"))
    for v in values:
        assert any(rgx.match(v) for rgx in spec_to_re.values()), \
            f"value matches no state format: {v!r}"


# ── 10 000-count memory smoke ───────────────────────────────────────────────

@pytest.mark.parametrize("gen_cls", [
    SSNSyntheticGenerator, UKNINSyntheticGenerator, BRCPFSyntheticGenerator,
    AUMedicareSyntheticGenerator, DETaxIdSyntheticGenerator,
    USDriversLicenceSyntheticGenerator,
])
def test_iter_generate_handles_10k(gen_cls):
    """iter_generate must produce exactly 10 000 values without
    materialising the full list. Smoke-test only — no RSS measurement."""
    gen = gen_cls()
    n = 0
    for _ in gen.iter_generate(10_000, seed=1):
        n += 1
    assert n == 10_000


# ── Registry — every new category resolves ──────────────────────────────────

def test_registry_resolves_new_categories():
    from evadex.synthetic.registry import (
        get_synthetic_generator, load_synthetic_generators,
    )
    from evadex.core.result import PayloadCategory
    load_synthetic_generators()
    for cat in (
        PayloadCategory.SSN, PayloadCategory.UK_NIN,
        PayloadCategory.BR_CPF, PayloadCategory.AU_MEDICARE,
        PayloadCategory.DE_TAX_ID, PayloadCategory.US_DL,
    ):
        gen = get_synthetic_generator(cat)
        assert gen is not None, f"no generator for {cat.value}"
        assert len(gen.generate(5, seed=1)) == 5
