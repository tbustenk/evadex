"""Tests for Canadian regional ID payloads and category detection."""
import pytest
from evadex.payloads.builtins import get_payloads, BUILTIN_PAYLOADS
from evadex.core.result import PayloadCategory, CATEGORY_TYPES, CategoryType


_CA_CATEGORIES = [
    PayloadCategory.CA_RAMQ,
    PayloadCategory.CA_ONTARIO_HEALTH,
    PayloadCategory.CA_BC_CARECARD,
    PayloadCategory.CA_AB_HEALTH,
    PayloadCategory.CA_QC_DRIVERS,
    PayloadCategory.CA_ON_DRIVERS,
    PayloadCategory.CA_BC_DRIVERS,
    PayloadCategory.CA_PASSPORT,
]


def test_all_canadian_id_categories_have_payloads():
    for cat in _CA_CATEGORIES:
        payloads = get_payloads({cat})
        assert payloads, f"No builtin payload for {cat}"


def test_all_canadian_id_categories_are_structured():
    for cat in _CA_CATEGORIES:
        assert CATEGORY_TYPES[cat] == CategoryType.STRUCTURED, (
            f"{cat} should be STRUCTURED"
        )


def test_ramq_payload_format():
    payloads = get_payloads({PayloadCategory.CA_RAMQ})
    assert len(payloads) >= 1
    # Format: XXXX DDDD DDDD (4 alpha + space + 4 digits + space + 4 digits)
    import re
    pattern = re.compile(r'^[A-Z]{4} \d{4} \d{4}$')
    for p in payloads:
        assert pattern.match(p.value), f"RAMQ format mismatch: {p.value!r}"


def test_ontario_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_ONTARIO_HEALTH})
    assert len(payloads) >= 1
    # Format: NNNN-NNN-NNN-LL
    import re
    pattern = re.compile(r'^\d{4}-\d{3}-\d{3}-[A-Z]{2}$')
    for p in payloads:
        assert pattern.match(p.value), f"Ontario health card format mismatch: {p.value!r}"


def test_bc_carecard_payload_format():
    payloads = get_payloads({PayloadCategory.CA_BC_CARECARD})
    assert len(payloads) >= 1
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 10, (
            f"BC CareCard should be 10 digits: {p.value!r}"
        )


def test_ab_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_AB_HEALTH})
    assert len(payloads) >= 1
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 9, (
            f"Alberta health card should be 9 digits: {p.value!r}"
        )


def test_qc_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_QC_DRIVERS})
    assert len(payloads) >= 1
    import re
    pattern = re.compile(r'^[A-Z]\d{12}$')
    for p in payloads:
        assert pattern.match(p.value), f"QC driver's licence format mismatch: {p.value!r}"


def test_on_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_ON_DRIVERS})
    assert len(payloads) >= 1
    import re
    pattern = re.compile(r'^[A-Z]\d{4}-\d{5}-\d{5}$')
    for p in payloads:
        assert pattern.match(p.value), f"ON driver's licence format mismatch: {p.value!r}"


def test_bc_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_BC_DRIVERS})
    assert len(payloads) >= 1
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 7, (
            f"BC driver's licence should be 7 digits: {p.value!r}"
        )


def test_ca_passport_payload_format():
    payloads = get_payloads({PayloadCategory.CA_PASSPORT})
    assert len(payloads) >= 1
    import re
    pattern = re.compile(r'^[A-Z]{2}\d{6}$')
    for p in payloads:
        assert pattern.match(p.value), f"Canadian passport format mismatch: {p.value!r}"


def test_canadian_id_payloads_not_heuristic():
    """Canadian IDs are excluded from heuristic filter — should appear by default."""
    all_structured = get_payloads(include_heuristic=False)
    ca_cats = {p.category for p in all_structured}
    for cat in _CA_CATEGORIES:
        assert cat in ca_cats, f"{cat} missing from structured payloads"


def test_canadian_id_variants_applicable_for_delimiter():
    """All Canadian ID categories should have delimiter variants generated."""
    from evadex.core.registry import load_builtins
    load_builtins()
    from evadex.core.registry import get_generator
    gen = get_generator("delimiter")
    for cat in _CA_CATEGORIES:
        payloads = get_payloads({cat})
        value = payloads[0].value
        variants = list(gen.generate(value))
        assert variants, f"No delimiter variants for {cat} value {value!r}"


def test_sin_format_verified():
    """Verify the existing Canada SIN seed payload is in correct NNN NNN NNN format."""
    import re
    from evadex.synthetic.validators import sin_valid
    payloads = get_payloads({PayloadCategory.SIN})
    assert payloads
    for p in payloads:
        digits = p.value.replace(" ", "")
        assert sin_valid(digits), f"SIN seed payload fails checksum: {p.value!r}"
