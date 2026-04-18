"""Unit tests for the high-entropy secret payloads.

Every ``ENTROPY_CATEGORIES`` payload must:
- carry a high-enough Shannon entropy core token to cross Siphon's 4.5
  bits/char threshold
- have a core token at least 16 chars long (Siphon's ENTROPY_MIN_TOKEN_LEN)
- be registered as heuristic so it doesn't leak into the default scan tier
"""
import math
from collections import Counter

import pytest

from evadex.core.result import CategoryType, CATEGORY_TYPES, PayloadCategory
from evadex.payloads.builtins import (
    BUILTIN_PAYLOADS,
    ENTROPY_CATEGORIES,
    HEURISTIC_CATEGORIES,
    get_payloads,
)


SIPHON_ENTROPY_THRESHOLD = 4.5
SIPHON_MIN_TOKEN_LEN = 16


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _core(value: str) -> str:
    """Extract the secret portion from a payload value.

    ``=`` is ambiguous — it's both an assignment separator and base64
    padding — so we only split on it when the LHS looks like a keyword,
    not when it's a base64 blob.
    """
    for sep in (": ", ":"):
        if sep in value:
            return value.split(sep, 1)[1].strip()
    if "=" in value:
        lhs, rhs = value.split("=", 1)
        # Treat LHS as a KEY= prefix when it's all-caps/underscore/alnum AND
        # short (keywords are short, base64 blobs are long).
        if lhs and len(lhs) <= 40 and all(c.isalnum() or c == "_" for c in lhs):
            stripped = rhs.strip()
            if stripped:
                return stripped
    return value


@pytest.fixture
def entropy_payloads():
    return [p for p in BUILTIN_PAYLOADS if p.category in ENTROPY_CATEGORIES]


def test_all_six_categories_present(entropy_payloads):
    cats = {p.category for p in entropy_payloads}
    assert cats == ENTROPY_CATEGORIES


def test_entropy_core_above_threshold_or_hex(entropy_payloads):
    """Mixed-alphabet payloads must exceed Siphon's 4.5 bits/char threshold.

    Pure-hex payloads are a known exception — log2(16)=4.0 is the
    theoretical maximum for [0-9a-f]-only content, so Siphon's entropy
    mode cannot catch them. We still include a hex category because
    it's a real-world secret shape, but the test distinguishes them.
    """
    hex_re = __import__("re").compile(r"^[0-9a-f]+$")
    for p in entropy_payloads:
        core = _core(p.value)
        h = shannon(core)
        if hex_re.match(core):
            # Hex can't clear the threshold — documented limitation.
            assert h <= 4.0 + 0.01, (
                f"{p.category.value} hex core entropy {h:.2f} shouldn't exceed 4.0"
            )
        else:
            assert h > SIPHON_ENTROPY_THRESHOLD, (
                f"{p.category.value} core entropy {h:.2f} must exceed "
                f"Siphon threshold {SIPHON_ENTROPY_THRESHOLD}"
            )


def test_entropy_core_meets_min_length(entropy_payloads):
    for p in entropy_payloads:
        core = _core(p.value)
        assert len(core) >= SIPHON_MIN_TOKEN_LEN, (
            f"{p.category.value} core '{core}' is shorter than "
            f"Siphon's {SIPHON_MIN_TOKEN_LEN}-char min token length"
        )


def test_assignment_payload_uses_equals_format():
    payloads = [p for p in BUILTIN_PAYLOADS
                if p.category == PayloadCategory.ASSIGNMENT_SECRET]
    assert payloads, "ASSIGNMENT_SECRET payload missing"
    assert "=" in payloads[0].value


def test_gated_payload_contains_siphon_keyword():
    """Gated payload needs a Siphon context keyword (api_key, secret, token, …)."""
    siphon_keywords = {
        "secret", "key", "token", "password", "auth",
        "credential", "api_key", "apikey", "bearer",
    }
    payloads = [p for p in BUILTIN_PAYLOADS
                if p.category == PayloadCategory.GATED_SECRET]
    assert payloads, "GATED_SECRET payload missing"
    v = payloads[0].value.lower()
    assert any(kw in v for kw in siphon_keywords)


def test_entropy_categories_are_heuristic():
    for cat in ENTROPY_CATEGORIES:
        assert CATEGORY_TYPES[cat] is CategoryType.HEURISTIC
        assert cat in HEURISTIC_CATEGORIES


def test_entropy_payloads_excluded_by_default():
    """Default get_payloads call should NOT return entropy payloads."""
    default = get_payloads()
    for p in default:
        assert p.category not in ENTROPY_CATEGORIES


def test_entropy_payloads_included_with_heuristic_flag():
    all_payloads = get_payloads(include_heuristic=True)
    present = {p.category for p in all_payloads} & ENTROPY_CATEGORIES
    assert present == ENTROPY_CATEGORIES
