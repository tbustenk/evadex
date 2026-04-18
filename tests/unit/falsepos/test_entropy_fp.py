"""Unit tests for the entropy false-positive generator."""
import re

import pytest

from evadex.falsepos.generators import (
    FALSEPOS_GENERATORS,
    generate_false_entropy_values,
    wrap_with_context,
)


UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
HEX_RE = re.compile(r"^[0-9a-f]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def test_generator_registered():
    assert "entropy" in FALSEPOS_GENERATORS


def test_generator_produces_requested_count():
    values = generate_false_entropy_values(50, seed=1)
    assert len(values) == 50


def test_generator_is_seed_reproducible():
    a = generate_false_entropy_values(20, seed=42)
    b = generate_false_entropy_values(20, seed=42)
    assert a == b


def _classify(value: str) -> str:
    if UUID_RE.match(value):
        return "uuid"
    # Common MD5/SHA-1/SHA-256 hashes are all-hex, length 32/40/64
    if HEX_RE.match(value) and len(value) in (32, 40, 64):
        return "hash"
    # Repetition pattern: small alphabet, long runs
    if re.match(r"^([a-z])\1+([a-z])\2+([a-z])\3+([a-z])\4+$", value):
        return "repetition"
    if BASE64_RE.match(value):
        return "base64"
    return "other"


def test_generator_produces_all_four_shapes():
    values = generate_false_entropy_values(200, seed=7)
    kinds = {_classify(v) for v in values}
    # Expect all four documented shapes to appear across 200 samples
    assert "uuid" in kinds
    assert "hash" in kinds
    assert "repetition" in kinds
    assert "base64" in kinds


def test_uuid_values_are_canonical_format():
    values = generate_false_entropy_values(200, seed=3)
    uuids = [v for v in values if UUID_RE.match(v)]
    assert uuids, "expected at least one UUID in 200 samples"
    for u in uuids:
        assert UUID_RE.match(u)


def test_generator_handles_count_zero():
    assert generate_false_entropy_values(0, seed=1) == []


def test_context_wrap_uses_assignment_and_keyword():
    wrapped = wrap_with_context("entropy", "550e8400-e29b-41d4-a716-446655440000")
    # Wrap template must hit both 'api_key' keyword and '=' assignment so the
    # false positive stresses BOTH gated and assignment modes.
    assert "api_key" in wrapped.lower()
    assert "=" in wrapped
