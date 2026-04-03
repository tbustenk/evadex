"""Unit tests for DlpscanAdapter._parse_response edge cases.

These are critical for a production DLP test suite: a mis-parsed response
produces a false pass or false fail that is indistinguishable from a real result.
"""
import pytest
from evadex.adapters.dlpscan.adapter import DlpscanAdapter

BASE = "http://localhost:8080"


@pytest.fixture
def adapter():
    return DlpscanAdapter({"base_url": BASE})


# ── Standard bool responses ──────────────────────────────────────────────────

def test_detected_true_bool(adapter):
    assert adapter._parse_response({"detected": True}) is True


def test_detected_false_bool(adapter):
    assert adapter._parse_response({"detected": False}) is False


# ── Integer / float responses ─────────────────────────────────────────────────

def test_detected_int_one(adapter):
    assert adapter._parse_response({"detected": 1}) is True


def test_detected_int_zero(adapter):
    assert adapter._parse_response({"detected": 0}) is False


# ── String responses ──────────────────────────────────────────────────────────

def test_detected_string_true(adapter):
    assert adapter._parse_response({"detected": "true"}) is True


def test_detected_string_yes(adapter):
    assert adapter._parse_response({"detected": "yes"}) is True


def test_detected_string_false(adapter):
    assert adapter._parse_response({"detected": "false"}) is False


# ── List / matches responses ──────────────────────────────────────────────────

def test_matches_non_empty_list(adapter):
    assert adapter._parse_response({"matches": [{"rule": "credit_card"}]}) is True


def test_matches_empty_list(adapter):
    assert adapter._parse_response({"matches": []}) is False


# ── None / null value ─────────────────────────────────────────────────────────

def test_detected_null_returns_false_not_fallthrough(adapter):
    """A null 'detected' key must return False; it must NOT fall through to heuristic keys."""
    # If fallthrough happened and 'found' was True, we'd incorrectly get True.
    assert adapter._parse_response({"detected": None, "found": True}) is False


# ── Configured key precedence ─────────────────────────────────────────────────

def test_configured_key_takes_precedence(adapter):
    """The user-configured key must win over generic heuristic keys."""
    custom_adapter = DlpscanAdapter({
        "base_url": BASE,
        "response_detected_key": "is_match",
    })
    # is_match=False but detected=True; configured key must win.
    assert custom_adapter._parse_response({"is_match": False, "detected": True}) is False


def test_configured_key_present_unrecognised_type_returns_false(adapter):
    """If configured key is present but its value is a dict, return False — do not fall through."""
    assert adapter._parse_response({"detected": {"nested": True}, "found": True}) is False


# ── No recognised key at all ──────────────────────────────────────────────────

def test_empty_response_returns_false(adapter):
    assert adapter._parse_response({}) is False


def test_unrecognised_keys_only_returns_false(adapter):
    assert adapter._parse_response({"status": "ok", "count": 0}) is False
