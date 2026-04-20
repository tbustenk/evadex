"""Unit tests for the SiphonCliAdapter and its subprocess client.

Subprocess interactions are mocked — these tests lock in
(a) command-line argument assembly for every supported cmd_style,
(b) JSON response parsing for text vs file scans,
(c) enrichment extraction (confidence, sub_category, bin_*),
(d) empty-match handling.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from evadex.adapters.siphon_cli.adapter import SiphonCliAdapter
from evadex.adapters.siphon_cli.client import (
    SiphonCliClient,
    SiphonCliError,
    _parse_file_matches,
    _parse_matches,
)
from evadex.core.result import Payload, PayloadCategory, Variant


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def text_match() -> dict:
    """Representative scan-text match object including BIN metadata."""
    return {
        "category": "Credit Card Numbers",
        "confidence": 0.95,
        "context_required": False,
        "has_context": True,
        "metadata": {
            "bin_brand": "Visa",
            "bin_card_type": "Credit",
            "bin_country": "ES",
            "bin_issuer": "BANCO CAMINOS, S.A.",
        },
        "span": [18, 34],
        "sub_category": "Visa",
        "text": "4532015112830366",
    }


@pytest.fixture
def cc_payload() -> Payload:
    return Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "test-cc")


@pytest.fixture
def text_variant() -> Variant:
    return Variant(
        "4532015112830366", "raw", "identity", "raw credit card", strategy="text"
    )


# ── Command assembly ───────────────────────────────────────────────────────


def test_binary_scan_text_command_default_flags():
    client = SiphonCliClient(executable="siphon.exe")
    cmd = client.build_scan_text_command()
    assert cmd == ["siphon.exe", "scan-text", "--format", "json"]


def test_binary_scan_text_command_with_require_context():
    client = SiphonCliClient(executable="siphon.exe", require_context=True)
    cmd = client.build_scan_text_command()
    assert cmd == ["siphon.exe", "scan-text", "--format", "json", "--require-context"]


def test_binary_scan_file_command():
    client = SiphonCliClient(executable="siphon.exe")
    cmd = client.build_scan_file_command("/tmp/foo.txt")
    assert cmd == ["siphon.exe", "scan", "--format", "json", "/tmp/foo.txt"]


def test_cargo_mode_wraps_with_cargo_run():
    client = SiphonCliClient(cmd_style="cargo")
    cmd = client.build_scan_text_command()
    assert cmd[:6] == ["cargo", "run", "--release", "--bin", "siphon", "--"]
    # The scanner flags come after the ``--`` separator.
    assert cmd[6:] == ["scan-text", "--format", "json"]


def test_categories_and_min_confidence_flags_appear():
    client = SiphonCliClient(min_confidence=0.5, categories=["credit_card", "ssn"])
    cmd = client.build_scan_text_command()
    assert "--min-confidence" in cmd
    assert "0.5" in cmd
    assert "--categories" in cmd
    assert "credit_card,ssn" in cmd


# ── Response parsing ───────────────────────────────────────────────────────


def test_parse_matches_empty_array_yields_empty_list():
    assert _parse_matches("[]") == []


def test_parse_matches_rejects_non_list():
    with pytest.raises(SiphonCliError):
        _parse_matches('{"error": "bad"}')


def test_parse_matches_rejects_invalid_json():
    with pytest.raises(SiphonCliError):
        _parse_matches("not json")


def test_parse_file_matches_unwraps_file_envelope(text_match):
    envelope = json.dumps(
        [{"file_path": "/tmp/x.txt", "matches": [text_match], "error": None}]
    )
    assert _parse_file_matches(envelope) == [text_match]


def test_parse_file_matches_surfaces_scanner_error():
    envelope = json.dumps(
        [{"file_path": "/tmp/x.txt", "matches": [], "error": "permission denied"}]
    )
    with pytest.raises(SiphonCliError, match="permission denied"):
        _parse_file_matches(envelope)


def test_parse_file_matches_empty_outer_list_yields_empty():
    assert _parse_file_matches("[]") == []


# ── Adapter submit: text strategy ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_text_detects_and_parses_bin_enrichment(
    cc_payload, text_variant, text_match
):
    adapter = SiphonCliAdapter({"extra_only": True})
    with patch.object(
        adapter._client, "scan_text", new=AsyncMock(return_value=[text_match])
    ) as mock_scan:
        result = await adapter.submit(cc_payload, text_variant)

    mock_scan.assert_awaited_once_with("4532015112830366")
    assert result.detected is True
    assert result.confidence == pytest.approx(0.95)
    assert result.sub_category == "Visa"
    assert result.bin_brand == "Visa"
    assert result.bin_card_type == "Credit"
    assert result.bin_country == "ES"
    assert result.bin_issuer == "BANCO CAMINOS, S.A."
    assert result.raw_response == {"matches": [text_match]}


@pytest.mark.asyncio
async def test_submit_text_empty_response_means_not_detected(cc_payload, text_variant):
    adapter = SiphonCliAdapter({})
    with patch.object(
        adapter._client, "scan_text", new=AsyncMock(return_value=[])
    ):
        result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is False
    # No enrichment when there are no matches.
    assert result.confidence is None
    assert result.bin_brand is None
    assert result.sub_category is None
    assert result.raw_response == {"matches": []}


@pytest.mark.asyncio
async def test_submit_text_picks_highest_confidence_match(cc_payload, text_variant):
    adapter = SiphonCliAdapter({})
    low = {"confidence": 0.3, "sub_category": "Mastercard"}
    high = {
        "confidence": 0.9,
        "sub_category": "Visa",
        "metadata": {"bin_brand": "Visa"},
    }
    with patch.object(
        adapter._client, "scan_text", new=AsyncMock(return_value=[low, high])
    ):
        result = await adapter.submit(cc_payload, text_variant)

    assert result.confidence == pytest.approx(0.9)
    assert result.sub_category == "Visa"
    assert result.bin_brand == "Visa"


# ── Adapter submit: file strategy ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_file_routes_to_file_scan(cc_payload, text_match):
    adapter = SiphonCliAdapter({})
    docx_variant = Variant(
        "4532015112830366", "raw", "identity", "docx wrap", strategy="docx"
    )
    with patch.object(
        adapter._client,
        "scan_file_bytes",
        new=AsyncMock(return_value=[text_match]),
    ) as mock_scan, patch.object(
        adapter._client, "scan_text", new=AsyncMock(return_value=[])
    ) as mock_text:
        result = await adapter.submit(cc_payload, docx_variant)

    # File strategy must use the file client path, not the text path.
    mock_scan.assert_awaited_once()
    mock_text.assert_not_called()
    args, _ = mock_scan.call_args
    _data, suffix = args
    assert suffix == ".docx"
    assert result.detected is True
    assert result.bin_brand == "Visa"


# ── Adapter config plumbing ────────────────────────────────────────────────


def test_adapter_propagates_cargo_cmd_style_to_client():
    adapter = SiphonCliAdapter({"cmd_style": "cargo", "executable": "siphon"})
    cmd = adapter._client.build_scan_text_command()
    assert cmd[0] == "cargo"
    assert cmd[5] == "--"


def test_adapter_propagates_require_context_flag():
    adapter = SiphonCliAdapter({"require_context": True})
    cmd = adapter._client.build_scan_text_command()
    assert "--require-context" in cmd
