"""Unit tests for the http_generic adapter."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from evadex.adapters.http_generic.adapter import HttpGenericAdapter, _extract_path
from evadex.core.result import Payload, PayloadCategory, Variant


# ── Helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture
def cc_payload() -> Payload:
    return Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "test-cc")


@pytest.fixture
def text_variant() -> Variant:
    return Variant("4532015112830366", "raw", "identity", "raw credit card", strategy="text")


def _make_adapter(**cfg) -> HttpGenericAdapter:
    """Build an HttpGenericAdapter from a flat config dict.

    The BaseAdapter.from_dict pulls keys not in (base_url, api_key, timeout)
    into config.extra — that is where HttpGenericAdapter reads url / method /
    request_field / response_path.
    """
    defaults = {"url": "http://localhost:9000/scan"}
    defaults.update(cfg)
    return HttpGenericAdapter(defaults)


# ── _extract_path ─────────────────────────────────────────────────────────────


def test_extract_path_simple():
    assert _extract_path({"findings": [1, 2]}, "findings") == [1, 2]


def test_extract_path_nested():
    data = {"data": {"matches": ["hit1"]}}
    assert _extract_path(data, "data.matches") == ["hit1"]


def test_extract_path_missing_key_returns_none():
    assert _extract_path({}, "findings") is None


def test_extract_path_intermediate_missing_returns_none():
    assert _extract_path({"a": None}, "a.b") is None


# ── submit() ─────────────────────────────────────────────────────────────────


async def test_submit_detected_when_findings_nonempty(cc_payload, text_variant):
    adapter = _make_adapter()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"findings": [{"category": "Credit Card Numbers"}]}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    adapter._client = mock_client

    result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is True
    assert result.error is None


async def test_submit_not_detected_when_findings_empty(cc_payload, text_variant):
    adapter = _make_adapter()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"findings": []}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    adapter._client = mock_client

    result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is False
    assert result.error is None


async def test_submit_uses_custom_response_path(cc_payload, text_variant):
    adapter = _make_adapter(response_path="data.matches")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"data": {"matches": [{"id": "x"}]}}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    adapter._client = mock_client

    result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is True


async def test_submit_error_on_http_status_error(cc_payload, text_variant):
    import httpx

    adapter = _make_adapter()
    mock_client = AsyncMock()
    resp = MagicMock()
    resp.status_code = 403
    resp.text = "Forbidden"
    mock_client.post = AsyncMock(
        side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=resp)
    )
    adapter._client = mock_client

    result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is False
    assert result.error is not None
    assert "403" in result.error


async def test_submit_error_on_network_exception(cc_payload, text_variant):
    adapter = _make_adapter()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=Exception("connection refused"))
    adapter._client = mock_client

    result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is False
    assert result.error is not None


async def test_submit_returns_error_when_no_url(cc_payload, text_variant):
    # Pass empty url AND empty base_url so the fallback chain produces ""
    adapter = _make_adapter(url="", base_url="")
    result = await adapter.submit(cc_payload, text_variant)

    assert result.detected is False
    assert result.error is not None


async def test_submit_sends_correct_request_field(cc_payload, text_variant):
    adapter = _make_adapter(request_field="content")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"findings": []}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    adapter._client = mock_client

    await adapter.submit(cc_payload, text_variant)

    call_kwargs = mock_client.post.call_args
    assert call_kwargs.kwargs["json"] == {"content": text_variant.value}


# ── health_check() ───────────────────────────────────────────────────────────


async def test_health_check_returns_false_when_no_url():
    adapter = _make_adapter(url="", base_url="")
    result = await adapter.health_check()
    assert result is False
