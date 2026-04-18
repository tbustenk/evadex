"""Integration tests for the Siphon (dlpscan-rs HTTP API) adapter.

The Siphon server is mocked with respx so these tests run entirely offline.
"""
import httpx
import pytest
import respx

from evadex.adapters.base import AdapterError
from evadex.adapters.siphon.adapter import SiphonAdapter
from evadex.adapters.siphon.client import SiphonClient
from evadex.core.result import Payload, PayloadCategory, Variant


BASE = "http://localhost:8000"


def _finding(**over) -> dict:
    base = {
        "text": "************0366",
        "category": "credit_card",
        "sub_category": "visa",
        "confidence": 0.95,
        "has_context": False,
        "span": [0, 16],
    }
    base.update(over)
    return base


def _scan_response(findings=None, is_clean=False) -> dict:
    findings = findings if findings is not None else [_finding()]
    return {
        "is_clean": is_clean if findings else True,
        "finding_count": len(findings),
        "categories_found": sorted({f["category"] for f in findings}),
        "redacted_text": None,
        "findings": findings,
    }


@pytest.fixture
def adapter():
    return SiphonAdapter({"base_url": BASE, "api_key": "test-key"})


@pytest.fixture
def visa_payload():
    return Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")


@pytest.fixture
def text_variant():
    return Variant(
        "4532015112830366",
        "structural",
        "no_delimiter",
        "No delimiter",
        strategy="text",
    )


# ── Text scan ─────────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_text_scan_detected(adapter, visa_payload, text_variant):
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=_scan_response())
    )
    result = await adapter.submit(visa_payload, text_variant)
    assert result.detected is True
    assert result.error is None
    assert result.confidence == 0.95
    # API key header is forwarded to Siphon.
    assert route.calls.last.request.headers["x-api-key"] == "test-key"
    # Presets/categories default to empty and are included in the request body.
    import json as _json
    body = _json.loads(route.calls.last.request.content)
    assert body["text"] == "4532015112830366"
    assert body["presets"] == []
    assert body["require_context"] is False


@respx.mock
@pytest.mark.asyncio
async def test_text_scan_not_detected(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=_scan_response(findings=[], is_clean=True))
    )
    result = await adapter.submit(visa_payload, text_variant)
    assert result.detected is False
    assert result.confidence is None


# ── Enriched fields ───────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_enrichment_fields_parsed(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(
            200,
            json=_scan_response(findings=[
                _finding(
                    confidence=0.99,
                    bin_brand="Visa",
                    bin_country="US",
                    validator="luhn",
                    entropy_classification="structured",
                ),
            ]),
        )
    )
    result = await adapter.submit(visa_payload, text_variant)
    assert result.confidence == 0.99
    assert result.bin_brand == "Visa"
    assert result.bin_country == "US"
    assert result.validator == "luhn"
    assert result.entropy_classification == "structured"


@respx.mock
@pytest.mark.asyncio
async def test_enrichment_picks_highest_confidence(adapter, visa_payload, text_variant):
    """When multiple findings are present, enrichment comes from the top-confidence match."""
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(
            200,
            json=_scan_response(findings=[
                _finding(confidence=0.5, bin_brand="Discover"),
                _finding(confidence=0.98, bin_brand="Visa"),
            ]),
        )
    )
    result = await adapter.submit(visa_payload, text_variant)
    assert result.confidence == 0.98
    assert result.bin_brand == "Visa"


@respx.mock
@pytest.mark.asyncio
async def test_to_dict_includes_enrichment_only_when_present(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(
            200,
            json=_scan_response(findings=[_finding(confidence=0.9)]),
        )
    )
    result = await adapter.submit(visa_payload, text_variant)
    d = result.to_dict()
    assert d["confidence"] == 0.9
    assert "bin_brand" not in d
    assert "validator" not in d


# ── File scan ─────────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_docx_scan_routes_to_v1_scan(adapter, visa_payload):
    """Siphon's API is text-only, so DOCX is extracted client-side and sent to /v1/scan."""
    docx_variant = Variant(
        "4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="docx"
    )
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=_scan_response())
    )
    result = await adapter.submit(visa_payload, docx_variant)
    assert result.detected is True
    # Ensure the extracted DOCX text actually contained the payload value.
    import json as _json
    body = _json.loads(route.calls.last.request.content)
    assert "4532015112830366" in body["text"]


# ── Health check ──────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_health_check_ok(adapter):
    respx.get(f"{BASE}/health").mock(
        return_value=httpx.Response(200, json={"status": "ok", "version": "0.5.0"})
    )
    assert await adapter.health_check() is True


@respx.mock
@pytest.mark.asyncio
async def test_health_check_failure(adapter):
    respx.get(f"{BASE}/health").mock(return_value=httpx.Response(503, text="draining"))
    assert await adapter.health_check() is False


# ── Auth / error handling ────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_auth_failure_surfaces_clear_error(visa_payload, text_variant):
    adapter = SiphonAdapter({"base_url": BASE, "api_key": "wrong"})
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(401, json={"detail": "Invalid or missing API key"})
    )
    with pytest.raises(AdapterError) as exc:
        await adapter.submit(visa_payload, text_variant)
    assert "auth failed" in str(exc.value).lower() or "401" in str(exc.value)


@respx.mock
@pytest.mark.asyncio
async def test_rate_limit_error(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(
            429, headers={"retry-after": "60"}, json={"detail": "Rate limit exceeded"}
        )
    )
    with pytest.raises(AdapterError) as exc:
        await adapter.submit(visa_payload, text_variant)
    assert "rate limit" in str(exc.value).lower()


@respx.mock
@pytest.mark.asyncio
async def test_forbidden_error(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(403, json={"detail": "Insufficient permissions"})
    )
    with pytest.raises(AdapterError) as exc:
        await adapter.submit(visa_payload, text_variant)
    assert "403" in str(exc.value) or "refused" in str(exc.value).lower()


@respx.mock
@pytest.mark.asyncio
async def test_timeout_error(visa_payload, text_variant):
    adapter = SiphonAdapter({"base_url": BASE, "api_key": "test-key", "timeout": 0.5})
    respx.post(f"{BASE}/v1/scan").mock(side_effect=httpx.ConnectTimeout("timed out"))
    with pytest.raises(AdapterError) as exc:
        await adapter.submit(visa_payload, text_variant)
    assert "request failed" in str(exc.value).lower() or "timed out" in str(exc.value).lower()


# ── Client-level tests ────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_client_scan_text_sends_expected_body():
    client = SiphonClient(base_url=BASE, api_key="k")
    route = respx.post(f"{BASE}/v1/scan").mock(
        return_value=httpx.Response(200, json=_scan_response(findings=[]))
    )
    resp = await client.scan_text(
        "hello",
        presets=["pci_dss"],
        categories=["credit_card"],
        min_confidence=0.7,
        require_context=True,
    )
    assert resp["is_clean"] is True
    import json as _json
    body = _json.loads(route.calls.last.request.content)
    assert body == {
        "text": "hello",
        "presets": ["pci_dss"],
        "categories": ["credit_card"],
        "action": "flag",
        "min_confidence": 0.7,
        "require_context": True,
    }
    await client.close()


# ── Adapter name / registration ──────────────────────────────────────────────

def test_adapter_is_registered_as_siphon():
    from evadex.core.registry import _ADAPTERS, load_builtins
    load_builtins()
    assert "siphon" in _ADAPTERS
    assert _ADAPTERS["siphon"] is SiphonAdapter
