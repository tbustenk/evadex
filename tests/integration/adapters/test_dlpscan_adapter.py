import pytest
import respx
import httpx
from evadex.adapters.dlpscan.adapter import DlpscanAdapter
from evadex.core.result import Payload, Variant, PayloadCategory

BASE = "http://localhost:8080"


@pytest.fixture
def adapter():
    return DlpscanAdapter({"base_url": BASE})


@pytest.fixture
def visa_payload():
    return Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")


@pytest.fixture
def text_variant():
    return Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")


@respx.mock
@pytest.mark.asyncio
async def test_text_submission_detected(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/scan").mock(return_value=httpx.Response(200, json={"detected": True}))
    result = await adapter.submit(visa_payload, text_variant)
    assert result.detected is True
    assert result.error is None


@respx.mock
@pytest.mark.asyncio
async def test_text_submission_not_detected(adapter, visa_payload, text_variant):
    respx.post(f"{BASE}/scan").mock(return_value=httpx.Response(200, json={"detected": False}))
    result = await adapter.submit(visa_payload, text_variant)
    assert result.detected is False


@respx.mock
@pytest.mark.asyncio
async def test_docx_submission(adapter, visa_payload):
    docx_variant = Variant(
        "4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="docx"
    )
    respx.post(f"{BASE}/scan/file").mock(return_value=httpx.Response(200, json={"detected": True}))
    result = await adapter.submit(visa_payload, docx_variant)
    assert result.detected is True


@pytest.mark.asyncio
async def test_file_builder_produces_bytes():
    from evadex.adapters.dlpscan.file_builder import FileBuilder

    docx_bytes, mime = FileBuilder.build("4532015112830366", "docx")
    assert len(docx_bytes) > 0
    assert mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    xlsx_bytes, mime = FileBuilder.build("4532015112830366", "xlsx")
    assert len(xlsx_bytes) > 0

    pdf_bytes, mime = FileBuilder.build("4532015112830366", "pdf")
    assert len(pdf_bytes) > 0
