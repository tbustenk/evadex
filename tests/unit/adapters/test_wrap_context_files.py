"""File-strategy fixtures carry the same keyword sentence as the text path.

Before v3.41.0 a DOCX/PDF/XLSX fixture held the bare variant value while
the text submission held a keyword sentence, so context-gated rules could
never fire on a file: SSN and SIN scored 0% in DOCX and ~80% in text on
the same scanner.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from evadex.adapters.dlpscan_cli import adapter as dlpscan_mod
from evadex.adapters.siphon_cli import adapter as siphon_mod
from evadex.core.registry import get_adapter
from evadex.core.result import Payload, PayloadCategory, Variant

CARD = "4532015112830366"
PAYLOAD = Payload(CARD, PayloadCategory.CREDIT_CARD, "Visa")


def _variant(strategy: str) -> Variant:
    return Variant(CARD, "structural", "uppercase", "Uppercased", strategy)


@pytest.fixture
def capture_build(monkeypatch):
    """Replace FileBuilder.build in both adapters; record the text it is given."""
    seen: list[tuple[str, str]] = []

    class _Builder:
        @staticmethod
        def build(text, fmt):
            seen.append((text, fmt))
            return b"bytes", "application/octet-stream"

    monkeypatch.setattr(siphon_mod, "FileBuilder", _Builder)
    monkeypatch.setattr(dlpscan_mod, "FileBuilder", _Builder)
    return seen


async def _siphon(strategy, **extra):
    adapter = get_adapter("siphon-cli", {"executable": "siphon", **extra})
    adapter._client.scan_text = AsyncMock(return_value=[])
    adapter._client.scan_file_bytes = AsyncMock(return_value=[])
    await adapter.submit(PAYLOAD, _variant(strategy))
    return adapter


async def test_docx_fixture_gets_the_keyword_sentence(capture_build):
    await _siphon("docx", wrap_context=True, seed=7)
    ((text, fmt),) = capture_build
    assert fmt == "docx"
    assert CARD in text and text != CARD


async def test_same_seed_same_sentence_for_text_and_file(capture_build):
    adapter = await _siphon("docx", wrap_context=True, seed=7)
    adapter2 = get_adapter(
        "siphon-cli", {"executable": "siphon", "wrap_context": True, "seed": 7}
    )
    adapter2._client.scan_text = AsyncMock(return_value=[])
    await adapter2.submit(PAYLOAD, _variant("text"))
    sentence_in_file = capture_build[0][0]
    sentence_as_text = adapter2._client.scan_text.call_args.args[0]
    assert sentence_in_file == sentence_as_text


async def test_without_wrap_context_file_holds_the_bare_value(capture_build):
    await _siphon("pdf")
    assert capture_build == [(CARD, "pdf")]


async def test_http_transport_file_strategy_is_wrapped_too(capture_build):
    adapter = get_adapter(
        "siphon-cli", {"transport": "http", "wrap_context": True, "seed": 7}
    )
    adapter._http_client.scan_file_bytes = AsyncMock(return_value=[])
    await adapter.submit(PAYLOAD, _variant("xlsx"))
    ((text, fmt),) = capture_build
    assert fmt == "xlsx" and CARD in text and text != CARD


async def test_dlpscan_cli_file_strategy_is_wrapped(capture_build):
    adapter = get_adapter(
        "dlpscan-cli", {"executable": "dlpscan", "wrap_context": True, "seed": 7}
    )
    adapter._scan_bytes_async = AsyncMock(return_value=[])
    await adapter.submit(PAYLOAD, _variant("docx"))
    ((text, fmt),) = capture_build
    assert fmt == "docx" and CARD in text and text != CARD
