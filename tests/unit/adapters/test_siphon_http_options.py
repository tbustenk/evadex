"""`transport: http` forwards require_context / min_confidence / categories.

siphon-api's `POST /scan` takes them under `options`; before v3.41.0 the
HTTP client posted `{"text": ...}` only and the settings were dropped.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from evadex.adapters.siphon_cli.client import SiphonHttpClient
from evadex.core.registry import get_adapter


def _fake_http(client: SiphonHttpClient):
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"findings": []}
    fake = MagicMock()
    fake.post = AsyncMock(return_value=resp)
    client._get_client = AsyncMock(return_value=fake)  # type: ignore[method-assign]
    return fake


async def test_options_forwarded_when_set():
    c = SiphonHttpClient(
        require_context=True, min_confidence=0.7, categories=["ssn", "iban"]
    )
    fake = _fake_http(c)
    await c.scan_text("hello")
    body = fake.post.call_args.kwargs["json"]
    assert body["text"] == "hello"
    assert body["options"] == {
        "require_context": True,
        "min_confidence": 0.7,
        "categories": ["ssn", "iban"],
    }


async def test_no_options_key_when_nothing_is_set():
    c = SiphonHttpClient()
    fake = _fake_http(c)
    await c.scan_text("hello")
    assert fake.post.call_args.kwargs["json"] == {"text": "hello"}


def test_adapter_passes_its_settings_to_the_http_client():
    adapter = get_adapter(
        "siphon-cli",
        {
            "transport": "http",
            "require_context": True,
            "min_confidence": 0.3,
            "categories": ["ssn"],
        },
    )
    assert adapter._http_client._options() == {
        "require_context": True,
        "min_confidence": 0.3,
        "categories": ["ssn"],
    }
