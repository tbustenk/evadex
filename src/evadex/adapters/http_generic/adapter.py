"""evadex adapter for any DLP scanner with an HTTP API.

Works with any scanner that accepts a POST request with the text to scan
and returns a JSON response containing a list of findings.

Configuration (evadex.yaml)
---------------------------
::

    tool: http_generic
    url: https://my-dlp.example.com/scan
    method: POST                 # HTTP method (default: POST)
    request_field: text          # JSON key containing the text (default: "text")
    response_path: findings      # dot-path to findings list (default: "findings")
    auth_header: "X-Api-Key: {api_key}"  # optional; {api_key} is substituted
    api_key: "secret"            # optional; also read from EVADEX_API_KEY env var

``response_path`` supports simple dot-notation: ``"data.matches"`` extracts
``response["data"]["matches"]``.  The adapter treats any non-empty list at
that path as a detection (``detected=True``).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from evadex.adapters.base import AdapterConfig, BaseAdapter
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, ScanResult, Variant


def _extract_path(data: Any, path: str) -> Any:
    """Walk a dot-separated path through nested dicts/lists."""
    current = data
    for key in path.split("."):
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
        if current is None:
            return None
    return current


@register_adapter("http_generic")
class HttpGenericAdapter(BaseAdapter):
    """Generic HTTP adapter for any DLP scanner with a JSON scan endpoint.

    Sends the variant text as a JSON POST body and inspects the response for
    a findings list at the configured ``response_path``.  Any non-empty list
    is interpreted as a detection.
    """

    name = "http_generic"

    def __init__(self, config: "dict | AdapterConfig") -> None:
        super().__init__(config)
        extra = self.config.extra

        self._url: str = extra.get("url", "") or self.config.base_url or ""
        self._method: str = extra.get("method", "POST").upper()
        self._request_field: str = extra.get("request_field", "text")
        self._response_path: str = extra.get("response_path", "findings")

        # Auth header template: e.g. "X-Api-Key: {api_key}"
        self._auth_header_tpl: str | None = extra.get("auth_header")

        # API key: config wins over env var
        api_key = (
            self.config.api_key
            or os.environ.get("EVADEX_API_KEY")
            or extra.get("api_key")
        )
        self._api_key: str | None = api_key

        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self._auth_header_tpl and self._api_key:
            rendered = self._auth_header_tpl.replace("{api_key}", self._api_key)
            if ": " in rendered:
                h_name, h_val = rendered.split(": ", 1)
                headers[h_name.strip()] = h_val.strip()

        self._client = httpx.AsyncClient(
            timeout=self.config.timeout,
            headers=headers,
        )

    async def teardown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> bool:
        if not self._url:
            return False
        try:
            client = self._client or httpx.AsyncClient(timeout=5.0)
            r = await client.get(self._url.rstrip("/") + "/health")
            return r.status_code < 500
        except Exception:
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        if not self._url:
            return ScanResult(
                payload=payload,
                variant=variant,
                detected=False,
                raw_response=None,
                error="http_generic: no URL configured (set 'url:' in evadex.yaml)",
            )

        client = self._client
        if client is None:
            client = httpx.AsyncClient(timeout=self.config.timeout)

        body = {self._request_field: variant.value}

        try:
            if self._method == "GET":
                r = await client.get(self._url, params=body)
            else:
                r = await client.post(self._url, json=body)

            r.raise_for_status()
            response_json = r.json()

        except httpx.HTTPStatusError as exc:
            return ScanResult(
                payload=payload,
                variant=variant,
                detected=False,
                raw_response=None,
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
            )
        except Exception as exc:
            return ScanResult(
                payload=payload,
                variant=variant,
                detected=False,
                raw_response=None,
                error=str(exc),
            )

        findings = _extract_path(response_json, self._response_path)
        detected = bool(findings) and isinstance(findings, list) and len(findings) > 0

        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            raw_response=response_json,
            error=None,
        )
