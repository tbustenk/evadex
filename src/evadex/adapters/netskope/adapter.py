"""evadex adapter for Netskope DLP.

Uses the Netskope REST API to submit text for DLP scanning and parse findings.

Configuration (evadex.yaml)
---------------------------
::

    tool: netskope
    netskope_tenant: mycompany   # tenant hostname prefix; full URL is
                                 # https://{tenant}.goskope.com
    api_key: "v1token..."        # Netskope API v1 token (or NETSKOPE_API_KEY env var)
    profile: "DLP-Policy-1"      # optional DLP policy profile name to use

The adapter calls the Netskope Inline API endpoint:
  POST /api/v1/events/dataprotection/scan
with a JSON body ``{ "text": <value> }`` and reads violations from the response.

If ``profile`` is set, it passes it as ``dlp_profile`` in the request body.

Authentication:
  The token is passed as the ``Netskope-Api-Token`` HTTP header.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from evadex.adapters.base import AdapterConfig, BaseAdapter
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, ScanResult, Variant

_SCAN_PATH = "/api/v1/events/dataprotection/scan"
_HEALTH_PATH = "/api/v1/events/dataprotection"


def _has_violations(data: Any) -> bool:
    """Return True if the Netskope response contains DLP violations."""
    if not isinstance(data, dict):
        return False
    # Netskope response shape: {"status": "success", "data": {"violations": [...]}}
    violations = (
        (data.get("data") or {}).get("violations")
        or data.get("violations")
        or data.get("findings")
        or []
    )
    return isinstance(violations, list) and len(violations) > 0


@register_adapter("netskope")
class NetskopeAdapter(BaseAdapter):
    """Netskope DLP adapter.

    Submits each variant to Netskope's inline DLP scan API and interprets
    any returned violations as a detection (``detected=True``).
    """

    name = "netskope"

    def __init__(self, config: "dict | AdapterConfig") -> None:
        super().__init__(config)
        extra = self.config.extra

        tenant = extra.get("netskope_tenant", "")
        if tenant:
            self._base_url = f"https://{tenant}.goskope.com"
        else:
            self._base_url = self.config.base_url or ""

        api_key = (
            self.config.api_key
            or os.environ.get("NETSKOPE_API_KEY")
            or extra.get("api_key")
            or ""
        )
        self._api_key: str = api_key
        self._profile: str | None = extra.get("profile")
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["Netskope-Api-Token"] = self._api_key

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self.config.timeout,
            headers=headers,
        )

    async def teardown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> bool:
        if not self._base_url:
            return False
        try:
            client = self._client or httpx.AsyncClient(
                base_url=self._base_url, timeout=5.0
            )
            r = await client.get(_HEALTH_PATH)
            return r.status_code < 500
        except Exception:
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        if not self._base_url:
            return ScanResult(
                payload=payload,
                variant=variant,
                detected=False,
                raw_response=None,
                error=(
                    "netskope: no tenant configured. "
                    "Set 'netskope_tenant:' in evadex.yaml or pass base_url."
                ),
            )

        client = self._client
        if client is None:
            client = httpx.AsyncClient(
                base_url=self._base_url, timeout=self.config.timeout
            )

        body: dict[str, Any] = {"text": variant.value}
        if self._profile:
            body["dlp_profile"] = self._profile

        try:
            r = await client.post(_SCAN_PATH, json=body)
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

        return ScanResult(
            payload=payload,
            variant=variant,
            detected=_has_violations(response_json),
            raw_response=response_json,
            error=None,
        )
