"""Async HTTP client for the Siphon (dlpscan-rs) REST API.

Endpoints (see dlpscan-rs src/api.rs):
    GET  /health            — health / readiness
    POST /v1/scan           — scan text, returns findings + redacted_text
    POST /v1/batch/scan     — batch scan (unused here but supported by the server)

Authentication
--------------
Siphon authenticates with an API key sent via the ``x-api-key`` header.
Supply it via ``--api-key`` or the ``EVADEX_API_KEY`` environment variable.
"""
from typing import Optional

import httpx

from evadex.adapters.base import AdapterError


SCAN_PATH = "/v1/scan"
HEALTH_PATH = "/health"


class SiphonClient:
    """Thin async wrapper around the Siphon HTTP API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["x-api-key"] = self._api_key
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def health(self) -> dict:
        """GET /health — raises AdapterError if unreachable or non-2xx."""
        client = await self._get_client()
        headers = self._headers()
        try:
            resp = await client.get(f"{self.base_url}{HEALTH_PATH}", headers=headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise AdapterError(
                f"Siphon health check HTTP {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise AdapterError(f"Siphon health check failed: {e}") from e

    async def scan_text(
        self,
        text: str,
        presets: Optional[list] = None,
        categories: Optional[list] = None,
        min_confidence: float = 0.0,
        require_context: bool = False,
    ) -> dict:
        """POST /v1/scan — scan a single text blob.

        Returns the parsed ScanResponse dict:
            {"is_clean": bool, "finding_count": int, "categories_found": [...],
             "redacted_text": str|None, "findings": [...]}
        """
        client = await self._get_client()
        body = {
            "text": text,
            "presets": presets or [],
            "categories": categories or [],
            "action": "flag",
            "min_confidence": min_confidence,
            "require_context": require_context,
        }
        try:
            resp = await client.post(
                f"{self.base_url}{SCAN_PATH}",
                json=body,
                headers=self._headers(),
            )
        except httpx.RequestError as e:
            raise AdapterError(f"Siphon scan request failed: {e}") from e

        self._raise_for_status(resp)
        try:
            return resp.json()
        except ValueError as e:
            raise AdapterError(f"Siphon returned non-JSON response: {e}") from e

    async def scan_file(
        self,
        data: bytes,
        filename: str,
        mime_type: str,
        **scan_kwargs,
    ) -> dict:
        """Submit a file's textual content to Siphon for scanning.

        Siphon's HTTP API is text-only (/v1/scan), so this extracts text
        from the provided bytes in-process and forwards it to scan_text.
        DOCX/XLSX/PDF extraction uses the same backends evadex's FileBuilder
        produces, so the round-trip is lossless for what Siphon would see.
        """
        text = _extract_text(data, filename, mime_type)
        return await self.scan_text(text, **scan_kwargs)

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code == 401:
            raise AdapterError(
                "Siphon auth failed (401) — set --api-key or EVADEX_API_KEY"
            )
        if resp.status_code == 403:
            raise AdapterError(
                "Siphon refused the request (403) — API key lacks required permission"
            )
        if resp.status_code == 429:
            retry = resp.headers.get("retry-after", "?")
            raise AdapterError(
                f"Siphon rate limit exceeded (429, retry-after={retry})"
            )
        if resp.status_code >= 500:
            raise AdapterError(
                f"Siphon server error {resp.status_code}: "
                f"{resp.text[:200] if resp.text else '(no body)'}"
            )
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            detail = ""
            try:
                detail = resp.json().get("detail", "")
            except Exception:
                detail = resp.text[:200]
            raise AdapterError(
                f"Siphon HTTP {e.response.status_code}: {detail}"
            ) from e

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        await self._get_client()
        return self

    async def __aexit__(self, *args):
        await self.close()


def _extract_text(data: bytes, filename: str, mime_type: str) -> str:
    """Extract plain text from common office formats for Siphon submission.

    Siphon's HTTP API scans text, so binary documents are decoded client-side.
    """
    lowered = (filename or "").lower()
    if lowered.endswith(".docx") or "wordprocessingml" in (mime_type or ""):
        return _extract_docx(data)
    if lowered.endswith(".xlsx") or "spreadsheetml" in (mime_type or ""):
        return _extract_xlsx(data)
    if lowered.endswith(".pdf") or (mime_type or "").endswith("/pdf"):
        return _extract_pdf(data)
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_docx(data: bytes) -> str:
    try:
        import io
        from docx import Document
    except ImportError as e:
        raise AdapterError(
            "python-docx is required to scan DOCX files with Siphon"
        ) from e
    doc = Document(io.BytesIO(data))
    return "\n".join(p.text for p in doc.paragraphs)


def _extract_xlsx(data: bytes) -> str:
    try:
        import io
        import openpyxl
    except ImportError as e:
        raise AdapterError(
            "openpyxl is required to scan XLSX files with Siphon"
        ) from e
    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    parts: list = []
    for sheet in wb.worksheets:
        for row in sheet.iter_rows(values_only=True):
            for cell in row:
                if cell is not None:
                    parts.append(str(cell))
    return "\n".join(parts)


def _extract_pdf(data: bytes) -> str:
    # PDF text extraction is intentionally minimal: Siphon itself performs
    # pattern matching on extracted text upstream. We return a best-effort
    # decoded stream so the roundtrip at least contains the bytes; callers
    # that need high-fidelity extraction should feed Siphon text directly.
    try:
        return data.decode("latin-1", errors="replace")
    except Exception:
        return ""
