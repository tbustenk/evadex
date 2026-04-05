"""HTTP client for Microsoft Presidio's REST API.

Presidio Analyzer default endpoint: http://localhost:5002
"""
import httpx
from typing import Optional
from evadex.adapters.base import AdapterError


class PresidioClient:
    """Thin async wrapper around the Presidio Analyzer REST API."""

    def __init__(
        self,
        base_url: str = "http://localhost:5002",
        timeout: float = 30.0,
        language: str = "en",
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.language = language
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def health(self) -> dict:
        """GET /health — raises AdapterError if unreachable."""
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.base_url}/health")
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError as e:
            raise AdapterError(f"Presidio health check failed: {e}") from e
        except httpx.HTTPStatusError as e:
            raise AdapterError(
                f"Presidio health check HTTP {e.response.status_code}"
            ) from e

    async def analyze(self, text: str) -> list[dict]:
        """POST /analyze — returns list of recognizer result dicts.

        Each dict has at minimum:
            entity_type (str), start (int), end (int), score (float)
        """
        client = await self._get_client()
        body = {
            "text": text,
            "language": self.language,
        }
        try:
            resp = await client.post(f"{self.base_url}/analyze", json=body)
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError as e:
            raise AdapterError(f"Presidio analyze request failed: {e}") from e
        except httpx.HTTPStatusError as e:
            raise AdapterError(
                f"Presidio analyze HTTP {e.response.status_code}: {e.response.text}"
            ) from e

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
