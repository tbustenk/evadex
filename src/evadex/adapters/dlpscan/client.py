import httpx
from typing import Optional
from evadex.adapters.base import AdapterError


class DlpscanClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip('/')
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._headers = headers
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(headers=self._headers, timeout=self._timeout)
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(headers=self._headers, timeout=self._timeout)
        return self._client

    async def post_text(self, text: str) -> dict:
        client = await self._get_client()
        # Exclude Content-Type so httpx sets it correctly for JSON
        headers = {k: v for k, v in self._headers.items() if k != "Content-Type"}
        try:
            resp = await client.post(
                f"{self.base_url}/scan",
                json={"content": text},
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise AdapterError(f"HTTP {e.response.status_code}: {e.response.text}") from e
        except httpx.RequestError as e:
            raise AdapterError(f"Request failed: {e}") from e

    async def upload_file(self, data: bytes, filename: str, mime_type: str) -> dict:
        client = await self._get_client()
        headers = {k: v for k, v in self._headers.items() if k != "Content-Type"}
        try:
            resp = await client.post(
                f"{self.base_url}/scan/file",
                files={"file": (filename, data, mime_type)},
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise AdapterError(f"HTTP {e.response.status_code}: {e.response.text}") from e
        except httpx.RequestError as e:
            raise AdapterError(f"Request failed: {e}") from e

    async def get_health(self) -> dict:
        client = await self._get_client()
        try:
            resp = await client.get(f"{self.base_url}/health")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            raise AdapterError(f"Health check failed: {e}") from e

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
