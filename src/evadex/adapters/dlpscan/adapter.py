from evadex.adapters.base import BaseAdapter, AdapterConfig
from evadex.adapters.dlpscan.client import DlpscanClient
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult


@register_adapter("dlpscan")
class DlpscanAdapter(BaseAdapter):
    name = "dlpscan"

    def __init__(self, config):
        super().__init__(config)
        self._client = DlpscanClient(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            timeout=self.config.timeout,
        )
        # Key in response JSON that indicates detection. Configurable via adapter extra config.
        self._detected_key = self.config.extra.get("response_detected_key", "detected")

    async def setup(self):
        pass

    async def teardown(self):
        await self._client.close()

    async def health_check(self) -> bool:
        try:
            await self._client.get_health()
            return True
        except Exception:
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy
        if strategy == "text":
            raw = await self._client.post_text(variant.value)
        else:
            data, mime = FileBuilder.build(variant.value, strategy)
            filename = f"evadex_test.{strategy}"
            raw = await self._client.upload_file(data, filename, mime)

        detected = self._parse_response(raw)
        return ScanResult(payload=payload, variant=variant, detected=detected, raw_response=raw)

    def _parse_response(self, raw: dict) -> bool:
        # Try configured key first. If the key is present, only use it — do not
        # fall through to the heuristic block regardless of the value's type.
        if self._detected_key in raw:
            val = raw[self._detected_key]
            if isinstance(val, bool):
                return val
            if isinstance(val, (int, float)):
                return bool(val)
            if isinstance(val, str):
                return val.lower() in ('true', '1', 'yes', 'detected')
            if isinstance(val, list):
                return len(val) > 0
            # Unrecognised type (None, dict, …) — treat as not detected.
            return False

        # Configured key absent — try common response shapes.
        for key in ("detected", "found", "matches", "findings", "alert", "flagged"):
            if key in raw:
                val = raw[key]
                if isinstance(val, bool):
                    return val
                if isinstance(val, list):
                    return len(val) > 0
                if isinstance(val, (int, float)):
                    return bool(val)

        return False
