"""evadex adapter for Microsoft Presidio Analyzer.

Presidio runs as a local REST service; default address is http://localhost:5002.

Usage with evadex scan:
    evadex scan --tool presidio --url http://localhost:5002 --strategy text

Supported strategies
--------------------
* text  — submits the variant value directly to POST /analyze.

Non-text strategies (docx, pdf, xlsx) are not supported because Presidio's
REST API analyses plain text only. Pass ``--strategy text`` when running evadex
against this adapter.

Extra config keys (via adapter extra dict)
------------------------------------------
language : str
    BCP-47 language code sent to Presidio (default: "en").
min_score : float
    Minimum recognizer confidence score to count as a detection (default: 0.0).
"""
from evadex.adapters.base import BaseAdapter, AdapterError
from evadex.adapters.presidio.client import PresidioClient
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult


@register_adapter("presidio")
class PresidioAdapter(BaseAdapter):
    name = "presidio"

    def __init__(self, config):
        super().__init__(config)
        language = self.config.extra.get("language", "en")
        self._min_score = float(self.config.extra.get("min_score", 0.0))
        self._client = PresidioClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            language=language,
        )

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        await self._client.close()

    async def health_check(self) -> bool:
        """Return True if Presidio responds to GET /health."""
        try:
            await self._client.health()
            return True
        except AdapterError:
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy
        if strategy != "text":
            raise AdapterError(
                f"Presidio adapter only supports 'text' strategy, got {strategy!r}. "
                "Pass --strategy text when scanning with Presidio."
            )

        results = await self._client.analyze(variant.value)
        detected = self._parse_results(results)
        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            raw_response={"results": results},
        )

    def _parse_results(self, results: list[dict]) -> bool:
        """Return True if any recognizer result meets the minimum score threshold."""
        if not isinstance(results, list):
            return False
        return any(
            isinstance(r, dict) and r.get("score", 0.0) >= self._min_score
            for r in results
        )
