"""evadex adapter for Siphon (dlpscan-rs) HTTP API.

Siphon exposes a REST API on ``DLPSCAN_API_HOST:DLPSCAN_API_PORT`` (default
``127.0.0.1:8000``). This adapter talks to it directly so evadex can run in
production environments where the CLI is unavailable.

Usage
-----
    evadex scan --tool siphon --url http://siphon:8000 --api-key $EVADEX_API_KEY

Extra config keys (via adapter extra dict / evadex.yaml)
--------------------------------------------------------
presets : list[str]
    Compliance presets to apply (e.g. ``["pci_dss", "pii"]``).
categories : list[str]
    Restrict detection to these categories.
min_confidence : float
    Confidence floor forwarded to Siphon (0.0 – 1.0, default 0.0).
require_context : bool
    Require keyword context for a match (mirrors ``--require-context`` on the CLI).
"""
from typing import Optional

from evadex.adapters.base import BaseAdapter, AdapterError
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.adapters.siphon.client import SiphonClient
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, ScanResult, Variant


@register_adapter("siphon")
class SiphonAdapter(BaseAdapter):
    name = "siphon"

    def __init__(self, config):
        super().__init__(config)
        extra = self.config.extra
        self._presets = list(extra.get("presets", []))
        self._categories = list(extra.get("categories", []))
        self._min_confidence = float(extra.get("min_confidence", 0.0))
        self._require_context = bool(extra.get("require_context", False))
        self._client = SiphonClient(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            timeout=self.config.timeout,
        )

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        await self._client.close()

    async def health_check(self) -> bool:
        try:
            await self._client.health()
            return True
        except AdapterError:
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy
        scan_kwargs = dict(
            presets=self._presets,
            categories=self._categories,
            min_confidence=self._min_confidence,
            require_context=self._require_context,
        )

        if strategy == "text":
            raw = await self._client.scan_text(variant.value, **scan_kwargs)
        else:
            data, mime = FileBuilder.build(variant.value, strategy)
            filename = f"evadex_test.{strategy}"
            raw = await self._client.scan_file(data, filename, mime, **scan_kwargs)

        detected = self._parse_detected(raw)
        enrichment = self._parse_enrichment(raw)

        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            raw_response=raw,
            **enrichment,
        )

    def _parse_detected(self, raw: dict) -> bool:
        """Siphon returns ``is_clean`` and ``finding_count``; either signals detection."""
        if not isinstance(raw, dict):
            return False
        if "is_clean" in raw:
            return not bool(raw["is_clean"])
        count = raw.get("finding_count")
        if isinstance(count, (int, float)):
            return count > 0
        findings = raw.get("findings")
        if isinstance(findings, list):
            return len(findings) > 0
        return False

    def _parse_enrichment(self, raw: dict) -> dict:
        """Extract Siphon-specific detail from the first finding.

        Siphon surfaces a few detail fields on its ``findings[]`` objects:
        - ``confidence`` — recognizer confidence (always present on a match)
        - ``bin_brand`` / ``bin_country`` — present for credit card findings
        - ``entropy_classification`` — present for high-entropy heuristics
        - ``validator`` — which validator accepted the match (luhn, mod97, …)

        All are optional — older Siphon versions omit some of them. We
        capture whichever are present on the top-confidence finding.
        """
        out: dict = {}
        if not isinstance(raw, dict):
            return out
        findings = raw.get("findings")
        if not isinstance(findings, list) or not findings:
            return out
        # Pick the highest-confidence finding so enrichment is stable when
        # multiple matches overlap.
        best = max(
            (f for f in findings if isinstance(f, dict)),
            key=lambda f: f.get("confidence", 0.0) or 0.0,
            default=None,
        )
        if best is None:
            return out
        conf = best.get("confidence")
        if isinstance(conf, (int, float)):
            out["confidence"] = float(conf)
        for field in ("bin_brand", "bin_country", "entropy_classification", "validator"):
            val = best.get(field)
            if isinstance(val, str) and val:
                out[field] = val
        return out
