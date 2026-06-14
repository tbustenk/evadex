"""evadex adapter for the Siphon CLI (``siphon.exe``).

Parallel to :mod:`evadex.adapters.dlpscan_cli` but targets the Siphon
subcommand surface:

* Text  : piped via stdin to ``siphon scan-text --format json``
* File  : written to a temp file, then ``siphon scan --format json <path>``

Response shape (scan-text): top-level JSON array of match objects with
``category``, ``confidence``, ``span``, ``sub_category``, ``text``, and a
``metadata`` dict that carries BIN enrichment for credit card matches
(``bin_brand``, ``bin_card_type``, ``bin_country``, ``bin_issuer``).

Extra config keys (via adapter extra dict / evadex.yaml)
--------------------------------------------------------
executable      : path to the siphon binary (default ``"siphon"``)
cmd_style       : ``"binary"`` (default) or ``"cargo"`` — the latter invokes
                  ``cargo run --release --bin siphon -- ...``
wrap_context    : embed the variant value in a keyword sentence before
                  submission (mirrors dlpscan-cli behaviour)
require_context : pass ``--require-context`` to the scanner
min_confidence  : confidence floor (``--min-confidence``)
categories      : restrict scanning to these categories (``--categories``)
"""

from __future__ import annotations

import random

from evadex.adapters.base import AdapterConfig, BaseAdapter
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.adapters.siphon_cli.client import SiphonCliClient, SiphonHttpClient
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, ScanResult, Variant
from evadex.generate.filler import get_keyword_sentence


_BIN_FIELDS = ("bin_brand", "bin_card_type", "bin_country", "bin_issuer")


@register_adapter("siphon-cli")
class SiphonCliAdapter(BaseAdapter):
    """Adapter for the Siphon DLP scanner.

    Supports two transports selected by the ``transport`` extra config key:

    ``cli`` (default)
        Spawns ``siphon scan-text`` / ``siphon scan`` as a subprocess.
        Requires the siphon binary on PATH (or ``executable`` in extra config).

    ``http``
        POSTs to a running ``siphon serve`` / ``siphon-api`` HTTP endpoint.
        No subprocess overhead; 200+ variants/sec vs ~8 for CLI mode.
        Requires ``siphon serve`` (or the ``siphon-api`` binary) to be running.
        Point it at the server with ``base_url`` / ``--url`` and authenticate
        with ``api_key`` / ``--api-key``.
    """

    name = "siphon-cli"

    def __init__(self, config: "dict | AdapterConfig") -> None:
        super().__init__(config)
        extra = self.config.extra
        self._transport = extra.get("transport", "cli")
        self._wrap_context = bool(extra.get("wrap_context", False))
        self._require_context = bool(extra.get("require_context", False))
        self._min_confidence = float(extra.get("min_confidence", 0.0))
        self._categories = list(extra.get("categories", []))

        if self._transport == "http":
            self._http_client: SiphonHttpClient | None = SiphonHttpClient(
                base_url=self.config.base_url or "http://localhost:8080",
                api_key=self.config.api_key,
                timeout=self.config.timeout,
            )
            self._client: SiphonCliClient | None = None
        else:
            self._http_client = None
            exe = extra.get("executable", "siphon")
            cmd_style = extra.get("cmd_style", "binary")
            self._client = SiphonCliClient(
                executable=exe,
                cmd_style=cmd_style,
                timeout=self.config.timeout,
                require_context=self._require_context,
                min_confidence=self._min_confidence,
                categories=self._categories,
            )

    async def teardown(self) -> None:
        if self._transport == "http" and self._http_client is not None:
            await self._http_client.close()

    async def health_check(self) -> bool:
        if self._transport == "http":
            return await self._http_client.health_check()  # type: ignore[union-attr]
        return await self._client.health_check()  # type: ignore[union-attr]

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy

        if self._transport == "http":
            # HTTP transport: always submits as text (siphon-api /scan endpoint).
            # File-format strategies are decoded to UTF-8 before submission —
            # adequate for regex-layer evasion tests; for file-extraction pipeline
            # tests use transport=cli which invokes ``siphon scan <file>``.
            text = variant.value
            if self._wrap_context:
                text = get_keyword_sentence(random.Random(), payload.category, text)
            if strategy != "text":
                data, _ = FileBuilder.build(variant.value, strategy)
                matches = await self._http_client.scan_file_bytes(data, f".{strategy}")  # type: ignore[union-attr]
            else:
                matches = await self._http_client.scan_text(text)  # type: ignore[union-attr]
        elif strategy == "text":
            text = variant.value
            if self._wrap_context:
                # Siphon's rules often require keyword context to fire. Wrap
                # the bare variant in a realistic sentence so detection rates
                # reflect what a scanner would see in real documents.
                text = get_keyword_sentence(random.Random(), payload.category, text)
            matches = await self._client.scan_text(text)  # type: ignore[union-attr]
        else:
            data, _ = FileBuilder.build(variant.value, strategy)
            matches = await self._client.scan_file_bytes(data, f".{strategy}")  # type: ignore[union-attr]

        detected = len(matches) > 0
        enrichment = self._parse_enrichment(matches)

        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            raw_response={"matches": matches},
            **enrichment,
        )

    def _parse_enrichment(self, matches: list) -> dict[str, object]:
        """Extract enrichment fields from the highest-confidence match.

        Siphon surfaces a ``confidence`` float on every match and a
        ``metadata`` dict that carries BIN enrichment for credit card
        findings. We pick the top-confidence match so enrichment is
        stable when multiple overlap.
        """
        if not matches:
            return {}
        best = max(
            (m for m in matches if isinstance(m, dict)),
            key=lambda m: m.get("confidence", 0.0) or 0.0,
            default=None,
        )
        if best is None:
            return {}
        out: dict = {}
        conf = best.get("confidence")
        if isinstance(conf, (int, float)):
            out["confidence"] = float(conf)
        sub = best.get("sub_category")
        if isinstance(sub, str) and sub:
            out["sub_category"] = sub
        metadata = best.get("metadata")
        if isinstance(metadata, dict):
            for field in _BIN_FIELDS:
                val = metadata.get(field)
                if isinstance(val, str) and val:
                    out[field] = val
        return out
