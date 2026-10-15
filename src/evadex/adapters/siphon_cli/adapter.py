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
batch           : CLI transport only. Coalesce concurrent submissions, text
                  and file strategies alike, into one ``siphon scan-dir``
                  process instead of one process each (default ``False``)
batch_size      : flush a batch at this many pending items (default 64)
batch_wait      : or this many seconds after its first item (default 0.05)
"""

from __future__ import annotations

import asyncio

from evadex.adapters.base import AdapterConfig, BaseAdapter
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.adapters.siphon_cli.client import (
    SiphonCliClient,
    SiphonCliNoResult,
    SiphonHttpClient,
)
from evadex.core.registry import register_adapter
from evadex.core.relevance import classify_detection
from evadex.core.result import Payload, ScanResult, Variant
from evadex.generate.filler import get_keyword_sentence, sentence_rng


_BIN_FIELDS = ("bin_brand", "bin_card_type", "bin_country", "bin_issuer")


class _Batcher:
    """Coalesce concurrent submissions into one ``scan-dir`` process.

    The engine keeps up to ``concurrency`` submissions in flight and each one
    used to pay a scanner start-up (~0.3 s of regex and automaton building)
    for ~10 ms of scanning; Siphon's quality gate spent 2.5 hours that way.
    Text and file strategies alike become one file each in a batch
    directory. A caller awaits a future; the batch holding it flushes when it
    reaches ``max_size`` items or ``max_wait`` seconds after its first item,
    whichever comes first, so a lone call still returns promptly. An item
    ``scan-dir`` reports nothing for is re-run through ``siphon scan`` on
    its own, so a batched run never answers less than a per-file run would.
    """

    def __init__(
        self, client: SiphonCliClient, max_size: int = 64, max_wait: float = 0.05
    ) -> None:
        self._client = client
        self._max_size = max(1, int(max_size))
        self._max_wait = max(0.0, float(max_wait))
        self._pending: list = []
        self._timer: asyncio.TimerHandle | None = None
        self._tasks: set = set()

    async def scan_text(self, text: str) -> list:
        return await self._submit((text.encode("utf-8"), ".txt"))

    async def scan_bytes(self, data: bytes, suffix: str) -> list:
        return await self._submit((data, suffix))

    async def _submit(self, item: tuple) -> list:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending.append((item, fut))
        if len(self._pending) >= self._max_size:
            self._flush()
        elif self._timer is None:
            self._timer = loop.call_later(self._max_wait, self._flush)
        return await fut

    def _flush(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        batch, self._pending = self._pending, []
        if not batch:
            return
        task = asyncio.ensure_future(self._run(batch))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, batch: list) -> None:
        try:
            results = await self._client.scan_batch([item for item, _ in batch])
        except Exception as exc:
            for _, fut in batch:
                if not fut.done():
                    fut.set_exception(exc)
            return
        retry: list = []
        for (item, fut), result in zip(batch, results):
            if fut.done():
                continue
            if isinstance(result, SiphonCliNoResult):
                retry.append((item, fut))
            elif isinstance(result, BaseException):
                fut.set_exception(result)
            else:
                fut.set_result(result)
        for (data, suffix), fut in retry:
            try:
                fut.set_result(await self._client.scan_file_bytes(data, suffix))
            except Exception as exc:
                fut.set_exception(exc)

    async def drain(self) -> None:
        """Flush whatever is pending and wait for every in-flight batch."""
        self._flush()
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


@register_adapter("siphon-cli")
class SiphonCliAdapter(BaseAdapter):
    """Adapter for the Siphon DLP scanner.

    Supports three transports selected by the ``transport`` extra config key:

    ``cli`` (default)
        Spawns ``siphon scan-text`` / ``siphon scan`` as a subprocess.
        Requires the siphon binary on PATH (or ``executable`` in extra config).

    ``http``
        POSTs to a running ``siphon serve`` / ``siphon-api`` HTTP endpoint.
        No subprocess overhead; 200+ variants/sec vs ~8 for CLI mode.
        Requires ``siphon serve`` (or the ``siphon-api`` binary) to be running.
        Point it at the server with ``base_url`` / ``--url`` and authenticate
        with ``api_key`` / ``--api-key``.

    ``auto``
        Probes the configured ``base_url`` (default ``http://localhost:8080``)
        during :meth:`setup`.  Selects ``http`` if reachable, ``cli`` otherwise.
        Useful for configs that run in both laptop-dev and CI environments
        without editing ``evadex.yaml``.
    """

    name = "siphon-cli"

    def __init__(self, config: "dict | AdapterConfig") -> None:
        super().__init__(config)
        extra = self.config.extra
        self._transport = extra.get("transport", "cli")
        self._wrap_context = bool(extra.get("wrap_context", False))
        # Seed for the per-submission template draw under wrap_context. None
        # keeps the pre-3.41.0 behaviour (a fresh unseeded RNG per call).
        _seed = extra.get("seed")
        self._seed: int | None = int(_seed) if _seed is not None else None
        self._require_context = bool(extra.get("require_context", False))
        self._min_confidence = float(extra.get("min_confidence", 0.0))
        self._categories = list(extra.get("categories", []))
        self._batch = bool(extra.get("batch", False))
        self._batch_size = int(extra.get("batch_size", 64))
        self._batch_wait = float(extra.get("batch_wait", 0.05))
        self._batcher: _Batcher | None = None

        exe = extra.get("executable", "siphon")
        cmd_style = extra.get("cmd_style", "binary")
        http_kwargs = dict(
            base_url=self.config.base_url or "http://localhost:8080",
            api_key=self.config.api_key,
            timeout=self.config.timeout,
            require_context=self._require_context,
            min_confidence=self._min_confidence,
            categories=self._categories,
        )
        cli_kwargs = dict(
            executable=exe,
            cmd_style=cmd_style,
            timeout=self.config.timeout,
            require_context=self._require_context,
            min_confidence=self._min_confidence,
            categories=self._categories,
        )
        if self._transport == "http":
            self._http_client: SiphonHttpClient | None = SiphonHttpClient(**http_kwargs)
            self._client: SiphonCliClient | None = None
        elif self._transport == "auto":
            # Both clients created upfront; setup() resolves which to use.
            self._http_client = SiphonHttpClient(**http_kwargs)
            self._client = SiphonCliClient(**cli_kwargs)
        else:
            self._http_client = None
            self._client = SiphonCliClient(**cli_kwargs)
            self._install_batcher()

    def _install_batcher(self) -> None:
        if self._batch and self._client is not None and self._batcher is None:
            self._batcher = _Batcher(
                self._client, max_size=self._batch_size, max_wait=self._batch_wait
            )

    async def setup(self) -> None:
        """Resolve ``auto`` transport by probing the HTTP endpoint."""
        if self._transport != "auto":
            return
        try:
            reachable = await self._http_client.health_check()  # type: ignore[union-attr]
        except Exception:
            reachable = False
        if reachable:
            self._transport = "http"
            self._client = None
        else:
            self._transport = "cli"
            if self._http_client is not None:
                await self._http_client.close()
            self._http_client = None
            self._install_batcher()

    async def teardown(self) -> None:
        if self._batcher is not None:
            await self._batcher.drain()
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
                text = get_keyword_sentence(
                    sentence_rng(self._seed, payload.category, variant.value),
                    payload.category,
                    text,
                )
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
                text = get_keyword_sentence(
                    sentence_rng(self._seed, payload.category, variant.value),
                    payload.category,
                    text,
                )
            if self._batcher is not None:
                matches = await self._batcher.scan_text(text)
            else:
                matches = await self._client.scan_text(text)  # type: ignore[union-attr]
        else:
            data, _ = FileBuilder.build(variant.value, strategy)
            if self._batcher is not None:
                matches = await self._batcher.scan_bytes(data, f".{strategy}")
            else:
                matches = await self._client.scan_file_bytes(data, f".{strategy}")  # type: ignore[union-attr]

        detected, detected_any = classify_detection(payload.category.value, matches)
        enrichment = self._parse_enrichment(matches)

        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            detected_any=detected_any,
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
