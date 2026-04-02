import asyncio
import time
from typing import AsyncIterator
from evadex.core.result import Payload, Variant, ScanResult
from evadex.adapters.base import BaseAdapter
from evadex.variants.base import BaseVariantGenerator
from evadex.core.registry import all_generators


class Engine:
    def __init__(
        self,
        adapter: BaseAdapter,
        generators: list[BaseVariantGenerator] | None = None,
        concurrency: int = 5,
        strategies: list[str] | None = None,
    ):
        self.adapter = adapter
        self.generators = generators  # None = use all registered
        self.concurrency = concurrency
        self.strategies = strategies or ["text", "docx", "pdf", "xlsx"]

    def run(self, payloads: list[Payload]) -> list[ScanResult]:
        return asyncio.run(self._run_async_collect(payloads))

    async def _run_async_collect(self, payloads: list[Payload]) -> list[ScanResult]:
        results = []
        async for r in self.run_async(payloads):
            results.append(r)
        return results

    async def run_async(self, payloads: list[Payload]) -> AsyncIterator[ScanResult]:
        generators = self.generators if self.generators is not None else all_generators()
        sem = asyncio.Semaphore(self.concurrency)
        tasks = []

        for payload in payloads:
            for gen in generators:
                # Check applicable_categories
                if hasattr(gen, 'applicable_categories') and gen.applicable_categories is not None:
                    if payload.category not in gen.applicable_categories:
                        continue
                for variant in gen.generate(payload.value):
                    for strategy in self.strategies:
                        tasks.append(self._run_one(sem, payload, variant, strategy))

        await self.adapter.setup()
        try:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                yield result
        finally:
            await self.adapter.teardown()

    async def _run_one(
        self, sem: asyncio.Semaphore, payload: Payload, variant, strategy: str
    ) -> ScanResult:
        # Clone variant with strategy
        v = Variant(
            value=variant.value,
            generator=variant.generator,
            technique=variant.technique,
            transform_name=variant.transform_name,
            strategy=strategy,
        )
        async with sem:
            start = time.perf_counter()
            try:
                result = await self.adapter.submit(payload, v)
                result.duration_ms = (time.perf_counter() - start) * 1000
                return result
            except Exception as e:
                return ScanResult(
                    payload=payload,
                    variant=v,
                    detected=False,
                    error=str(e),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
