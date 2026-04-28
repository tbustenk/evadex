import asyncio
import time
from typing import AsyncGenerator, Callable, Optional
from evadex.core.result import Payload, Variant, ScanResult
from evadex.adapters.base import BaseAdapter
from evadex.variants.base import BaseVariantGenerator
from evadex.core.registry import all_generators


class Engine:
    def __init__(
        self,
        adapter: BaseAdapter,
        generators: list[BaseVariantGenerator] | None = None,
        concurrency: int = 32,
        strategies: list[str] | None = None,
        on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
        technique_filter: Optional[set[str]] = None,
        streaming: bool = True,
    ):
        self.adapter = adapter
        self.generators = generators  # None = use all registered
        self.concurrency = concurrency
        self.strategies = strategies or ["text", "docx", "pdf", "xlsx"]
        self.on_result = on_result  # callback(result, completed, total)
        # v3.21.0: optional whitelist of technique names. When set, any
        # variant whose technique is not in the set is skipped — used by
        # ``--fast`` to trim the variant pool to high-bypass techniques.
        self.technique_filter = technique_filter
        # v3.25.0: streaming=True (default) submits tasks as variants are
        # generated; streaming=False collects all variants before submitting.
        # Streaming uses less peak memory; batch mode pre-allocates all work.
        self.streaming = streaming

    def run(self, payloads: list[Payload]) -> list[ScanResult]:
        return asyncio.run(self._run_async_collect(payloads))

    async def _run_async_collect(self, payloads: list[Payload]) -> list[ScanResult]:
        results = []
        async for r in self.run_async(payloads):
            results.append(r)
        return results

    async def run_async(self, payloads: list[Payload]) -> AsyncGenerator[ScanResult, None]:
        generators = self.generators if self.generators is not None else all_generators()
        sem = asyncio.Semaphore(self.concurrency)

        await self.adapter.setup()
        pending: set[asyncio.Task] = set()
        completed = 0
        total_submitted = 0

        async def _submit_one(payload: Payload, variant: Variant, strategy: str) -> ScanResult:
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
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    return ScanResult(
                        payload=payload,
                        variant=v,
                        detected=False,
                        error=str(e),
                        duration_ms=(time.perf_counter() - start) * 1000,
                    )

        try:
            if self.streaming:
                # Streaming mode (default): submit tasks as variants are generated
                # so subprocess calls start immediately rather than waiting for all
                # variants to be built. Peak memory proportional to concurrency.
                for payload in payloads:
                    for gen in generators:
                        if hasattr(gen, 'applicable_categories') and gen.applicable_categories is not None:
                            if payload.category not in gen.applicable_categories:
                                continue
                        for variant in gen.generate(payload.value):
                            if self.technique_filter is not None and variant.technique not in self.technique_filter:
                                continue
                            for strategy in self.strategies:
                                task = asyncio.create_task(_submit_one(payload, variant, strategy))
                                pending.add(task)
                                total_submitted += 1
                                # Drain any tasks that already completed while we were generating
                                done = {t for t in pending if t.done()}
                                for t in done:
                                    pending.discard(t)
                                    completed += 1
                                    result = t.result()
                                    if self.on_result:
                                        try:
                                            self.on_result(result, completed, total_submitted)
                                        except Exception:
                                            pass
                                    yield result
            else:
                # Batch mode (--no-stream): enumerate all (payload, variant, strategy)
                # tuples into a list first, then submit them all. Uses more peak memory
                # than streaming but makes total_submitted known upfront.
                all_work: list[tuple] = []
                for payload in payloads:
                    for gen in generators:
                        if hasattr(gen, 'applicable_categories') and gen.applicable_categories is not None:
                            if payload.category not in gen.applicable_categories:
                                continue
                        for variant in gen.generate(payload.value):
                            if self.technique_filter is not None and variant.technique not in self.technique_filter:
                                continue
                            for strategy in self.strategies:
                                all_work.append((payload, variant, strategy))
                total_submitted = len(all_work)
                for payload, variant, strategy in all_work:
                    task = asyncio.create_task(_submit_one(payload, variant, strategy))
                    pending.add(task)

            # Drain remaining in-flight tasks (shared by both modes)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    completed += 1
                    result = t.result()
                    if self.on_result:
                        try:
                            self.on_result(result, completed, total_submitted)
                        except Exception:
                            pass
                    yield result

        except BaseException:
            for t in pending:
                t.cancel()
            raise
        finally:
            await self.adapter.teardown()
