import asyncio
import json
import tempfile
import os
from evadex.adapters.base import BaseAdapter
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult


@register_adapter("dlpscan-cli")
class DlpscanCliAdapter(BaseAdapter):
    name = "dlpscan-cli"

    def __init__(self, config):
        super().__init__(config)
        self._exe = self.config.extra.get("executable", "dlpscan")

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy
        loop = asyncio.get_running_loop()

        if strategy == "text":
            raw = await loop.run_in_executor(None, self._scan_text, variant.value)
        else:
            data, _ = FileBuilder.build(variant.value, strategy)
            raw = await loop.run_in_executor(None, self._scan_bytes, data, strategy)

        detected = len(raw) > 0
        return ScanResult(payload=payload, variant=variant, detected=detected, raw_response={"matches": raw})

    def _scan_text(self, text: str) -> list:
        suffix = ".txt"
        return self._run_on_tempfile(text.encode("utf-8"), suffix)

    def _scan_bytes(self, data: bytes, fmt: str) -> list:
        suffix = f".{fmt}"
        return self._run_on_tempfile(data, suffix)

    def _run_on_tempfile(self, data: bytes, suffix: str) -> list:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            f.write(data)
            path = f.name
        try:
            import subprocess
            result = subprocess.run(
                [self._exe, "-f", "json", path],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            if result.returncode != 0:
                raise RuntimeError(f"dlpscan exited {result.returncode}: {result.stderr.strip()}")
            try:
                return json.loads(result.stdout or "[]")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSON from dlpscan: {e}") from e
        finally:
            os.unlink(path)
