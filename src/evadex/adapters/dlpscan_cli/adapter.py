import asyncio
import json
import random
import tempfile
import os
from evadex.adapters.base import BaseAdapter
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult
from evadex.generate.filler import get_keyword_sentence

# cmd_style="python"  →  dlpscan -f json <file>         → bare list of matches
# cmd_style="rust"    →  dlpscan --format json scan <file> → list of file objects with nested matches


@register_adapter("dlpscan-cli")
class DlpscanCliAdapter(BaseAdapter):
    name = "dlpscan-cli"

    def __init__(self, config):
        super().__init__(config)
        self._exe = self.config.extra.get("executable", "dlpscan")
        self._cmd_style = self.config.extra.get("cmd_style", "python")
        self._wrap_context = self.config.extra.get("wrap_context", False)

    async def health_check(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self._exe, "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return False
            return proc.returncode == 0
        except (FileNotFoundError, OSError):
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy

        if strategy == "text":
            text = variant.value
            if self._wrap_context:
                # Embed the variant value in a realistic keyword sentence so that
                # dlpscan-rs context requirements are satisfied.  The original
                # variant.value is preserved in the result for reporting.
                text = get_keyword_sentence(random.Random(), payload.category, text)
            matches = await self._scan_text_async(text)
        else:
            data, _ = FileBuilder.build(variant.value, strategy)
            matches = await self._scan_bytes_async(data, strategy)

        detected = len(matches) > 0
        return ScanResult(payload=payload, variant=variant, detected=detected, raw_response={"matches": matches})

    async def _scan_text_async(self, text: str) -> list:
        return await self._run_on_tempfile_async(text.encode("utf-8"), ".txt")

    async def _scan_bytes_async(self, data: bytes, fmt: str) -> list:
        return await self._run_on_tempfile_async(data, f".{fmt}")

    def _build_command(self, path: str) -> list:
        require_context = self.config.extra.get("require_context", False)
        if self._cmd_style == "rust":
            cmd = [self._exe, "--format", "json"]
            if require_context:
                cmd.append("--require-context")
            cmd += ["scan", path]
            return cmd
        return [self._exe, "-f", "json", path]

    def _extract_matches(self, parsed: object) -> list:
        if not isinstance(parsed, list):
            raise RuntimeError(
                f"dlpscan returned unexpected JSON type {type(parsed).__name__!r}; expected list"
            )
        if self._cmd_style == "rust":
            # Rust scan returns: [{file_path, matches:[...], error, ...}]
            if not parsed:
                return []
            file_obj = parsed[0]
            if not isinstance(file_obj, dict):
                raise RuntimeError(
                    f"dlpscan (rust) file object is {type(file_obj).__name__!r}; expected dict"
                )
            if file_obj.get("error"):
                raise RuntimeError(f"dlpscan (rust) scan error: {file_obj['error']}")
            matches = file_obj.get("matches", [])
            if not isinstance(matches, list):
                raise RuntimeError(
                    f"dlpscan (rust) matches field is {type(matches).__name__!r}; expected list"
                )
            return matches
        # Python: parsed is already the flat list of matches
        return parsed

    async def _run_on_tempfile_async(self, data: bytes, suffix: str) -> list:
        # mode=0o600 restricts the temp file to the owner only, preventing other
        # processes from reading sensitive payload values before cleanup.
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w+b") as f:
            try:
                os.chmod(f.name, 0o600)
            except OSError:
                pass  # Best-effort; Windows ACLs are managed differently
            f.write(data)
            path = f.name
        try:
            cmd = self._build_command(path)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.config.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise RuntimeError(f"dlpscan timed out after {self.config.timeout}s")

            if proc.returncode != 0:
                raise RuntimeError(
                    f"dlpscan exited {proc.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace').strip()}"
                )
            stdout_text = stdout.decode("utf-8", errors="replace")
            try:
                parsed = json.loads(stdout_text or "[]")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSON from dlpscan: {e}") from e
            return self._extract_matches(parsed)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
