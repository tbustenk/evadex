import asyncio
import json
import subprocess
import tempfile
import os
from evadex.adapters.base import BaseAdapter
from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult

# cmd_style="python"  →  dlpscan -f json <file>         → bare list of matches
# cmd_style="rust"    →  dlpscan --format json scan <file> → list of file objects with nested matches


@register_adapter("dlpscan-cli")
class DlpscanCliAdapter(BaseAdapter):
    name = "dlpscan-cli"

    def __init__(self, config):
        super().__init__(config)
        self._exe = self.config.extra.get("executable", "dlpscan")
        self._cmd_style = self.config.extra.get("cmd_style", "python")

    async def health_check(self) -> bool:
        try:
            result = subprocess.run(
                [self._exe, "--help"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        strategy = variant.strategy
        loop = asyncio.get_running_loop()

        if strategy == "text":
            matches = await loop.run_in_executor(None, self._scan_text, variant.value)
        else:
            data, _ = FileBuilder.build(variant.value, strategy)
            matches = await loop.run_in_executor(None, self._scan_bytes, data, strategy)

        detected = len(matches) > 0
        return ScanResult(payload=payload, variant=variant, detected=detected, raw_response={"matches": matches})

    def _scan_text(self, text: str) -> list:
        return self._run_on_tempfile(text.encode("utf-8"), ".txt")

    def _scan_bytes(self, data: bytes, fmt: str) -> list:
        return self._run_on_tempfile(data, f".{fmt}")

    def _build_command(self, path: str) -> list:
        if self._cmd_style == "rust":
            return [self._exe, "--format", "json", "scan", path]
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

    def _run_on_tempfile(self, data: bytes, suffix: str) -> list:
        # mode=0o600 restricts the temp file to the owner only, preventing other
        # processes from reading sensitive payload values before cleanup.
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w+b") as f:
            # Restrict permissions to owner-only immediately after creation
            try:
                os.chmod(f.name, 0o600)
            except OSError:
                pass  # Best-effort; Windows ACLs are managed differently
            f.write(data)
            path = f.name
        try:
            result = subprocess.run(
                self._build_command(path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.config.timeout,
            )
            if result.returncode != 0:
                raise RuntimeError(f"dlpscan exited {result.returncode}: {result.stderr.strip()}")
            try:
                parsed = json.loads(result.stdout or "[]")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSON from dlpscan: {e}") from e
            return self._extract_matches(parsed)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
