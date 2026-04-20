"""Async subprocess wrapper for the Siphon CLI binary.

Siphon exposes a ``scan-text`` subcommand that reads text from stdin and a
``scan`` subcommand that takes a file path. Both emit a JSON array of match
objects when ``--format json`` is passed. Empty array ``[]`` means no matches.

File-scan responses wrap matches inside a per-file object with a ``matches``
key (and entropy / file_size / error metadata), so the two shapes differ.

Supported invocation styles
---------------------------
``binary`` (default): ``siphon scan-text --format json``
``cargo``:           ``cargo run --release --bin siphon -- scan-text --format json``
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from typing import Optional


class SiphonCliError(RuntimeError):
    pass


class SiphonCliClient:
    """Runs the Siphon CLI as a subprocess and parses its JSON output."""

    def __init__(
        self,
        executable: str = "siphon",
        cmd_style: str = "binary",
        timeout: float = 30.0,
        require_context: bool = False,
        min_confidence: float = 0.0,
        categories: Optional[list] = None,
    ):
        self._exe = executable
        self._cmd_style = cmd_style
        self._timeout = timeout
        self._require_context = require_context
        self._min_confidence = float(min_confidence)
        self._categories = list(categories) if categories else []

    def _base_command(self) -> list:
        if self._cmd_style == "cargo":
            # ``cargo run --release --bin siphon -- <args>`` invokes the
            # compiled siphon binary through cargo. The ``--`` separator
            # stops cargo from consuming the scanner's own flags.
            return ["cargo", "run", "--release", "--bin", "siphon", "--"]
        return [self._exe]

    def _common_flags(self) -> list:
        flags = ["--format", "json"]
        if self._require_context:
            flags.append("--require-context")
        if self._min_confidence > 0.0:
            flags += ["--min-confidence", str(self._min_confidence)]
        if self._categories:
            flags += ["--categories", ",".join(self._categories)]
        return flags

    def build_scan_text_command(self) -> list:
        return self._base_command() + ["scan-text"] + self._common_flags()

    def build_scan_file_command(self, path: str) -> list:
        return self._base_command() + ["scan"] + self._common_flags() + [path]

    async def health_check(self) -> bool:
        cmd = self._base_command() + ["--version"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return False
            return proc.returncode == 0
        except (FileNotFoundError, OSError):
            return False

    async def scan_text(self, text: str) -> list:
        """Pipe *text* through ``siphon scan-text`` and parse the response.

        Returns the raw list of match dicts (may be empty).
        """
        cmd = self.build_scan_text_command()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(text.encode("utf-8")),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise SiphonCliError(f"siphon scan-text timed out after {self._timeout}s")

        if proc.returncode != 0:
            raise SiphonCliError(
                f"siphon scan-text exited {proc.returncode}: "
                f"{stderr.decode('utf-8', errors='replace').strip()}"
            )
        return _parse_matches(stdout.decode("utf-8", errors="replace"))

    async def scan_file_bytes(self, data: bytes, suffix: str) -> list:
        """Write *data* to a temp file, run ``siphon scan``, return matches."""
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w+b") as f:
            try:
                os.chmod(f.name, 0o600)
            except OSError:
                pass
            f.write(data)
            path = f.name
        try:
            cmd = self.build_scan_file_command(path)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise SiphonCliError(f"siphon scan timed out after {self._timeout}s")

            if proc.returncode != 0:
                raise SiphonCliError(
                    f"siphon scan exited {proc.returncode}: "
                    f"{stderr.decode('utf-8', errors='replace').strip()}"
                )
            return _parse_file_matches(stdout.decode("utf-8", errors="replace"))
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass


def _parse_matches(stdout_text: str) -> list:
    """Parse the JSON response from ``siphon scan-text``.

    The scan-text subcommand returns a top-level JSON array of match
    objects. An empty document produces ``[]``.
    """
    try:
        parsed = json.loads(stdout_text or "[]")
    except json.JSONDecodeError as e:
        raise SiphonCliError(f"Invalid JSON from siphon: {e}") from e
    if not isinstance(parsed, list):
        raise SiphonCliError(
            f"siphon returned unexpected JSON type {type(parsed).__name__!r}; "
            "expected list"
        )
    return parsed


def _parse_file_matches(stdout_text: str) -> list:
    """Parse the JSON response from ``siphon scan`` (file scan).

    File scans wrap matches inside a list of per-file objects:
        [{"file_path": "...", "matches": [...], "error": null, ...}]
    """
    try:
        parsed = json.loads(stdout_text or "[]")
    except json.JSONDecodeError as e:
        raise SiphonCliError(f"Invalid JSON from siphon: {e}") from e
    if not isinstance(parsed, list):
        raise SiphonCliError(
            f"siphon returned unexpected JSON type {type(parsed).__name__!r}; "
            "expected list"
        )
    if not parsed:
        return []
    file_obj = parsed[0]
    if not isinstance(file_obj, dict):
        raise SiphonCliError(
            f"siphon file object is {type(file_obj).__name__!r}; expected dict"
        )
    if file_obj.get("error"):
        raise SiphonCliError(f"siphon scan error: {file_obj['error']}")
    matches = file_obj.get("matches", [])
    if not isinstance(matches, list):
        raise SiphonCliError(
            f"siphon matches field is {type(matches).__name__!r}; expected list"
        )
    return matches
