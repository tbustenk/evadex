"""Async transports for the Siphon DLP scanner.

Two transport implementations are provided:

``SiphonCliClient`` (default)
    Spawns ``siphon scan-text`` / ``siphon scan`` as a subprocess and parses
    its ``--format json`` output.  One process per variant — simple but with
    ~50 ms spawn overhead per call.

``SiphonHttpClient``
    POSTs to a running ``siphon serve`` / ``siphon-api`` HTTP endpoint.
    Reuses a single ``httpx.AsyncClient`` across calls; no spawn overhead.
    Expected throughput: 200+ variants/sec vs ~8 for the CLI transport.

Supported CLI invocation styles
--------------------------------
``binary`` (default): ``siphon scan-text --format json``
``cargo``:            ``cargo run --release --bin siphon -- scan-text --format json``
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


class SiphonHttpClient:
    """Scan via a running siphon-api / ``siphon serve`` HTTP endpoint.

    Uses ``httpx`` (already a core evadex dependency) with an async client
    context opened per call.  For high-throughput use, pass a shared
    ``httpx.AsyncClient`` via the ``_client`` kwarg; otherwise a fresh
    one is created per call (safe but slightly less efficient).

    Response shape from ``POST /scan``:
        {
            "findings": [
                {"category": "...", "sub_category": "...", "text": "...",
                 "confidence": 0.95, "has_context": true,
                 "span": [0, 16], "metadata": {...}},
                ...
            ],
            "finding_count": 1,
            "scan_duration_ms": 2,
            ...
        }

    ``scan_text`` returns a list in the same shape as ``SiphonCliClient``'s
    output so the adapter's ``_parse_enrichment`` logic is reused unchanged.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._persistent_client = None  # lazy-init by _get_client()

    def _headers(self) -> dict:
        h: dict = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    async def _get_client(self):
        """Return the shared persistent httpx client, creating it on first use.

        The client is kept open for the lifetime of this object so TCP
        connections are reused across calls (connection pooling). Call
        ``close()`` when done to release the underlying transport.
        """
        import httpx

        if self._persistent_client is None:
            self._persistent_client = httpx.AsyncClient(timeout=self._timeout)
        return self._persistent_client

    async def close(self) -> None:
        """Close the underlying httpx transport and release connections."""
        if self._persistent_client is not None:
            await self._persistent_client.aclose()
            self._persistent_client = None

    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            resp = await client.get(f"{self._base_url}/health")
            return resp.status_code == 200
        except Exception:
            return False

    async def scan_text(self, text: str) -> list:
        """POST *text* to ``/scan`` and return the findings list.

        The findings list uses the same field names (``category``,
        ``sub_category``, ``text``, ``confidence``, ``has_context``,
        ``span``, ``metadata``) as the CLI JSON output so
        ``SiphonCliAdapter._parse_enrichment`` works unmodified.

        Uses the persistent httpx client for connection reuse across calls.
        """
        import httpx

        client = await self._get_client()
        try:
            resp = await client.post(
                f"{self._base_url}/scan",
                json={"text": text},
                headers=self._headers(),
            )
        except httpx.TimeoutException:
            raise SiphonCliError(
                f"siphon HTTP scan timed out after {self._timeout}s"
            )
        except httpx.RequestError as exc:
            raise SiphonCliError(f"siphon HTTP request error: {exc}") from exc

        if resp.status_code == 401:
            raise SiphonCliError("siphon HTTP 401: API key required or invalid")
        if resp.status_code != 200:
            raise SiphonCliError(
                f"siphon HTTP {resp.status_code}: {resp.text[:300]}"
            )

        data = resp.json()
        return data.get("findings", [])

    async def scan_file_bytes(self, data: bytes, suffix: str) -> list:
        """Scan file bytes via ``/scan`` by submitting as UTF-8 text.

        siphon-api only exposes a text ``/scan`` endpoint (file scanning lives
        in the separate siphon-fs service).  We decode the file bytes to UTF-8
        and submit them directly — adequate for regex-layer evasion tests where
        the file-format wrapper bytes are noise anyway.

        Callers that need true file-extraction pipeline testing should use the
        CLI transport (``transport: cli``) which invokes ``siphon scan <file>``.
        """
        text = data.decode("utf-8", errors="replace")
        return await self.scan_text(text)


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
