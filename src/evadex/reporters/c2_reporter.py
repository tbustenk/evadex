"""Push evadex results to a Siphon-C2 management-plane instance.

Siphon-C2 is the admin web UI and control API described in
``dlpscan-rs/docs/architecture/microservices.md``. It aggregates
operational metrics plus testing results (FP/FN corpus trends, pattern
coverage) for administrators. This reporter ships evadex scan, false
positive, and comparison results into that dashboard.

Design constraints
------------------
1. **Never fail the caller.** C2 is explicitly "not critical path" in
   the architecture doc — an unreachable C2 must not alter the scan's
   exit code or output. All errors log a single-line warning to stderr
   and return cleanly.
2. **Same auth as Siphon.** The existing HTTP API uses an ``x-api-key``
   header verified via SHA-256 hash. We mirror that so C2 can reuse the
   same key-management surface.
3. **Small, obvious endpoints.** Reports land on ``/v1/evadex/<kind>``
   where kind is ``scan``, ``falsepos``, ``compare``, or ``history``.
   C2 fans these out to its trends dashboards.
4. **Synchronous sync call.** We use ``httpx.post`` with a short
   timeout. Evadex is CLI-invoked and already completed the scan; we
   don't need async fan-out here.
"""
from __future__ import annotations

import os
import socket
import sys
from datetime import datetime, timezone
from typing import Optional

import httpx


DEFAULT_TIMEOUT_SECS = 5.0

C2_ENV_URL = "EVADEX_C2_URL"
C2_ENV_KEY = "EVADEX_C2_KEY"

# Endpoint paths on the Siphon-C2 admin API. Centralised so a future
# version bump (say, /v2/evadex) can change them in one place.
PATH_SCAN = "/v1/evadex/scan"
PATH_FALSEPOS = "/v1/evadex/falsepos"
PATH_COMPARE = "/v1/evadex/compare"
PATH_HISTORY = "/v1/evadex/history"
PATH_HEALTH = "/health"


try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        _VERSION = version("evadex")
    except PackageNotFoundError:
        _VERSION = "unknown"
except ImportError:
    _VERSION = "unknown"


class C2PushError(Exception):
    """Raised only by the low-level client — the public helpers swallow it."""


class C2Client:
    """Thin synchronous HTTP client for the Siphon-C2 admin API.

    Built on httpx.Client so the test suite can mock it with respx and
    so we get the same SSL / timeout behaviour as the rest of evadex's
    HTTP surface.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECS,
    ):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"evadex/{_VERSION}",
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key
        return headers

    def post(self, path: str, body: dict) -> None:
        """POST ``body`` to ``self.base_url + path``.

        Raises :class:`C2PushError` on any failure. Callers in this
        module wrap the call in a try/except that converts errors to
        warnings — see :func:`_push_silently`.
        """
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.post(
                url, json=body, headers=self._headers(), timeout=self._timeout
            )
        except httpx.RequestError as exc:
            raise C2PushError(f"request to {url} failed: {exc}") from exc

        if resp.status_code == 401:
            raise C2PushError(
                f"auth failed (401) pushing to {url} — check --c2-key / EVADEX_C2_KEY"
            )
        if resp.status_code == 403:
            raise C2PushError(f"forbidden (403) pushing to {url}")
        if resp.status_code == 429:
            raise C2PushError(f"rate-limited (429) pushing to {url}")
        if resp.status_code >= 500:
            raise C2PushError(f"server error {resp.status_code} at {url}")
        if resp.status_code >= 400:
            detail = ""
            try:
                detail = resp.json().get("detail", "") if resp.content else ""
            except Exception:
                detail = (resp.text or "")[:200]
            raise C2PushError(f"HTTP {resp.status_code} at {url}: {detail}")


# ── Public helpers ──────────────────────────────────────────────────────────

def resolve_c2_config(
    c2_url: Optional[str],
    c2_key: Optional[str],
    cfg_url: Optional[str] = None,
    cfg_key: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Merge CLI, config file, and env var C2 settings.

    Precedence: CLI > config file > environment variable. Returns
    ``(url, key)`` with ``url=None`` meaning "C2 push is disabled".
    Missing keys are allowed (anonymous push).
    """
    url = c2_url or cfg_url or os.environ.get(C2_ENV_URL)
    key = c2_key or cfg_key or os.environ.get(C2_ENV_KEY)
    return url or None, key or None


def push_scan_results(
    c2_url: Optional[str],
    c2_key: Optional[str],
    *,
    scanner_label: str,
    tool: str,
    categories: list[str],
    strategies: list[str],
    total: int,
    passes: int,
    fails: int,
    errors: int,
    pass_rate: float,
    by_category: Optional[dict] = None,
    by_technique: Optional[dict] = None,
    fail_findings: Optional[list[dict]] = None,
    timeout: float = DEFAULT_TIMEOUT_SECS,
) -> bool:
    """Push one scan's results to C2. Returns True on success."""
    if not c2_url:
        return False
    body = {
        "type": "scan",
        "timestamp": _now(),
        "evadex_version": _VERSION,
        "host": _host(),
        "scanner_label": scanner_label,
        "tool": tool,
        "categories": categories,
        "strategies": strategies,
        "counts": {
            "total": total, "pass": passes,
            "fail": fails, "error": errors,
        },
        "pass_rate": pass_rate,
        "by_category": by_category or {},
        "by_technique": by_technique or {},
        "fail_findings": fail_findings or [],
    }
    return _push_silently(c2_url, c2_key, PATH_SCAN, body, timeout)


def push_falsepos_report(
    c2_url: Optional[str],
    c2_key: Optional[str],
    *,
    report: dict,
    timeout: float = DEFAULT_TIMEOUT_SECS,
) -> bool:
    """Push a falsepos report (the dict built by ``evadex falsepos``)."""
    if not c2_url:
        return False
    body = {
        "type": "falsepos",
        "timestamp": _now(),
        "evadex_version": _VERSION,
        "host": _host(),
        "report": report,
    }
    return _push_silently(c2_url, c2_key, PATH_FALSEPOS, body, timeout)


def push_comparison(
    c2_url: Optional[str],
    c2_key: Optional[str],
    *,
    comparison: dict,
    timeout: float = DEFAULT_TIMEOUT_SECS,
) -> bool:
    """Push a comparison dict (the output of ``build_comparison``)."""
    if not c2_url:
        return False
    body = {
        "type": "compare",
        "timestamp": _now(),
        "evadex_version": _VERSION,
        "host": _host(),
        "comparison": comparison,
    }
    return _push_silently(c2_url, c2_key, PATH_COMPARE, body, timeout)


def push_history_batch(
    c2_url: Optional[str],
    c2_key: Optional[str],
    *,
    entries: list[dict],
    timeout: float = DEFAULT_TIMEOUT_SECS,
) -> bool:
    """Backfill: push a batch of audit-log entries to C2."""
    if not c2_url:
        return False
    body = {
        "type": "history",
        "timestamp": _now(),
        "evadex_version": _VERSION,
        "host": _host(),
        "count": len(entries),
        "entries": entries,
    }
    return _push_silently(c2_url, c2_key, PATH_HISTORY, body, timeout)


# ── Internal ────────────────────────────────────────────────────────────────

def _push_silently(
    c2_url: str,
    c2_key: Optional[str],
    path: str,
    body: dict,
    timeout: float,
) -> bool:
    """Send ``body`` to C2 and swallow errors.

    Returns True if the push succeeded, False if C2 rejected the
    payload, was unreachable, or anything else went wrong. A single
    warning line is printed to stderr on failure.
    """
    client = C2Client(c2_url, api_key=c2_key, timeout=timeout)
    try:
        client.post(path, body)
        return True
    except C2PushError as exc:
        _warn(f"C2 push failed: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001 — truly defensive, never re-raise
        _warn(f"C2 push failed with unexpected error: {exc!r}")
        return False


def _warn(message: str) -> None:
    print(f"[evadex] warning: {message}", file=sys.stderr)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _host() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
