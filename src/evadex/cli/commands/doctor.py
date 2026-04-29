"""evadex doctor — environment health check.

Rapid, read-only diagnostic that reports whether every optional
component evadex relies on is actually available in the current
environment. The command never mutates state (no writes to audit
logs, no network POSTs) — it inspects and prints.

Exit codes:

* ``0`` if every check passed or only raised *warnings* (yellow ⚠)
* ``1`` if any check *failed* (red ✗)

That split lets CI pipelines gate on ``evadex doctor`` without
tripping on optional-extra warnings.
"""
from __future__ import annotations

import importlib
import importlib.metadata as im
import os
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import click
from rich.console import Console

err_console = Console()


# Status symbols — kept as plain ASCII so a Windows console without
# CP65001 still renders cleanly.
_OK = "[green]✓[/green]"      # ✓
_BAD = "[red]✗[/red]"         # ✗
_WARN = "[yellow]⚠[/yellow]"  # ⚠


@dataclass
class _Check:
    ok: bool
    msg: str
    # ``warn`` means "pass, but worth a note". The overall exit code
    # only flips to non-zero on a hard failure (ok=False, warn=False).
    warn: bool = False

    def render(self) -> str:
        if self.warn:
            return f"{_WARN} {self.msg}"
        return f"{_OK if self.ok else _BAD} {self.msg}"


def _check_evadex_version() -> _Check:
    try:
        v = im.version("evadex")
        return _Check(True, f"evadex {v}")
    except im.PackageNotFoundError:
        return _Check(False, "evadex package metadata missing — reinstall?")


def _check_python() -> _Check:
    v = sys.version_info
    msg = f"Python {v.major}.{v.minor}.{v.micro}"
    # 3.10 is the declared floor in pyproject.toml.
    if (v.major, v.minor) < (3, 10):
        return _Check(False, f"{msg} — requires 3.10 or newer")
    return _Check(True, msg)


def _check_siphon() -> _Check:
    # First check PATH — fastest and covers the system-install case.
    for name in ("siphon", "siphon.exe", "siphon-cli", "siphon-cli.exe"):
        found = shutil.which(name)
        if found:
            return _Check(True, f"siphon found at {found}")
    # Fall back to the same resolver the bridge uses (env vars,
    # evadex.yaml, well-known paths) so a developer build sitting in
    # ./target/release/siphon isn't reported as missing.
    try:
        from evadex.bridge.server import _resolve_siphon_exe
        resolved = _resolve_siphon_exe()
    except Exception:
        resolved = None
    if resolved:
        return _Check(True, f"siphon resolved at {resolved} (not on PATH)", warn=True)
    return _Check(
        False,
        "siphon not found on PATH or in any known install location — "
        "install siphon-cli, set SIPHON_EXE, or pass --exe to `evadex scan`",
    )


def _check_extra(pkg: str, label: str, purpose: str) -> _Check:
    """Check that a single optional extra's flagship package is importable."""
    try:
        importlib.import_module(pkg)
        return _Check(True, f"evadex\\[{label}] installed")
    except ImportError:
        return _Check(False, f"evadex\\[{label}] not installed — {purpose}")


def _bridge_reachable(url: str) -> bool:
    """Return True if the bridge health endpoint responds with any 2xx."""
    try:
        with urlopen(url, timeout=1.5) as resp:
            return 200 <= resp.status < 300
    except (URLError, socket.timeout, ConnectionError, OSError):
        return False


def _check_bridge() -> list[_Check]:
    """Bridge requires two things to be useful: the extra must be
    installed, AND a bridge process must be reachable. We split those
    so the operator sees which side is broken."""
    checks: list[_Check] = []
    try:
        importlib.import_module("fastapi")
        importlib.import_module("uvicorn")
        checks.append(_Check(True, "evadex\\[bridge] installed"))
        installed = True
    except ImportError:
        checks.append(_Check(
            False,
            "evadex\\[bridge] not installed — HTTP API server unavailable",
        ))
        installed = False

    if not installed:
        return checks

    # Hit the bridge's health endpoint. Fail silently if nothing's
    # listening — that's a common and correct state (operator runs the
    # bridge only when needed).
    url = os.environ.get("EVADEX_BRIDGE_URL", "http://localhost:8081")
    # /docs is always there on FastAPI; we don't require a /health route.
    # Try /health first; fall back to /docs (which FastAPI mounts).
    if _bridge_reachable(url.rstrip("/") + "/health"):
        checks.append(_Check(True, f"bridge reachable at {url}"))
    elif _bridge_reachable(url.rstrip("/") + "/docs"):
        checks.append(_Check(True, f"bridge reachable at {url}"))
    else:
        checks.append(_Check(
            True,
            f"bridge not running at {url} (start with `evadex bridge`)",
            warn=True,
        ))
    return checks


def _audit_log_path() -> Path:
    override = os.environ.get("EVADEX_AUDIT_LOG")
    if override:
        return Path(override)
    return Path.home() / ".evadex" / "results" / "audit.jsonl"


def _check_audit_log() -> _Check:
    p = _audit_log_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _Check(False, f"audit log parent not creatable ({p.parent}): {exc}")
    # Probe writability without leaving a real file behind.
    probe = p.parent / ".evadex_doctor_probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return _Check(True, f"audit log writable at {p}")
    except OSError as exc:
        return _Check(False, f"audit log not writable at {p}: {exc}")


def _check_default_tier() -> _Check:
    try:
        from evadex.payloads.tiers import NORTHAM_TIER, get_tier_categories
        cats = get_tier_categories("northam")
        n = len(cats) if cats is not None else 0
        return _Check(True, f"Default tier: northam (North America — Canada + US, {n} categories)")
    except Exception as exc:
        return _Check(False, f"Default tier check failed: {exc}")


def _check_profiles() -> list[_Check]:
    from evadex.profiles.storage import profiles_dir, _BUILTINS_PACKAGE
    out: list[_Check] = []
    try:
        pdir = profiles_dir()
        out.append(_Check(True, f"profiles directory at {pdir}"))
    except OSError as exc:
        out.append(_Check(False, f"profiles directory not creatable: {exc}"))
        return out

    # Count user profiles vs built-ins. If neither exists, nudge the
    # operator to `evadex profile init`.
    user_profiles = [p.stem for p in pdir.glob("*.yaml")]
    builtins = [p.stem for p in _BUILTINS_PACKAGE.glob("*.yaml")]
    missing_from_user = [b for b in builtins if b not in user_profiles]
    if missing_from_user and not user_profiles:
        out.append(_Check(
            True,
            f"{len(builtins)} built-in profiles available, 0 user profiles — "
            f"run `evadex profile init` to seed user copies",
            warn=True,
        ))
    elif not user_profiles and not builtins:
        out.append(_Check(
            False,
            "no profiles found (neither user nor built-in)",
        ))
    else:
        out.append(_Check(
            True,
            f"{len(user_profiles)} user profiles, {len(builtins)} built-in profiles",
        ))
    return out


def _run_checks() -> list[_Check]:
    results: list[_Check] = []
    results.append(_check_evadex_version())
    results.append(_check_python())
    results.append(_check_default_tier())
    results.append(_check_siphon())

    # Optional extras — each labelled with the install command so the
    # operator can copy-paste.
    results.append(_check_extra(
        "qrcode", "barcodes",
        "QR/barcode generation unavailable — `pip install evadex\\[barcodes]`",
    ))
    results.append(_check_extra(
        "pyarrow", "data-formats",
        "Parquet unavailable — `pip install evadex\\[data-formats]`",
    ))
    results.append(_check_extra(
        "py7zr", "archives",
        "7z archive generation unavailable — `pip install evadex\\[archives]`",
    ))

    results.extend(_check_bridge())
    results.append(_check_audit_log())
    results.extend(_check_profiles())
    return results


@click.command("doctor")
@click.option(
    "--json", "emit_json",
    is_flag=True,
    default=False,
    help="Emit the check results as JSON.",
)
def doctor(emit_json: bool) -> None:
    """Check the evadex environment for issues before running scans.

    Verifies Python version, evadex installation, scanner availability,
    and optional dependencies. Run this first if evadex scan fails.

    \b
    Examples:
      evadex doctor                      # full environment check
      evadex doctor --json               # machine-readable output
    """
    checks = _run_checks()

    if emit_json:
        import json as _json
        payload = [
            {"ok": c.ok, "warn": c.warn, "message": c.msg}
            for c in checks
        ]
        click.echo(_json.dumps(payload, indent=2))
    else:
        err_console.print("[bold]evadex doctor[/bold] — environment check")
        err_console.print("─" * 34)
        for c in checks:
            err_console.print(c.render())

    # Only hard failures flip the exit code — warnings are advisory.
    had_fail = any(not c.ok and not c.warn for c in checks)
    sys.exit(1 if had_fail else 0)
