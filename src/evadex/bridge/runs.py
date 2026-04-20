"""Launch evadex scans from the bridge and track their status in-process.

The bridge is designed to run alongside the evadex CLI on the same host —
we shell out to ``evadex scan`` rather than importing and executing scan
logic directly. This keeps the bridge thin and lets the CLI keep owning
the audit log, archive writes, and exit-code semantics.

State is held in a single process-local dict. Restarting the bridge
forgets queued/running state but the audit log (which is what
:mod:`evadex.bridge.metrics` reads) is unaffected.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional


# Use the uvicorn error logger so argv + run-failure lines show up in
# the bridge's terminal alongside request logs.
log = logging.getLogger("uvicorn.error")


# Run status values the C2 frontend understands.
STATUS_QUEUED    = "queued"
STATUS_RUNNING   = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED    = "failed"


# Process-local run registry — ``{run_id: {status, started_at, ...}}``.
_RUNS: dict[str, dict] = {}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _allocate_run_id() -> str:
    """Compact timestamp-based id — unique within a single bridge process."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"R-{ts}"


def _build_scan_argv(body: dict) -> list[str]:
    """Translate a C2 run-request body into an ``evadex scan`` argv.

    Only the fields documented in the C2 contract are honoured; anything
    else in *body* is ignored rather than rejected so the frontend can
    evolve independently.

    Server-level defaults are read from environment variables set by the
    ``evadex bridge`` CLI (``EVADEX_BRIDGE_EXE``, ``EVADEX_BRIDGE_CMD_STYLE``).
    Per-request ``exe`` / ``cmd_style`` in *body* override the default.
    """
    argv = [sys.executable, "-m", "evadex", "scan"]

    tool = body.get("tool") or "siphon-cli"
    argv += ["--tool", str(tool)]

    # exe: request body wins, then CLI-provided env default.
    exe = body.get("exe") or os.environ.get("EVADEX_BRIDGE_EXE")
    if exe:
        argv += ["--exe", str(exe)]

    # cmd-style: same precedence.
    cmd_style = body.get("cmd_style") or os.environ.get("EVADEX_BRIDGE_CMD_STYLE")
    if cmd_style:
        argv += ["--cmd-style", str(cmd_style)]

    scanner_label = body.get("scanner_label")
    if scanner_label:
        argv += ["--scanner-label", str(scanner_label)]

    tier = body.get("tier")
    if tier:
        argv += ["--tier", str(tier)]

    evasion_mode = body.get("evasion_mode")
    if evasion_mode:
        argv += ["--evasion-mode", str(evasion_mode)]

    # Strategies default to "text" so the CLI doesn't need input files.
    for s in body.get("strategies") or ["text"]:
        argv += ["--strategy", str(s)]

    for c in body.get("categories") or []:
        argv += ["--category", str(c)]

    return argv


def _summarise_error(rec: dict) -> Optional[str]:
    """Return a short one-line error string for a failed run, or None.

    Pulls the last non-empty stderr line when available, falls back to
    any Python-side exception captured in ``rec['error']`` or to a
    generic "exit N" string. Used by :func:`get_run` so every failed run
    carries a top-level ``error`` key the UI can surface directly.
    """
    if rec.get("status") != STATUS_FAILED:
        return None
    # Prefer an explicit exception string set by ``_execute``.
    py_exc = rec.get("_exception")
    if py_exc:
        return py_exc
    stderr = rec.get("stderr_tail") or ""
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    if lines:
        # Return up to the last two non-empty lines joined by " · " so
        # the UI shows both the diagnosis and any hint the CLI printed.
        return " · ".join(lines[-2:])
    code = rec.get("exit_code")
    return f"evadex exited with code {code}" if code is not None else "scan failed"


def get_run(run_id: str) -> Optional[dict]:
    """Return the run record with frontend-friendly aliases.

    Adds ``error`` (set only for failed runs), plus ``stdout`` and
    ``stderr`` aliases that point at ``stdout_tail`` / ``stderr_tail``
    so clients don't have to know the internal naming.
    """
    rec = _RUNS.get(run_id)
    if rec is None:
        return None
    view = dict(rec)
    view["stdout"] = rec.get("stdout_tail", "")
    view["stderr"] = rec.get("stderr_tail", "")
    err = _summarise_error(rec)
    if err:
        view["error"] = err
    # Hide the internal exception field from clients.
    view.pop("_exception", None)
    return view


def list_runs() -> list[dict]:
    return sorted(
        ({"run_id": rid, **rec} for rid, rec in _RUNS.items()),
        key=lambda r: r.get("started_at", ""),
        reverse=True,
    )


async def _execute(run_id: str, argv: list[str], cwd: Optional[str]) -> None:
    rec = _RUNS[run_id]
    rec["status"] = STATUS_RUNNING
    log.info("[bridge/run %s] exec: %s (cwd=%s)", run_id, " ".join(argv), cwd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        stdout, stderr = await proc.communicate()
        rec["exit_code"] = proc.returncode
        rec["stdout_tail"] = (stdout or b"").decode("utf-8", "replace")[-4096:]
        rec["stderr_tail"] = (stderr or b"").decode("utf-8", "replace")[-4096:]
        rec["status"] = STATUS_COMPLETED if proc.returncode == 0 else STATUS_FAILED
        if rec["status"] == STATUS_FAILED:
            log.warning(
                "[bridge/run %s] exit=%s stderr=%r",
                run_id, proc.returncode,
                rec["stderr_tail"].strip().splitlines()[-1:] or "",
            )
    except Exception as exc:
        rec["status"] = STATUS_FAILED
        # Stash under a private key so get_run() can promote it into the
        # public "error" field without leaking the repr() twice.
        rec["_exception"] = repr(exc)
        log.exception("[bridge/run %s] launch failed", run_id)
    finally:
        rec["finished_at"] = _now()


def launch(body: dict, cwd: Optional[str] = None) -> dict:
    """Queue an ``evadex scan`` run based on *body* and return its record.

    The subprocess is spawned via :func:`asyncio.create_task` — callers
    must be running inside an event loop (FastAPI handlers are).
    """
    run_id = _allocate_run_id()
    argv = _build_scan_argv(body)
    record = {
        "status":       STATUS_QUEUED,
        "started_at":   _now(),
        "finished_at":  None,
        "argv":         argv,
        "request":      body,
        "exit_code":    None,
        "stdout_tail":  "",
        "stderr_tail":  "",
    }
    _RUNS[run_id] = record
    asyncio.create_task(_execute(run_id, argv, cwd))
    return {"run_id": run_id, **record}


def reset() -> None:
    """Drop all tracked runs. Intended for tests."""
    _RUNS.clear()
