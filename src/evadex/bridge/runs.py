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
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional


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
    """
    argv = [sys.executable, "-m", "evadex", "scan"]

    tool = body.get("tool") or "siphon-cli"
    argv += ["--tool", str(tool)]

    exe = body.get("exe")
    if exe:
        argv += ["--exe", str(exe)]

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


def get_run(run_id: str) -> Optional[dict]:
    return _RUNS.get(run_id)


def list_runs() -> list[dict]:
    return sorted(
        ({"run_id": rid, **rec} for rid, rec in _RUNS.items()),
        key=lambda r: r.get("started_at", ""),
        reverse=True,
    )


async def _execute(run_id: str, argv: list[str], cwd: Optional[str]) -> None:
    rec = _RUNS[run_id]
    rec["status"] = STATUS_RUNNING
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
    except Exception as exc:
        rec["status"] = STATUS_FAILED
        rec["error"] = repr(exc)
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
