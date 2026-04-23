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
import json as _json
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
STATUS_CANCELLED = "cancelled"


# Process-local run registry — ``{run_id: {status, started_at, ...}}``.
_RUNS: dict[str, dict] = {}


# ── Cancellation ───────────────────────────────────────────────
# SIGTERM grace period before SIGKILL. Kept short (bridge is never
# going to wait longer than a few seconds for a clean shutdown).
_CANCEL_GRACE_S = 5.0


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

    # Strategies: repeated --strategy flag. The UI sends either a full
    # list (strategies) or the single-value shorthand (strategy). When
    # the shorthand is "both" we expand to text + file.
    strategies = body.get("strategies")
    if not strategies:
        single = body.get("strategy")
        if single == "both":
            strategies = ["text", "file"]
        elif single:
            strategies = [single]
        else:
            strategies = ["text"]
    for s in strategies:
        argv += ["--strategy", str(s)]

    for c in body.get("categories") or []:
        argv += ["--category", str(c)]

    # Technique-group filter: accept either the single-value
    # ``technique_group`` (legacy / UI radio) or the list form
    # ``technique_groups`` (UI checkbox panel). "all" or an empty list
    # means no filter. Each entry becomes its own --variant-group NAME.
    tg_values: list[str] = []
    tgs = body.get("technique_groups")
    if isinstance(tgs, list):
        tg_values = [str(g) for g in tgs if g and g != "all"]
    else:
        single = body.get("technique_group")
        if single and single != "all":
            tg_values = [str(single)]
    # Dedupe while preserving first-seen order so repeated UI selections
    # don't inflate the argv.
    _seen: set[str] = set()
    for g in tg_values:
        if g in _seen:
            continue
        _seen.add(g)
        argv += ["--variant-group", g]

    # Confidence floor — threaded through to the adapter.
    mc = body.get("min_confidence")
    if mc is not None:
        argv += ["--min-confidence", str(float(mc))]

    # CI-gate threshold: evadex exits non-zero when below this rate.
    mdr = body.get("min_detection_rate")
    if mdr is not None:
        argv += ["--min-detection-rate", str(float(mdr))]

    if body.get("require_context"):
        argv += ["--require-context"]
    # wrap_context is tri-state in the CLI (--wrap-context vs
    # --no-wrap-context). Bridge translates the boolean when set.
    if body.get("wrap_context") is True:
        argv += ["--wrap-context"]
    elif body.get("wrap_context") is False:
        argv += ["--no-wrap-context"]

    save_as = body.get("save_as_profile")
    if save_as:
        argv += ["--save-as", str(save_as)]

    # Always emit structured progress so the bridge can report live
    # progress to the UI without having to parse Rich's TTY output.
    argv += ["--progress-json"]

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
    so clients don't have to know the internal naming. Progress fields
    (``progress`` / ``tested`` / ``total`` / ``detected`` / ``elapsed_s``)
    are passed through as set by ``--progress-json`` ticks.
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
    # Hide internal plumbing (asyncio handle, cancel flag, exception).
    for k in ("_exception", "_proc", "_cancel_requested"):
        view.pop(k, None)
    return view


def list_runs() -> list[dict]:
    return sorted(
        ({"run_id": rid, **rec} for rid, rec in _RUNS.items()),
        key=lambda r: r.get("started_at", ""),
        reverse=True,
    )


async def _drain_stream(stream: asyncio.StreamReader, buf: list[bytes],
                        *, on_line: Optional[callable] = None,
                        max_bytes: int = 4096) -> None:
    """Accumulate tail bytes and fire *on_line* for each complete line.

    Kept tail-only (4 KiB by default) so a chatty subprocess can't
    balloon the bridge's memory. Lines are decoded UTF-8 with replace so
    a malformed byte doesn't abort the reader mid-stream.
    """
    try:
        while True:
            line = await stream.readline()
            if not line:
                return
            buf.append(line)
            if on_line is not None:
                try:
                    text = line.decode("utf-8", "replace").rstrip("\r\n")
                    if text:
                        on_line(text)
                except Exception:
                    pass
            # Trim the head if we've gone past the tail budget.
            total = sum(len(b) for b in buf)
            while total > max_bytes and len(buf) > 1:
                total -= len(buf[0])
                buf.pop(0)
    except (asyncio.CancelledError, ConnectionResetError):
        return


def _on_progress_line(rec: dict, text: str) -> None:
    """Parse ``--progress-json`` lines and fold them into the run record.

    Non-JSON stderr lines (e.g. Rich diagnostic output) are silently
    ignored — the stream is shared with human-readable errors.
    """
    if not (text.startswith("{") and text.endswith("}")):
        return
    try:
        payload = _json.loads(text)
    except ValueError:
        return
    if not isinstance(payload, dict):
        return
    if "progress" not in payload and "tested" not in payload:
        return
    # Only overwrite when the new value is strictly newer — each tick
    # reflects the latest-known completed count.
    rec["progress"] = payload.get("progress")
    rec["tested"] = payload.get("tested")
    rec["total"] = payload.get("total")
    rec["detected"] = payload.get("detected")
    rec["elapsed_s"] = payload.get("elapsed_s")


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
        # Hold the handle so cancel_run can reach the subprocess even
        # while _execute is blocked on wait().
        rec["_proc"] = proc

        stdout_buf: list[bytes] = []
        stderr_buf: list[bytes] = []
        stdout_task = asyncio.create_task(
            _drain_stream(proc.stdout, stdout_buf)
        )
        stderr_task = asyncio.create_task(
            _drain_stream(
                proc.stderr, stderr_buf,
                on_line=lambda t, r=rec: _on_progress_line(r, t),
            )
        )
        try:
            returncode = await proc.wait()
        finally:
            # Make sure the drain tasks finish (proc may have exited
            # but buffered bytes could still be in the pipe).
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        rec["exit_code"] = returncode
        rec["stdout_tail"] = b"".join(stdout_buf).decode("utf-8", "replace")[-4096:]
        rec["stderr_tail"] = b"".join(stderr_buf).decode("utf-8", "replace")[-4096:]
        if rec.get("_cancel_requested"):
            rec["status"] = STATUS_CANCELLED
        else:
            rec["status"] = STATUS_COMPLETED if returncode == 0 else STATUS_FAILED
        # Backfill progress=100 on a clean completion so the UI's
        # progress bar lands at 100% even if the final --progress-json
        # tick was missed (e.g. output buffering on Windows).
        if rec["status"] == STATUS_COMPLETED:
            rec["progress"] = 100.0
        if rec["status"] == STATUS_FAILED:
            log.warning(
                "[bridge/run %s] exit=%s stderr=%r",
                run_id, returncode,
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
        rec.pop("_proc", None)


async def cancel_run(run_id: str) -> dict:
    """Terminate the subprocess for *run_id* — SIGTERM then SIGKILL.

    Returns the run record in its post-cancel state so the HTTP handler
    can shape the response. The kill path is tolerant of the process
    already having exited (race with natural completion).
    """
    rec = _RUNS.get(run_id)
    if rec is None:
        return {"run_id": run_id, "status": "unknown"}
    if rec.get("status") not in (STATUS_QUEUED, STATUS_RUNNING):
        return {"run_id": run_id, **rec}
    rec["_cancel_requested"] = True
    proc = rec.get("_proc")
    if proc is None:
        # Launched but subprocess not yet attached — mark cancelled so
        # _execute sees the flag when it finally reaches the check.
        rec["status"] = STATUS_CANCELLED
        rec["finished_at"] = _now()
        return {"run_id": run_id, **rec}
    try:
        proc.terminate()
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=_CANCEL_GRACE_S)
    except asyncio.TimeoutError:
        log.warning("[bridge/run %s] SIGTERM grace expired — killing", run_id)
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.wait()
        except Exception:
            pass
    except ProcessLookupError:
        pass
    # _execute's finally: block sets status=cancelled + finished_at.
    # Wait briefly for it to settle so the HTTP response reflects final
    # state rather than a transient "running" + cancelled flag.
    for _ in range(20):  # up to ~1 s
        if rec.get("status") == STATUS_CANCELLED or rec.get("finished_at"):
            break
        await asyncio.sleep(0.05)
    return {"run_id": run_id, **rec}


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
        # Progress fields populated by --progress-json stderr ticks.
        "progress":     0.0,
        "tested":       0,
        "total":        0,
        "detected":     0,
        "elapsed_s":    0.0,
    }
    _RUNS[run_id] = record
    asyncio.create_task(_execute(run_id, argv, cwd))
    return {"run_id": run_id, **record}


def reset() -> None:
    """Drop all tracked runs. Intended for tests."""
    _RUNS.clear()
