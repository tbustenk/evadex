"""FastAPI bridge server — drives evadex from siphon-c2 and other frontends.

Endpoints
---------
POST /v1/evadex/run
    Trigger an evadex scan in the background. Returns a run_id immediately.
GET  /v1/evadex/metrics
    Aggregate detection / FP / coverage + per-category + top evasions +
    last-10 history from the audit log.
POST /v1/evadex/generate
    Produce a synthetic test artefact and stream it back as a download.

Auth
----
If the ``EVADEX_BRIDGE_KEY`` env var is set at startup, all endpoints
require an ``x-api-key`` request header that matches it. Otherwise the
bridge runs open — intended for trusted local networks only.

CORS
----
Open by default so a file:// or localhost-served siphon-c2 page can call
the bridge. Restrict via ``EVADEX_BRIDGE_CORS_ORIGINS`` (comma list).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

try:
    from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
except ImportError as exc:  # pragma: no cover — handled by CLI command
    raise ImportError(
        "evadex bridge requires FastAPI. Install with: pip install evadex[bridge]"
    ) from exc

from evadex.bridge import categories as cat
from evadex.bridge import metrics as metrics_mod
from evadex.bridge import runs as runs_mod


# Version string surfaced in the OpenAPI doc + /healthz payload.
try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        _BRIDGE_VERSION = version("evadex")
    except PackageNotFoundError:
        _BRIDGE_VERSION = "unknown"
except ImportError:  # pragma: no cover
    _BRIDGE_VERSION = "unknown"


# ── Auth dependency ─────────────────────────────────────────────
def _require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Dependency that enforces ``x-api-key`` when configured."""
    expected = os.environ.get("EVADEX_BRIDGE_KEY")
    if not expected:
        return
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="invalid or missing x-api-key")


def _cors_origins() -> list[str]:
    raw = os.environ.get("EVADEX_BRIDGE_CORS_ORIGINS", "*")
    if raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


def _repo_root() -> Path:
    """Resolve the directory evadex scans against. Defaults to CWD."""
    return Path(os.environ.get("EVADEX_BRIDGE_ROOT") or Path.cwd())


# Paths checked (in order) when no explicit siphon exe is configured.
_SIPHON_AUTO_DISCOVERY_PATHS: tuple[str, ...] = (
    "/usr/local/bin/siphon",
    "/usr/bin/siphon",
    "./target/release/siphon",
    "./target/release/siphon.exe",
    "C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe",
)


def _config_bridge_exe() -> Optional[str]:
    """Read ``bridge.exe`` from ./evadex.yaml relative to _repo_root(), if any.

    Returns None when the file is missing, can't be parsed, has no
    ``bridge`` section, or the exe field is null. Silent on any error so
    a broken config never crashes the server — the caller falls through
    to auto-discovery.
    """
    try:
        import yaml
    except ImportError:
        return None
    candidate = _repo_root() / "evadex.yaml"
    if not candidate.is_file():
        return None
    try:
        with open(candidate, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception:
        return None
    bridge = raw.get("bridge") if isinstance(raw, dict) else None
    if not isinstance(bridge, dict):
        return None
    exe = bridge.get("exe")
    return str(exe) if isinstance(exe, str) and exe else None


def _resolve_siphon_exe() -> Optional[str]:
    """Resolve the siphon binary path using the documented priority chain.

    1. ``EVADEX_BRIDGE_EXE`` env var — set by the ``evadex bridge --exe`` CLI flag.
    2. ``SIPHON_EXE`` env var — direct override.
    3. ``bridge.exe`` key in ``evadex.yaml`` (relative to the scan root).
    4. Known install paths — see :data:`_SIPHON_AUTO_DISCOVERY_PATHS`.
    5. ``shutil.which('siphon')`` — PATH lookup.

    Returns the absolute path string or None when nothing is found.
    """
    # 1. CLI --exe flag (plumbed into env by evadex.cli.commands.bridge).
    cli_exe = os.environ.get("EVADEX_BRIDGE_EXE")
    if cli_exe:
        return cli_exe

    # 2. SIPHON_EXE env var — intentionally separate from EVADEX_BRIDGE_EXE
    # so users can point at siphon without knowing the bridge's internal
    # env name.
    env_exe = os.environ.get("SIPHON_EXE")
    if env_exe:
        return env_exe

    # 3. evadex.yaml → bridge.exe.
    cfg_exe = _config_bridge_exe()
    if cfg_exe:
        return cfg_exe

    # 4. Known install paths.
    for p in _SIPHON_AUTO_DISCOVERY_PATHS:
        candidate = Path(p)
        if candidate.is_file():
            return str(candidate.resolve())

    # 5. PATH lookup.
    which = shutil.which("siphon")
    if which:
        return which

    return None


def create_app() -> FastAPI:
    """Build the FastAPI app. Kept as a factory so tests can isolate state."""
    app = FastAPI(
        title="evadex bridge",
        version=_BRIDGE_VERSION,
        description=(
            "HTTP bridge that exposes evadex to siphon-c2 and other "
            "frontends. Endpoints: /v1/evadex/run, /v1/evadex/metrics, "
            "/v1/evadex/generate."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )

    # ── Health / version — unauthenticated, useful for uptime probes. ──
    @app.get("/healthz")
    def healthz() -> dict:
        exe = _resolve_siphon_exe()
        return {
            "ok":           True,
            "version":      _BRIDGE_VERSION,
            "siphon_exe":   exe,
            "siphon_found": exe is not None,
        }

    # ── POST /v1/evadex/run ─────────────────────────────────────
    @app.post("/v1/evadex/run", dependencies=[Depends(_require_api_key)])
    async def run_scan(body: dict) -> JSONResponse:
        """Queue an evadex scan in the background. Returns immediately.

        Accepted body keys (all optional, defaults applied per-field):
            profile, tier, evasion_mode, tool, exe, scanner_label,
            categories (list of C2 buckets or evadex fine cats), strategies.
        """
        # Resolve the scanner path if the request didn't override it. If
        # nothing is found anywhere in the priority chain, fail fast with
        # a clear error instead of letting the subprocess blow up.
        if not body.get("exe"):
            resolved_exe = _resolve_siphon_exe()
            if resolved_exe is None:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "siphon binary not found",
                        "hint": (
                            "Set SIPHON_EXE, pass --exe on `evadex bridge`, "
                            "add bridge.exe to evadex.yaml, or install siphon "
                            "to a standard location (/usr/local/bin/siphon, "
                            "./target/release/siphon)."
                        ),
                        "searched": list(_SIPHON_AUTO_DISCOVERY_PATHS),
                    },
                )
            body = {**body, "exe": resolved_exe}

        # Translate C2 coarse buckets into fine evadex categories if the
        # frontend passed any. Anything that isn't a known bucket falls
        # through as-is so evadex's own validation catches typos.
        cats = body.get("categories") or []
        known_buckets = set(cat.all_buckets())
        expanded: list[str] = []
        for c in cats:
            if c.upper() in known_buckets:
                expanded.extend(cat.expand(c))
            else:
                expanded.append(c)
        launch_body = {**body, "categories": expanded}

        record = runs_mod.launch(launch_body, cwd=str(_repo_root()))
        return JSONResponse(
            status_code=202,
            content={
                "run_id":     record["run_id"],
                "status":     record["status"],
                "started_at": record["started_at"],
            },
        )

    @app.get("/v1/evadex/run/{run_id}", dependencies=[Depends(_require_api_key)])
    def run_status(run_id: str) -> dict:
        rec = runs_mod.get_run(run_id)
        if rec is None:
            raise HTTPException(status_code=404, detail=f"unknown run_id {run_id!r}")
        return {"run_id": run_id, **rec}

    # ── GET /v1/evadex/metrics ──────────────────────────────────
    @app.get("/v1/evadex/metrics", dependencies=[Depends(_require_api_key)])
    def get_metrics(
        audit_log: Optional[str] = None,
    ) -> dict:
        path = audit_log or os.environ.get(
            "EVADEX_BRIDGE_AUDIT_LOG", metrics_mod.DEFAULT_AUDIT_LOG,
        )
        data = metrics_mod.build_metrics(repo_root=_repo_root(), audit_log=path)
        # Surface scanner-binary status so the UI can show "siphon not
        # found" alongside an empty metrics payload instead of looking
        # like a silent outage. Historical metrics still render — just
        # warn that future runs will fail until the exe is wired up.
        exe = _resolve_siphon_exe()
        data["siphon_exe"] = exe
        data["siphon_found"] = exe is not None
        if exe is None:
            data["warning"] = (
                "siphon binary not found — /v1/evadex/run will fail until "
                "SIPHON_EXE, --exe, bridge.exe, or PATH is configured"
            )
        return data

    # ── POST /v1/evadex/generate ────────────────────────────────
    @app.post("/v1/evadex/generate", dependencies=[Depends(_require_api_key)])
    def generate_file(body: dict) -> FileResponse:
        """Generate a synthetic test file and return it as a download.

        Body keys:
            format      (str)   xlsx | docx | pdf | csv | json | eml | ...
            tier        (str)   banking | core | regional | full
            category    (str)   C2 bucket (PCI/PII/…) or evadex fine cat
            count       (int)   records to emit (default 100, capped 10_000)
            evasion_rate(float) 0–1 or 0–100 — auto-normalised
            language    (str)   en | fr-CA
            template    (str)   evadex template name
        """
        fmt = (body.get("format") or "csv").lower()
        tier = body.get("tier")
        category = body.get("category")
        count = int(body.get("count") or 100)
        count = max(1, min(count, 10_000))
        evasion_rate = body.get("evasion_rate")
        if evasion_rate is None:
            evasion_rate = 0.3
        else:
            evasion_rate = float(evasion_rate)
            if evasion_rate > 1.0:
                # C2 slider sends 0–100.
                evasion_rate = evasion_rate / 100.0
            evasion_rate = max(0.0, min(evasion_rate, 1.0))
        language = body.get("language") or "en"
        template = body.get("template") or "generic"

        # Translate C2 coarse bucket → evadex fine categories.
        evadex_cats: list[str] = []
        if category:
            if category.upper() in set(cat.all_buckets()):
                evadex_cats = cat.expand(category)
            else:
                evadex_cats = [category]

        # Resolve output path — temp file that FastAPI streams back. The
        # caller cleans up via the FileResponse background task below.
        ext_map = {
            "sqlite": "db", "multi_barcode_png": "png", "zip_nested": "zip",
        }
        ext = ext_map.get(fmt, fmt)
        tmp = tempfile.NamedTemporaryFile(
            prefix="evadex-bridge-", suffix=f".{ext}", delete=False,
        )
        tmp.close()
        out_path = Path(tmp.name)

        argv: list[str] = [
            sys.executable, "-m", "evadex", "generate",
            "--format", fmt,
            "--count", str(count),
            "--evasion-rate", f"{evasion_rate:.3f}",
            "--language", language,
            "--template", template,
            "--output", str(out_path),
        ]
        if tier and not evadex_cats:
            argv += ["--tier", tier]
        for c in evadex_cats:
            argv += ["--category", c]

        proc = subprocess.run(
            argv,
            cwd=str(_repo_root()),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0 or not out_path.is_file():
            detail = {
                "error": "evadex generate failed",
                "exit_code": proc.returncode,
                "stderr": (proc.stderr or "")[-2048:],
                "argv": argv[2:],  # hide the python exe
            }
            raise HTTPException(status_code=500, detail=detail)

        # Use a background task so the file is removed after FastAPI
        # finishes streaming it to the client.
        from starlette.background import BackgroundTask

        cleanup = BackgroundTask(_unlink_quietly, out_path)
        filename = f"evadex-{category or tier or 'sample'}-{count}.{ext}"
        return FileResponse(
            path=str(out_path),
            filename=filename,
            media_type="application/octet-stream",
            background=cleanup,
        )

    return app


def _unlink_quietly(path: Path) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except Exception:
        pass


# Module-level app instance so ``uvicorn evadex.bridge.server:app`` works.
app = create_app()
