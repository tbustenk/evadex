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
from typing import Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
except ImportError as exc:  # pragma: no cover — handled by CLI command
    raise ImportError(
        "evadex bridge requires FastAPI. Install with: pip install evadex[bridge]"
    ) from exc

from evadex.bridge import categories as cat
from evadex.bridge import metrics as metrics_mod
from evadex.bridge import runs as runs_mod


# ── Input allowlists ────────────────────────────────────────────
# Keep these small and explicit — every value here ends up as a
# subprocess argv. Anything outside the allowlist is rejected with
# 400 before the subprocess ever launches.
_ALLOWED_FORMATS = {
    "csv", "json", "xlsx", "docx", "pdf", "eml", "txt", "html",
    "xml", "yaml", "yml", "sqlite", "parquet", "zip", "zip_nested",
    "7z", "tar", "png", "jpg", "multi_barcode_png", "mbox", "ics", "warc",
}
_ALLOWED_LANGUAGES = {"en", "fr-CA"}
_ALLOWED_TIERS = {"banking", "core", "regional", "full"}
_ALLOWED_EVASION_MODES = {"random", "exhaustive", "weighted", "adversarial"}
_ALLOWED_TOOLS = {"dlpscan-cli", "siphon-cli", "siphon", "dlpscan", "presidio"}
_ALLOWED_CMD_STYLES = {"python", "rust", "binary", "cargo", "stdin"}
_ALLOWED_STRATEGIES = {"text", "file", "both", "docx", "pdf", "xlsx", "csv", "json"}

# Request-body size cap. The bridge only ever receives small JSON
# (≤ ~4 KiB for even the largest run body). Cap well above that so
# operators don't hit it during normal use, but low enough that an
# accidental / malicious gigabyte POST is refused up front instead of
# being parsed into memory.
_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB

# Scanner-label constraints: the label ends up in argv, audit entries,
# and (after sanitisation) archive filenames. Bound length + disallow
# control characters so a label can't bloat logs or smuggle terminal
# escape sequences into operator sessions.
_SCANNER_LABEL_MAX_LEN = 100

# Per-category string constraints for both run/categories[] entries
# and generate.category. Matches evadex's own allowed character set —
# anything outside is a typo or a hostile payload.
_CATEGORY_NAME_MAX_LEN = 64
_SAFE_CATEGORY_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
# Technique groups — mirror evadex.variants.* @register_generator names.
# "all" is a UI convenience that maps to "no filter" (pass nothing).
_ALLOWED_TECHNIQUE_GROUPS = {
    "all",
    "unicode_encoding", "unicode_whitespace", "delimiter", "splitting",
    "encoding", "encoding_chains", "leetspeak", "regional_digits",
    "structural", "morse_code", "soft_hyphen", "bidirectional",
    "archive_evasion", "barcode_evasion", "context_injection",
    "entropy_evasion",
}
# Profile names follow the same opaque-identifier rule as templates:
# filesystem-safe alphanumerics only. Rejecting paths keeps the save
# location inside ~/.evadex/profiles.
_SAFE_PROFILE_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
)
# Template names are opaque strings but must not be paths. Reject
# anything that could escape the templates dir or address the
# filesystem directly.
_SAFE_TEMPLATE_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."
)


def _bad_request(msg: str, **extra: object) -> HTTPException:
    return HTTPException(status_code=400, detail={"error": msg, **extra})


def _validate_template(name: str) -> str:
    """Reject path-traversal or filesystem-pointing template names.

    The CLI treats ``--template`` as an opaque identifier; the bridge is
    the trust boundary, so we enforce that identity here rather than
    hoping every downstream loader refuses ``../etc/passwd``.
    """
    if not isinstance(name, str) or not name:
        raise _bad_request("template must be a non-empty string")
    if any(ch not in _SAFE_TEMPLATE_CHARS for ch in name):
        raise _bad_request(
            "template contains disallowed characters",
            template=name,
            allowed="alphanumerics, '_', '-', '.'",
        )
    if name.startswith(".") or ".." in name:
        raise _bad_request("template must not contain '..' or start with '.'",
                           template=name)
    return name


def _validate_scanner_label(label: str) -> str:
    """Reject oversized or non-printable labels before they flow to argv.

    Labels end up in argv, audit rows, and — after sanitisation —
    archive filenames. Keeping them short and printable prevents log
    bloat and terminal-escape injection if operators ``tail -f`` the
    bridge's stderr.
    """
    if not isinstance(label, str):
        raise _bad_request("scanner_label must be a string or null")
    if len(label) > _SCANNER_LABEL_MAX_LEN:
        raise _bad_request(
            "scanner_label too long",
            scanner_label_len=len(label),
            max_len=_SCANNER_LABEL_MAX_LEN,
        )
    # Disallow every C0/C1 control char (including \x00, \r, \n, \x1b).
    if any((ord(ch) < 0x20 or ord(ch) == 0x7f) for ch in label):
        raise _bad_request(
            "scanner_label contains control characters",
        )
    return label


def _validate_category_item(item: object, *, field: str) -> str:
    """Validate a single category id (from ``categories[]`` or
    ``generate.category``). C2 coarse buckets (PCI, PII, …) are
    upper-cased and pass the allowlist; everything else must look like
    a snake-case evadex id. Path-like values are rejected outright —
    category ids never contain ``..`` or path separators.
    """
    if not isinstance(item, str) or not item:
        raise _bad_request(f"{field} entries must be non-empty strings",
                           entry=item)
    if len(item) > _CATEGORY_NAME_MAX_LEN:
        raise _bad_request(f"{field} entry too long",
                           entry=item, max_len=_CATEGORY_NAME_MAX_LEN)
    if any(ch not in _SAFE_CATEGORY_CHARS for ch in item):
        raise _bad_request(
            f"{field} contains disallowed characters",
            entry=item,
            allowed="alphanumerics, '_', '-'",
        )
    return item


def _validate_profile_name(name: str) -> str:
    """Reject path-traversal and filesystem-pointing profile names.

    Same trust-boundary rules as :func:`_validate_template` — the
    ``--save-as`` flag writes into ``~/.evadex/profiles`` so a value
    containing ``..`` or path separators could escape that directory.
    """
    if not isinstance(name, str) or not name:
        raise _bad_request("save_as_profile must be a non-empty string")
    if any(ch not in _SAFE_PROFILE_CHARS for ch in name):
        raise _bad_request(
            "save_as_profile contains disallowed characters",
            save_as_profile=name,
            allowed="alphanumerics, '_', '-', '.'",
        )
    if name.startswith(".") or ".." in name:
        raise _bad_request(
            "save_as_profile must not contain '..' or start with '.'",
            save_as_profile=name,
        )
    return name


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


def _sibling_dlpscan_rs_paths() -> tuple[str, ...]:
    """Siblng-repo candidates (``../dlpscan-rs/target/release/siphon[.exe]``).

    Computed from the evadex package location so developers with the
    standard ``<workspace>/evadex`` + ``<workspace>/dlpscan-rs`` layout get
    auto-discovery without a hard-coded user-specific path. Returns empty
    when the package is installed from a wheel far from any source tree.
    """
    evadex_pkg = Path(__file__).resolve()
    try:
        workspace = evadex_pkg.parents[4]  # src/evadex/bridge/server.py -> repo's parent
    except IndexError:
        return ()
    release_dir = workspace / "dlpscan-rs" / "target" / "release"
    return (str(release_dir / "siphon"), str(release_dir / "siphon.exe"))


# Paths checked (in order) when no explicit siphon exe is configured.
# Relative paths are resolved against the current working directory.
# Sibling-repo paths are computed at import time so the list remains
# portable across developer machines (no hard-coded user home directories).
_SIPHON_AUTO_DISCOVERY_PATHS: tuple[str, ...] = (
    "/usr/local/bin/siphon",
    "/usr/bin/siphon",
    "./target/release/siphon",
    "./target/release/siphon.exe",
) + _sibling_dlpscan_rs_paths()


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

    # Reject oversized request bodies before Starlette buffers them.
    # Every bridge endpoint only ever receives small JSON or empty
    # bodies, so a 1 MiB cap is well above normal use. Using the
    # Content-Length header rather than streaming-read lets us refuse
    # with 413 before any memory is spent on the body.
    @app.middleware("http")
    async def _limit_body_size(request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": {
                            "error":   "request body too large",
                            "limit":   _MAX_BODY_BYTES,
                            "got":     int(cl),
                        }},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": {"error": "invalid content-length"}},
                )
        return await call_next(request)

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
            categories (list of C2 buckets or evadex fine cats), strategies,
            strategy (single — shorthand; expanded to strategies),
            evasion_rate, technique_group, min_confidence,
            require_context, wrap_context, min_detection_rate,
            save_as_profile.
        """
        if not isinstance(body, dict):
            raise _bad_request("request body must be a JSON object")

        # Validate every enum-shaped field before it flows into argv. The
        # subprocess uses argv-list form (no shell), so these checks are
        # defence-in-depth against downstream evadex flag abuse rather
        # than against shell injection.
        for field, allowed in (
            ("tier",            _ALLOWED_TIERS),
            ("evasion_mode",    _ALLOWED_EVASION_MODES),
            ("tool",            _ALLOWED_TOOLS),
            ("cmd_style",       _ALLOWED_CMD_STYLES),
            ("technique_group", _ALLOWED_TECHNIQUE_GROUPS),
        ):
            val = body.get(field)
            if val is not None and val not in allowed:
                raise _bad_request(
                    f"unsupported {field}",
                    **{field: val}, allowed=sorted(allowed),
                )
        # technique_groups: multi-select variant of technique_group.
        # Each entry validated against the same allowlist.
        tgs = body.get("technique_groups")
        if tgs is not None:
            if not isinstance(tgs, list):
                raise _bad_request("technique_groups must be a list or null")
            for g in tgs:
                if not isinstance(g, str) or g not in _ALLOWED_TECHNIQUE_GROUPS:
                    raise _bad_request(
                        "unsupported technique_groups entry",
                        entry=g, allowed=sorted(_ALLOWED_TECHNIQUE_GROUPS),
                    )
        # strategy: single-value shorthand from the UI ("text" / "file" /
        # "both"). Expanded to the CLI's repeated --strategy flag below.
        strat = body.get("strategy")
        if strat is not None:
            if not isinstance(strat, str) or strat not in _ALLOWED_STRATEGIES:
                raise _bad_request(
                    "unsupported strategy",
                    strategy=strat,
                    allowed=sorted(_ALLOWED_STRATEGIES),
                )
        if body.get("exe") is not None and not isinstance(body["exe"], str):
            raise _bad_request("exe must be a string or null")
        if body.get("scanner_label") is not None:
            body = {**body, "scanner_label":
                    _validate_scanner_label(body["scanner_label"])}
        if body.get("categories") is not None:
            if not isinstance(body["categories"], list):
                raise _bad_request("categories must be a list or null")
            for c in body["categories"]:
                # C2 coarse buckets (uppercase) are still accepted —
                # they match the same allowlist when lower-cased.
                _validate_category_item(c, field="categories")
        if body.get("strategies") is not None:
            if not isinstance(body["strategies"], list):
                raise _bad_request("strategies must be a list or null")
            for s in body["strategies"]:
                if not isinstance(s, str) or s not in _ALLOWED_STRATEGIES:
                    raise _bad_request(
                        "unsupported strategies entry",
                        entry=s, allowed=sorted(_ALLOWED_STRATEGIES),
                    )

        # Numeric validation: bounded 0–1 ratios and an optional % gate.
        for field, lo, hi in (
            ("min_confidence",     0.0, 1.0),
            ("evasion_rate",       0.0, 100.0),  # accepts 0–1 or 0–100
            ("min_detection_rate", 0.0, 100.0),
        ):
            val = body.get(field)
            if val is None:
                continue
            try:
                num = float(val)
            except (TypeError, ValueError):
                raise _bad_request(f"{field} must be numeric", **{field: val})
            if field == "evasion_rate" and num > 1.0:
                # UI slider sends 0–100; the normalized value stays bounded.
                num = num / 100.0
                hi = 1.0
            if not (lo <= num <= hi):
                raise _bad_request(
                    f"{field} must be in [{lo}, {hi}]",
                    **{field: val},
                )
            body = {**body, field: num}

        for field in ("require_context", "wrap_context"):
            val = body.get(field)
            if val is not None and not isinstance(val, bool):
                raise _bad_request(f"{field} must be boolean or null")

        save_as = body.get("save_as_profile")
        if save_as is not None:
            body = {**body, "save_as_profile": _validate_profile_name(save_as)}

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

    # ── DELETE /v1/evadex/run/{run_id} ──────────────────────────
    # Cancel a running scan. SIGTERM first, SIGKILL after the grace
    # period expires. Idempotent — repeat calls on a terminal run just
    # return the current record without re-signalling.
    @app.delete("/v1/evadex/run/{run_id}", dependencies=[Depends(_require_api_key)])
    async def cancel(run_id: str) -> dict:
        if runs_mod.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail=f"unknown run_id {run_id!r}")
        result = await runs_mod.cancel_run(run_id)
        # Strip private fields the way get_run() does — cancel_run
        # returns the raw record which still has _proc etc.
        view = runs_mod.get_run(run_id) or {}
        # Preserve the "status" cancel_run computed even if the view
        # was captured mid-transition.
        if result.get("status") and result["status"] != "unknown":
            view["status"] = result["status"]
        return {"run_id": run_id, **view}

    # ── GET /v1/evadex/categories ───────────────────────────────
    # Catalog of every registered payload category, grouped for the
    # checkbox panel. Read at UI mount so new categories added to
    # evadex appear automatically. Safe to serve unauthenticated would
    # be fine too, but we keep it behind the same gate as the rest of
    # the bridge so a single key protects the whole surface.
    @app.get("/v1/evadex/categories", dependencies=[Depends(_require_api_key)])
    def list_categories() -> dict:
        return cat.group_all_categories()

    # ── GET /v1/evadex/metrics ──────────────────────────────────
    @app.get("/v1/evadex/metrics", dependencies=[Depends(_require_api_key)])
    def get_metrics() -> dict:
        # Hardcode the audit-log path to the default (or the operator's
        # server-wide override via env). Accepting the path from the
        # caller opened a file-read primitive — any authenticated client
        # could point us at /etc/passwd and let the parser try it.
        path = os.environ.get(
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
        if not isinstance(body, dict):
            raise _bad_request("request body must be a JSON object")

        fmt = (body.get("format") or "csv")
        if not isinstance(fmt, str):
            raise _bad_request("format must be a string", format=fmt)
        fmt = fmt.lower()
        if fmt not in _ALLOWED_FORMATS:
            raise _bad_request(
                "unsupported format", format=fmt,
                allowed=sorted(_ALLOWED_FORMATS),
            )

        tier = body.get("tier")
        if tier is not None and tier not in _ALLOWED_TIERS:
            raise _bad_request(
                "unsupported tier", tier=tier, allowed=sorted(_ALLOWED_TIERS),
            )

        category = body.get("category")
        if category is not None:
            _validate_category_item(category, field="category")

        try:
            count = int(body.get("count") or 100)
        except (TypeError, ValueError):
            raise _bad_request("count must be an integer", count=body.get("count"))
        count = max(1, min(count, 10_000))

        evasion_rate = body.get("evasion_rate")
        if evasion_rate is None:
            evasion_rate = 0.3
        else:
            try:
                evasion_rate = float(evasion_rate)
            except (TypeError, ValueError):
                raise _bad_request(
                    "evasion_rate must be numeric", evasion_rate=evasion_rate,
                )
            if evasion_rate > 1.0:
                # C2 slider sends 0–100.
                evasion_rate = evasion_rate / 100.0
            evasion_rate = max(0.0, min(evasion_rate, 1.0))

        language = body.get("language") or "en"
        if language not in _ALLOWED_LANGUAGES:
            raise _bad_request(
                "unsupported language", language=language,
                allowed=sorted(_ALLOWED_LANGUAGES),
            )

        template = _validate_template(body.get("template") or "generic")

        # Translate C2 coarse bucket → evadex fine categories.
        evadex_cats: list[str] = []
        if category:
            if category.upper() in set(cat.all_buckets()):
                evadex_cats = cat.expand(category)
            else:
                evadex_cats = [category]

        # Resolve output path — temp file that FastAPI streams back. The
        # success path hands cleanup to a BackgroundTask; the failure
        # paths must unlink explicitly so we don't leak on every 500.
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

        try:
            proc = subprocess.run(
                argv,
                cwd=str(_repo_root()),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            _unlink_quietly(out_path)
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "failed to launch evadex generate",
                    "reason": str(exc),
                },
            )

        if proc.returncode != 0 or not out_path.is_file():
            detail = {
                "error": "evadex generate failed",
                "exit_code": proc.returncode,
                "stderr": (proc.stderr or "")[-2048:],
                "argv": argv[2:],  # hide the python exe
            }
            _unlink_quietly(out_path)
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
