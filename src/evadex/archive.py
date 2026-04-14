"""Results archive — auto-saves timestamped scan/falsepos runs and maintains
results/audit.jsonl.  All public functions swallow exceptions so that a disk
or permission failure never affects a scan run's exit code or output.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from importlib.metadata import version as _pkg_version, PackageNotFoundError
    try:
        _VERSION = _pkg_version("evadex")
    except PackageNotFoundError:
        _VERSION = "unknown"
except ImportError:
    _VERSION = "unknown"

# All archive files live under <cwd>/results/
_RESULTS_DIR = Path("results")


# ── Internal helpers ───────────────────────────────────────────────────────────

def _ensure_dirs() -> Path:
    """Create results directory structure if needed and return it."""
    for sub in ("scans", "falsepos", "comparisons"):
        (_RESULTS_DIR / sub).mkdir(parents=True, exist_ok=True)
    return _RESULTS_DIR


def _safe_label(s: str) -> str:
    """Sanitise label string for use in a filename (max 40 chars)."""
    cleaned = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in (s or ""))
    return cleaned[:40] or "unlabelled"


# ── Public helpers ─────────────────────────────────────────────────────────────

def get_commit_hash() -> Optional[str]:
    """Return the short git commit hash of HEAD, or None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
    except Exception:
        pass
    return None


# ── Archive functions ──────────────────────────────────────────────────────────

def archive_scan(
    rendered_json: str,
    scanner_label: str,
    *,
    ts: Optional[datetime] = None,
) -> Path:
    """Save *rendered_json* to results/scans/ with a timestamped name.

    Never overwrites an existing file.  Returns the path written.
    Silently returns a placeholder Path on any error.
    """
    try:
        ts = ts or datetime.now(timezone.utc)
        stamp = ts.strftime("%Y%m%dT%H%M%SZ")
        name = f"scan_{stamp}_{_safe_label(scanner_label)}.json"
        path = _ensure_dirs() / "scans" / name
        if not path.exists():
            path.write_text(rendered_json, encoding="utf-8")
        return path
    except Exception:
        return _RESULTS_DIR / "scans" / "error.json"


def archive_falsepos(
    report: dict,
    scanner_label: str = "",
    *,
    ts: Optional[datetime] = None,
) -> Path:
    """Save *report* to results/falsepos/ with a timestamped name.

    Never overwrites an existing file.  Returns the path written.
    Silently returns a placeholder Path on any error.
    """
    try:
        ts = ts or datetime.now(timezone.utc)
        stamp = ts.strftime("%Y%m%dT%H%M%SZ")
        name = f"falsepos_{stamp}_{_safe_label(scanner_label)}.json"
        path = _ensure_dirs() / "falsepos" / name
        if not path.exists():
            path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        return path
    except Exception:
        return _RESULTS_DIR / "falsepos" / "error.json"


def append_results_audit(entry: dict) -> None:
    """Append one JSON line to results/audit.jsonl.  Silently ignores errors."""
    try:
        audit_path = _ensure_dirs() / "audit.jsonl"
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


# ── Audit entry builders ───────────────────────────────────────────────────────

def build_scan_audit_entry(
    *,
    scanner_label: str,
    tool: str,
    categories: list[str],
    strategies: list[str],
    total: int,
    passes: int,
    fails: int,
    pass_rate: float,
    archive_file: str,
    commit_hash: Optional[str] = None,
    ts: Optional[datetime] = None,
) -> dict:
    return {
        "timestamp":      (ts or datetime.now(timezone.utc)).isoformat(),
        "type":           "scan",
        "evadex_version": _VERSION,
        "scanner_label":  scanner_label,
        "tool":           tool,
        "categories":     categories,
        "strategies":     strategies,
        "total":          total,
        "pass":           passes,
        "fail":           fails,
        "pass_rate":      pass_rate,
        "commit_hash":    commit_hash,
        "archive_file":   archive_file,
    }


def build_falsepos_audit_entry(
    *,
    tool: str,
    categories: list[str],
    total_tested: int,
    total_flagged: int,
    fp_rate: float,
    archive_file: str,
    commit_hash: Optional[str] = None,
    scanner_label: str = "",
    ts: Optional[datetime] = None,
) -> dict:
    return {
        "timestamp":      (ts or datetime.now(timezone.utc)).isoformat(),
        "type":           "falsepos",
        "evadex_version": _VERSION,
        "scanner_label":  scanner_label,
        "tool":           tool,
        "categories":     categories,
        "total_tested":   total_tested,
        "total_flagged":  total_flagged,
        "fp_rate":        fp_rate,
        "commit_hash":    commit_hash,
        "archive_file":   archive_file,
    }


# ── Backfill ───────────────────────────────────────────────────────────────────

def backfill_from_directory(directory: str = ".") -> int:
    """Scan *directory* for existing evadex result JSON files and add them
    to results/audit.jsonl.  Skips files already inside results/.

    Returns the number of entries added.
    """
    added = 0
    for path in sorted(Path(directory).glob("*.json")):
        if path.name.startswith("."):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # ── Scan result: has 'meta' with 'pass_rate' and 'results' list ──────
        if isinstance(data, dict) and "meta" in data and "results" in data:
            meta = data.get("meta", {})
            if not isinstance(meta, dict) or "pass_rate" not in meta:
                continue
            ts_str = meta.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str)
            except Exception:
                ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

            scanner_label = meta.get("scanner", "")
            stamp = ts.strftime("%Y%m%dT%H%M%SZ")
            dest_name = f"scan_{stamp}_{_safe_label(scanner_label)}.json"
            dest = _ensure_dirs() / "scans" / dest_name
            if not dest.exists():
                shutil.copy2(path, dest)

            entry = {
                "timestamp":      ts.isoformat(),
                "type":           "scan",
                "evadex_version": meta.get("evadex_version", "unknown"),
                "scanner_label":  scanner_label,
                "tool":           "dlpscan-cli",
                "categories":     list(meta.get("summary_by_category", {}).keys()),
                "strategies":     [],
                "total":          meta.get("total", 0),
                "pass":           meta.get("pass", 0),
                "fail":           meta.get("fail", 0),
                "pass_rate":      meta.get("pass_rate", 0.0),
                "commit_hash":    None,
                "archive_file":   str(dest),
                "_backfilled_from": str(path),
            }
            append_results_audit(entry)
            added += 1
            continue

        # ── Falsepos result: has 'total_tested' and 'overall_false_positive_rate' ──
        if (
            isinstance(data, dict)
            and "total_tested" in data
            and "overall_false_positive_rate" in data
        ):
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            stamp = ts.strftime("%Y%m%dT%H%M%SZ")
            dest_name = f"falsepos_{stamp}_{_safe_label(data.get('tool', ''))}.json"
            dest = _ensure_dirs() / "falsepos" / dest_name
            if not dest.exists():
                shutil.copy2(path, dest)

            entry = {
                "timestamp":      ts.isoformat(),
                "type":           "falsepos",
                "evadex_version": "unknown",
                "scanner_label":  "",
                "tool":           data.get("tool", ""),
                "categories":     list(data.get("by_category", {}).keys()),
                "total_tested":   data.get("total_tested", 0),
                "total_flagged":  data.get("total_flagged", 0),
                "fp_rate":        data.get("overall_false_positive_rate", 0.0),
                "commit_hash":    None,
                "archive_file":   str(dest),
                "_backfilled_from": str(path),
            }
            append_results_audit(entry)
            added += 1

    return added
