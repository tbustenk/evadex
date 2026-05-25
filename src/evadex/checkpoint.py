"""Scan progress checkpointing — save and resume interrupted scans.

Checkpoints are written to ~/.evadex/checkpoints/<run_id>.json.  Each
checkpoint records the set of already-completed (payload, category, generator,
technique, strategy) 5-tuples so a resumed scan can skip them and continue
from where it left off.

Usage in scan.py:

    run_id = new_run_id(tier, tool)
    cp = find_latest_checkpoint(tier, tool, categories)  # or None on fresh run
    skip_keys = {tuple(k) for k in cp["completed_keys"]} if cp else set()
    partial_results = cp.get("partial_results", []) if cp else []

    # Pass skip_keys to Engine; after each result, call save_checkpoint every N.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_CHECKPOINT_DIR = Path.home() / ".evadex" / "checkpoints"


def _checkpoint_dir() -> Path:
    _CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    return _CHECKPOINT_DIR


def _fingerprint(tier: str, tool: str, categories: list[str]) -> str:
    key = f"{tier}:{tool}:{':'.join(sorted(categories))}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def new_run_id(tier: str, tool: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{ts}-{tier}-{tool}"


def checkpoint_path(run_id: str) -> Path:
    return _checkpoint_dir() / f"{run_id}.json"


def find_latest_checkpoint(
    tier: str,
    tool: str,
    categories: list[str],
) -> Optional[dict]:
    """Return the most recent checkpoint matching these run parameters, or None."""
    fp = _fingerprint(tier, tool, categories)
    candidates = []
    for p in _checkpoint_dir().glob("*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("fingerprint") == fp:
                candidates.append((data.get("created", ""), data))
        except (json.JSONDecodeError, OSError):
            continue
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def save_checkpoint(
    run_id: str,
    tier: str,
    tool: str,
    categories: list[str],
    completed_keys: list[tuple],
    partial_results: list[dict],
) -> Path:
    """Write checkpoint to disk. Returns the file path."""
    path = checkpoint_path(run_id)
    data = {
        "run_id": run_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "fingerprint": _fingerprint(tier, tool, categories),
        "tier": tier,
        "tool": tool,
        "categories": sorted(categories),
        "completed_count": len(completed_keys),
        "completed_keys": [list(k) for k in completed_keys],
        "partial_results": partial_results,
    }
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def delete_checkpoint(run_id: str) -> None:
    """Remove a checkpoint file if it exists (no-op if missing)."""
    try:
        checkpoint_path(run_id).unlink()
    except OSError:
        pass
