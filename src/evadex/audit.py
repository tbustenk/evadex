"""Append-only audit log for evadex scan runs.

Each completed scan appends one JSON line to the configured log file.
Errors writing the audit log are silently ignored — a log failure must
never abort or alter the outcome of a scan.
"""

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        _VERSION = version("evadex")
    except PackageNotFoundError:
        _VERSION = "unknown"
except ImportError:
    _VERSION = "unknown"


def append_audit_entry(
    audit_log: str,
    *,
    scanner_label: str,
    tool: str,
    strategies: list[str],
    categories: list[str],
    include_heuristic: bool,
    total: int,
    passes: int,
    fails: int,
    errors: int,
    pass_rate: float,
    output_file: Optional[str],
    baseline_saved: Optional[str],
    compare_baseline: Optional[str],
    min_detection_rate: Optional[float],
    exit_code: int,
    technique_success_rates: Optional[dict] = None,
) -> None:
    """Append one JSON line to *audit_log* describing this scan run.

    Parent directories are created if they do not exist.  Any exception
    (permissions, disk full, bad path) is silently swallowed so the
    caller's exit code and output are never affected.

    *technique_success_rates* is a ``{technique_name: success_fraction}``
    mapping (success = pass / (pass + fail), errors excluded). The
    ``evadex techniques`` command and the ``weighted`` / ``adversarial``
    evasion modes consume this field.
    """
    entry = {
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "evadex_version":    _VERSION,
        "operator":          _operator(),
        "scanner_label":     scanner_label,
        "tool":              tool,
        "strategies":        strategies,
        "categories":        categories,
        "include_heuristic": include_heuristic,
        "total":             total,
        "pass":              passes,
        "fail":              fails,
        "error":             errors,
        "pass_rate":         pass_rate,
        "output_file":       output_file,
        "baseline_saved":    baseline_saved,
        "compare_baseline":  compare_baseline,
        "min_detection_rate": min_detection_rate,
        "exit_code":         exit_code,
        "technique_success_rates": technique_success_rates or {},
    }
    try:
        path = Path(audit_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def read_audit_entries(audit_path: Path) -> list[dict]:
    """Return all valid audit entries from *audit_path*, oldest first.

    Missing or unreadable files return an empty list. Malformed JSON lines
    are skipped silently — a corrupt entry must not prevent the caller from
    reading the rest of the log.
    """
    if not audit_path.exists():
        return []
    entries: list[dict] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _operator() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
