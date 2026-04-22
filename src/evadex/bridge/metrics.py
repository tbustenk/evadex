"""Aggregate evadex audit log + result archives into the C2 metrics shape.

The C2 dashboard expects a single GET ``/v1/evadex/metrics`` response that
carries detection rate, FP rate, coverage, per-category breakdown, top
evasions, and recent history. This module turns the append-only
``results/audit.jsonl`` (plus the archive files it points at) into that
shape without mutating any of the underlying data.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from evadex.bridge.categories import all_buckets, bucket_for_category


# Default audit + results layout — matches the evadex CLI defaults.
DEFAULT_AUDIT_LOG = "results/audit.jsonl"

# How many recent runs the C2 history panel shows.
HISTORY_LIMIT = 10

# How many data points the trend sparklines need.
TREND_LIMIT = 8

# Mapping from scan result category keys → whether they are "sensitive".
# Left intentionally empty — categories are passed through as-is. The
# "patterns_total" coverage denominator reads from the latest scan's
# ``summary_by_category`` if the caller doesn't supply one.


def _read_audit_entries(audit_log: Path) -> list[dict]:
    """Return audit entries oldest-first. Missing / malformed = empty list."""
    if not audit_log.is_file():
        return []
    out: list[dict] = []
    with open(audit_log, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _scan_entries(entries: list[dict]) -> list[dict]:
    return [e for e in entries if e.get("type", "scan") == "scan"]


def _falsepos_entries(entries: list[dict]) -> list[dict]:
    return [e for e in entries if e.get("type") == "falsepos"]


def _load_archive(repo_root: Path, entry: dict) -> Optional[dict]:
    """Load the detailed JSON archive a scan audit entry points at.

    Returns None if the file doesn't exist or can't be parsed.
    """
    rel = entry.get("archive_file") or entry.get("output_file")
    if not rel:
        return None
    path = repo_root / rel if not Path(rel).is_absolute() else Path(rel)
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _detection_rate_of(entry: dict) -> Optional[float]:
    """Scan audit entry → detection rate percent (0–100) or None."""
    pr = entry.get("pass_rate")
    if pr is None:
        return None
    try:
        return float(pr)
    except (TypeError, ValueError):
        return None


def _run_id_for(entry: dict, fallback_index: int) -> str:
    """Derive a stable short run id from an audit entry."""
    ts = entry.get("timestamp") or ""
    # Compact ISO → R-YYYYMMDDTHHMMSS
    if ts:
        stripped = ts.replace("-", "").replace(":", "").split(".")[0].split("+")[0]
        if stripped.endswith("Z"):
            stripped = stripped[:-1]
        return f"R-{stripped}"
    return f"R-{fallback_index:05d}"


def _by_category_breakdown(archive: Optional[dict]) -> dict[str, dict]:
    """Collapse the latest scan's per-fine-category counts into C2 buckets.

    Returns ``{BUCKET: {tp, fn, fp, recall, precision}}`` for every bucket
    that had any data, with recall / precision as floats in 0–100. ``fp``
    is populated by :func:`build_metrics` from the falsepos log separately;
    it stays 0 here.
    """
    buckets: dict[str, dict[str, float]] = {}
    if not archive:
        return {}
    summary = (archive.get("meta") or {}).get("summary_by_category") or {}
    for cat, counts in summary.items():
        passes = int(counts.get("pass", 0) or 0)
        fails = int(counts.get("fail", 0) or 0)
        bucket = bucket_for_category(cat)
        b = buckets.setdefault(bucket, {"tp": 0, "fn": 0, "fp": 0})
        # A "pass" in evadex-scan means the scanner detected the evasion
        # — i.e. a true positive. A "fail" means the evasion bypassed,
        # i.e. a false negative.
        b["tp"] += passes
        b["fn"] += fails
    # Compute recall / precision after aggregation.
    out: dict[str, dict] = {}
    for name, counts in buckets.items():
        tp, fn, fp = counts["tp"], counts["fn"], counts["fp"]
        recall = round(100.0 * tp / (tp + fn), 1) if (tp + fn) else 0.0
        precision = round(100.0 * tp / (tp + fp), 1) if (tp + fp) else 0.0
        out[name] = {
            "tp": int(tp), "fn": int(fn), "fp": int(fp),
            "recall": recall, "precision": precision,
        }
    return out


def _top_evasions(entry: dict, archive: Optional[dict], limit: int = 5) -> list[dict]:
    """Return the evasion techniques with the highest success rates.

    Prefers ``technique_success_rates`` (either on the audit entry or in
    the archive meta). Falls back to computing rates from the archive's
    ``summary_by_technique`` map when the fraction field isn't present
    — the ``build_scan_audit_entry`` path writes the counts but not the
    pre-computed rates, so this fallback is the common case.
    """
    raw = entry.get("technique_success_rates") or {}
    archive_meta = (archive or {}).get("meta") or {}
    if not raw:
        raw = archive_meta.get("technique_success_rates") or {}
    items: list[dict] = []
    if raw:
        for name, rate in raw.items():
            try:
                rate_f = float(rate)
            except (TypeError, ValueError):
                continue
            items.append({"technique": name, "success_rate": round(rate_f * 100.0, 1)})
    else:
        # Compute from counts. "pass" means the scanner caught the
        # variant, so from the evasion's perspective success = fail.
        # But the existing field semantics (elsewhere in the code +
        # C2 dashboard) treat "success_rate" as the scanner's catch
        # rate for that technique — keep that.
        by_tech = archive_meta.get("summary_by_technique") or {}
        for name, counts in by_tech.items():
            try:
                passes = int(counts.get("pass", 0) or 0)
                fails = int(counts.get("fail", 0) or 0)
            except (TypeError, ValueError, AttributeError):
                continue
            denom = passes + fails
            if denom <= 0:
                continue
            items.append({
                "technique": name,
                "success_rate": round(100.0 * passes / denom, 1),
                "pass": passes,
                "fail": fails,
            })
    items.sort(key=lambda r: r["success_rate"], reverse=True)
    return items[:limit]


def _coverage(archive: Optional[dict], fallback_total: int = 557) -> tuple[float, int, int]:
    """Return ``(coverage_pct, tested, total)``.

    ``tested`` = number of fine categories present in the latest scan.
    ``total``  = total fine categories defined (read from archive meta
                 when available, otherwise the supplied fallback).
    """
    if not archive:
        return (0.0, 0, fallback_total)
    summary = (archive.get("meta") or {}).get("summary_by_category") or {}
    tested = len(summary)
    total = (archive.get("meta") or {}).get("categories_total")
    try:
        total = int(total) if total else fallback_total
    except (TypeError, ValueError):
        total = fallback_total
    total = max(total, tested)
    pct = round(100.0 * tested / total, 1) if total else 0.0
    return (pct, tested, total)


def _safe_str(v: Any) -> str:
    return "" if v is None else str(v)


def _dedupe_scans(scans: list[dict]) -> list[dict]:
    """Collapse runs of audit entries that point at the same archive file.

    The CLI write-path used to produce one entry per writer invocation
    rather than per scan, so a single run could leave many identical
    lines behind in ``results/audit.jsonl``. Keep the first (earliest)
    sighting for each archive_file — that's the authoritative write —
    and drop the rest. Entries with no archive_file are kept as-is so
    legacy rows aren't silently lost.
    """
    seen: dict[str, dict] = {}
    loose: list[dict] = []
    for e in scans:
        key = e.get("archive_file")
        if not key:
            loose.append(e)
            continue
        if key not in seen:
            seen[key] = e
    deduped = list(seen.values()) + loose
    deduped.sort(key=lambda e: e.get("timestamp") or "")
    return deduped


def _fp_match_key(entry: Optional[dict]) -> tuple[str, str]:
    if not entry:
        return ("", "")
    return (
        _safe_str(entry.get("scanner_label")),
        _safe_str(entry.get("tool")),
    )


def _matching_fp_entries(
    falsepos: list[dict], latest_scan: Optional[dict],
) -> list[dict]:
    """Return falsepos entries that pair with *latest_scan*.

    Matches on ``(scanner_label, tool)`` — a falsepos run against a
    different scanner has no bearing on the current scanner's FP rate.
    If no scan is known yet, fall through and return everything so the
    trend panel still renders historical FP data.
    """
    if not latest_scan:
        return list(falsepos)
    scan_label = _safe_str(latest_scan.get("scanner_label"))
    scan_tool = _safe_str(latest_scan.get("tool"))
    out: list[dict] = []
    for e in falsepos:
        fp_label = _safe_str(e.get("scanner_label"))
        fp_tool = _safe_str(e.get("tool"))
        if scan_label and fp_label == scan_label:
            out.append(e)
        elif scan_tool and fp_tool == scan_tool:
            out.append(e)
    return out


def _latest_matching_fp(
    falsepos: list[dict], latest_scan: Optional[dict],
) -> Optional[dict]:
    matches = _matching_fp_entries(falsepos, latest_scan)
    return matches[-1] if matches else None


def build_metrics(
    repo_root: Path | str = ".",
    audit_log: Path | str = DEFAULT_AUDIT_LOG,
) -> dict:
    """Produce the C2 metrics payload from the audit log + archives.

    All numbers are floats in 0–100 (percent). Empty / missing inputs
    produce a well-formed response with zeros and empty lists so the
    frontend never has to branch on a totally-empty state.
    """
    repo_root = Path(repo_root)
    audit_path = Path(audit_log)
    if not audit_path.is_absolute():
        audit_path = repo_root / audit_path

    entries = _read_audit_entries(audit_path)
    scans = _dedupe_scans(_scan_entries(entries))
    falsepos = _falsepos_entries(entries)

    # Trend + history pull from scan entries, newest last.
    recent_scans = scans[-max(HISTORY_LIMIT, TREND_LIMIT):]
    detection_trend = [
        _detection_rate_of(e) or 0.0 for e in recent_scans[-TREND_LIMIT:]
    ]

    # Latest scan drives "current" detection rate + breakdown + top evasions.
    latest_scan = scans[-1] if scans else None
    archive = _load_archive(repo_root, latest_scan) if latest_scan else None

    # Pair the headline FP rate to the *same* scanner as the latest
    # scan. Mixing a dlpscan-cli FP run with a siphon-cli scan produced
    # misleading headline numbers (e.g. a narrow iban-only FP run
    # surfaced as 100% FP against an unrelated scan).
    latest_fp = _latest_matching_fp(falsepos, latest_scan)
    fp_trend = [
        float(e.get("fp_rate", 0.0) or 0.0)
        for e in _matching_fp_entries(falsepos, latest_scan)[-TREND_LIMIT:]
    ]

    detection_rate = _detection_rate_of(latest_scan) if latest_scan else 0.0
    # No matching falsepos run → return null so the UI can show "n/a"
    # instead of a stale/misleading rate.
    fp_rate: Optional[float]
    if latest_fp is None:
        fp_rate = None
    else:
        try:
            fp_rate = float(latest_fp.get("fp_rate", 0.0) or 0.0)
        except (TypeError, ValueError):
            fp_rate = None

    coverage_pct, tested, total = _coverage(archive)

    by_category = _by_category_breakdown(archive)
    # Ensure every coarse bucket appears in the response (empty zeros)
    # so the frontend table renders a stable set of rows.
    for b in all_buckets():
        by_category.setdefault(b, {
            "tp": 0, "fn": 0, "fp": 0, "recall": 0.0, "precision": 0.0,
        })

    # Fold in FP counts from the latest falsepos archive, best-effort.
    if latest_fp:
        fp_archive = _load_archive(repo_root, latest_fp)
        if fp_archive:
            per_cat_fp = (fp_archive.get("meta") or {}).get("fp_by_category") or {}
            for cat, count in per_cat_fp.items():
                bucket = bucket_for_category(cat)
                if bucket in by_category:
                    by_category[bucket]["fp"] += int(count or 0)
                    # Recompute precision after folding FPs back in.
                    row = by_category[bucket]
                    denom = row["tp"] + row["fp"]
                    row["precision"] = (
                        round(100.0 * row["tp"] / denom, 1) if denom else 0.0
                    )

    history = []
    for i, e in enumerate(scans[-HISTORY_LIMIT:][::-1]):
        history.append({
            "run_id": _run_id_for(e, i),
            "when": _safe_str(e.get("timestamp")),
            "profile": _safe_str(e.get("scanner_label") or e.get("tool") or ""),
            "scanner": _safe_str(e.get("tool") or ""),
            "detection_rate": _detection_rate_of(e) or 0.0,
        })

    return {
        "detection_rate": detection_rate or 0.0,
        "detection_trend": detection_trend or [0.0] * TREND_LIMIT,
        "fp_rate": fp_rate,
        "fp_trend": fp_trend or [0.0] * TREND_LIMIT,
        "coverage": coverage_pct,
        "patterns_tested": tested,
        "patterns_total": total,
        "last_run": _safe_str(latest_scan.get("timestamp")) if latest_scan else "",
        "last_run_id": _run_id_for(latest_scan, 0) if latest_scan else "",
        "last_run_scanner": _safe_str(latest_scan.get("tool")) if latest_scan else "",
        "by_category": by_category,
        "top_evasions": _top_evasions(latest_scan, archive) if latest_scan else [],
        "history": history,
    }
