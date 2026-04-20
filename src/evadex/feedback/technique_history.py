"""Read per-technique success-rate history from the audit log.

Each ``audit.jsonl`` line written since v3.13.0 carries a
``technique_success_rates`` field — a ``{technique: pass_rate}``
mapping captured at the end of one scan. This module aggregates
those entries so the CLI can present trends and so the
weighted/adversarial evasion modes have a numeric input.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class TechniqueStats:
    """Aggregated success-rate stats for one technique."""
    technique: str
    runs: int = 0
    average_success: float = 0.0
    latest_success: float = 0.0
    previous_success: Optional[float] = None  # for trend computation
    last_seen: str = ""
    history: list[float] = field(default_factory=list)

    @property
    def trend(self) -> Optional[float]:
        """Δ between latest and previous (in absolute success-rate units)."""
        if self.previous_success is None:
            return None
        return self.latest_success - self.previous_success


def _iter_audit_entries(path: str) -> Iterator[dict]:
    p = Path(path)
    if not p.exists():
        return
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_technique_history(
    audit_log: str,
    last_n: Optional[int] = None,
) -> dict[str, TechniqueStats]:
    """Walk *audit_log* and return ``{technique: TechniqueStats}``.

    *last_n* — if set, restrict to the most recent N audit entries. Older
    entries (and entries with no ``technique_success_rates`` field, e.g.
    pre-3.13.0) are skipped silently.
    """
    entries = list(_iter_audit_entries(audit_log))
    if last_n is not None:
        entries = entries[-last_n:]

    stats: dict[str, TechniqueStats] = {}
    for entry in entries:
        rates = entry.get("technique_success_rates") or {}
        ts = entry.get("timestamp", "")
        for tech, rate in rates.items():
            try:
                rate_f = float(rate)
            except (TypeError, ValueError):
                continue
            s = stats.setdefault(tech, TechniqueStats(technique=tech))
            s.history.append(rate_f)
            s.runs += 1
            s.last_seen = ts

    # Second pass — finalise averages and trend deltas.
    for s in stats.values():
        if not s.history:
            continue
        s.average_success = sum(s.history) / len(s.history)
        s.latest_success = s.history[-1]
        s.previous_success = s.history[-2] if len(s.history) >= 2 else None
    return stats


def filter_stats(
    stats: dict[str, TechniqueStats],
    *,
    min_runs: int = 1,
    top: Optional[int] = None,
) -> list[TechniqueStats]:
    """Return stats sorted by latest_success desc, applying min_runs and top filters."""
    pool = [s for s in stats.values() if s.runs >= min_runs]
    pool.sort(key=lambda s: -s.latest_success)
    if top is not None:
        pool = pool[:top]
    return pool


def has_history(audit_log: str) -> bool:
    """Cheap check: does the audit log contain at least one entry with
    technique_success_rates? Used for cold-start handling."""
    for entry in _iter_audit_entries(audit_log):
        if entry.get("technique_success_rates"):
            return True
    return False
