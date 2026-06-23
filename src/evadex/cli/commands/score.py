"""evadex score — composite scanner quality score (0-100) from audit history."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.audit import read_audit_entries

err_console = Console(stderr=True)

# Weight constants (must sum to 1.0)
_W_DETECTION = 0.40
_W_FP = 0.30
_W_COVERAGE = 0.20
_W_TIMING = 0.10

# Categories in the northam tier — used as the coverage denominator when no
# tier is specified.
_NORTHAM_SIZE_FALLBACK = 102


def _grade(score: float) -> tuple[str, str]:
    """Return (letter, rich colour) for a numeric score 0-100."""
    if score >= 85:
        return "A", "green"
    if score >= 70:
        return "B", "cyan"
    if score >= 55:
        return "C", "yellow"
    if score >= 40:
        return "D", "dark_orange"
    return "F", "red"


def _northam_size() -> int:
    try:
        from evadex.payloads.tiers import get_tier_categories

        cats = get_tier_categories("northam")
        return len(cats) if cats else _NORTHAM_SIZE_FALLBACK
    except Exception:
        return _NORTHAM_SIZE_FALLBACK


def _compute_score(
    scanner_label: Optional[str],
    audit_path: Path,
    last_n: int,
    tier: str,
) -> dict:
    """Return a dict with score components and the composite score."""
    entries = read_audit_entries(audit_path)

    if scanner_label:
        entries = [e for e in entries if e.get("scanner_label") == scanner_label]

    scan_entries = [e for e in entries if e.get("type") == "scan"]
    fp_entries = [e for e in entries if e.get("type") == "falsepos"]

    scan_entries = scan_entries[-last_n:]
    fp_entries = fp_entries[-last_n:]

    # ── Detection rate (40 %) ──────────────────────────────────────────────
    if scan_entries:
        detection_avg = sum(e.get("pass_rate", 0.0) for e in scan_entries) / len(
            scan_entries
        )
        detection_runs = len(scan_entries)
    else:
        detection_avg = 0.0
        detection_runs = 0

    # ── FP rate (30 %, lower is better → invert) ──────────────────────────
    if fp_entries:
        fp_avg = sum(e.get("fp_rate", 0.0) for e in fp_entries) / len(fp_entries)
        fp_runs = len(fp_entries)
    else:
        fp_avg = None  # no FP data
        fp_runs = 0

    # When FP data is absent, score that component at a conservative 70/100
    # (slight penalty for untested, but not catastrophic).
    fp_score = (100.0 - fp_avg) if fp_avg is not None else 70.0

    # ── Coverage breadth (20 %) ────────────────────────────────────────────
    all_cats: set[str] = set()
    for e in entries if not scan_entries else scan_entries:
        for c in e.get("categories", []):
            all_cats.add(c)

    try:
        from evadex.payloads.tiers import get_tier_categories

        tier_cats = get_tier_categories(tier)
        tier_size = len(tier_cats) if tier_cats else _northam_size()
    except Exception:
        tier_size = _northam_size()

    coverage_pct = min(100.0, len(all_cats) / tier_size * 100) if tier_size else 0.0

    # ── Response time (10 %) — not stored in audit log ────────────────────
    # Proxy: 50/100 (neutral) when no timing data is available.
    timing_score = 50.0
    timing_note = "N/A (not in audit log)"

    # ── Composite ─────────────────────────────────────────────────────────
    composite = (
        detection_avg * _W_DETECTION
        + fp_score * _W_FP
        + coverage_pct * _W_COVERAGE
        + timing_score * _W_TIMING
    )
    composite = round(min(100.0, max(0.0, composite)), 1)

    return {
        "composite": composite,
        "detection_avg": round(detection_avg, 1),
        "detection_runs": detection_runs,
        "fp_avg": round(fp_avg, 1) if fp_avg is not None else None,
        "fp_score": round(fp_score, 1),
        "fp_runs": fp_runs,
        "coverage_pct": round(coverage_pct, 1),
        "coverage_cats": len(all_cats),
        "tier_size": tier_size,
        "timing_score": timing_score,
        "timing_note": timing_note,
        "scanner_label": scanner_label,
        "last_n": last_n,
    }


@click.command("score")
@click.option(
    "--scanner-label",
    "scanner_label",
    default=None,
    help="Restrict history to this scanner label. Omit to aggregate all labels.",
)
@click.option(
    "--audit-log",
    default="results/audit.jsonl",
    show_default=True,
    help="Path to audit.jsonl written by evadex scan / evadex falsepos.",
)
@click.option(
    "--last",
    "last_n",
    default=10,
    show_default=True,
    type=int,
    help="Aggregate only the most recent N scan and falsepos entries.",
)
@click.option(
    "--tier",
    default="northam",
    show_default=True,
    type=click.Choice(["northam", "banking", "core", "regional", "full"]),
    help="Reference tier for coverage breadth calculation.",
)
@click.option(
    "--json",
    "emit_json",
    is_flag=True,
    default=False,
    help="Emit result as JSON.",
)
def score(
    scanner_label: Optional[str],
    audit_log: str,
    last_n: int,
    tier: str,
    emit_json: bool,
) -> None:
    """Composite 0-100 quality score for a scanner from audit history.

    Weighted breakdown:
      Detection rate  40 % — fraction of evasion variants caught
      FP rate         30 % — inverted false positive rate (lower FP = better)
      Coverage        20 % — categories tested vs tier size
      Response time   10 % — scanner latency (defaults to 50/100; not in log)

    Grade thresholds: A ≥ 85  B ≥ 70  C ≥ 55  D ≥ 40  F < 40

    \b
    Examples:
      evadex score
      evadex score --scanner-label siphon-prod
      evadex score --scanner-label siphon-prod --tier northam
      evadex score --json
    """
    audit_path = Path(audit_log)
    if not audit_path.exists():
        err_console.print(
            f"[yellow]No audit log found at {audit_path}.[/yellow]\n"
            "Run [bold]evadex scan[/bold] first to build history."
        )
        sys.exit(0)

    result = _compute_score(scanner_label, audit_path, last_n, tier)

    if emit_json:
        click.echo(json.dumps(result, indent=2))
        return

    console = Console()
    composite = result["composite"]
    grade_letter, grade_colour = _grade(composite)

    label_str = (
        f"[bold]{result['scanner_label']}[/bold]"
        if result["scanner_label"]
        else "[dim]all scanners[/dim]"
    )
    console.print()
    console.print(f"  Scanner     {label_str}")
    console.print(
        f"  Score       [bold {grade_colour}]{composite:.1f} / 100[/bold {grade_colour}]  "
        f"[bold {grade_colour}]{grade_letter}[/bold {grade_colour}]"
    )
    console.print()

    table = Table(show_header=True, header_style="bold dim", box=None, pad_edge=False)
    table.add_column("Component", style="", min_width=20)
    table.add_column("Weight", justify="right", min_width=8)
    table.add_column("Raw value", justify="right", min_width=14)
    table.add_column("Contribution", justify="right", min_width=14)
    table.add_column("Data points", justify="right", min_width=12)

    det_contrib = round(result["detection_avg"] * _W_DETECTION, 1)
    table.add_row(
        "Detection rate",
        "40 %",
        f"[cyan]{result['detection_avg']:.1f}%[/cyan]",
        f"{det_contrib:.1f} pts",
        str(result["detection_runs"]) + " scan(s)",
    )

    fp_raw = (
        f"{result['fp_avg']:.1f}%"
        if result["fp_avg"] is not None
        else "[dim]no data[/dim]"
    )
    fp_contrib = round(result["fp_score"] * _W_FP, 1)
    fp_note = str(result["fp_runs"]) + " falsepos run(s)"
    if result["fp_avg"] is None:
        fp_note += "  [dim](estimated)[/dim]"
    table.add_row(
        "FP rate (inverted)",
        "30 %",
        fp_raw,
        f"{fp_contrib:.1f} pts",
        fp_note,
    )

    cov_contrib = round(result["coverage_pct"] * _W_COVERAGE, 1)
    table.add_row(
        f"Coverage ({tier})",
        "20 %",
        f"[cyan]{result['coverage_pct']:.1f}%[/cyan]  "
        f"[dim]({result['coverage_cats']}/{result['tier_size']} cats)[/dim]",
        f"{cov_contrib:.1f} pts",
        str(result["detection_runs"]) + " scan(s)",
    )

    timing_contrib = round(result["timing_score"] * _W_TIMING, 1)
    table.add_row(
        "Response time",
        "10 %",
        f"[dim]{result['timing_score']:.0f}/100[/dim]",
        f"{timing_contrib:.1f} pts",
        f"[dim]{result['timing_note']}[/dim]",
    )

    console.print(table)
    console.print()

    # Recommendations
    recs = []
    if result["detection_avg"] < 70:
        recs.append(
            f"Detection rate is {result['detection_avg']:.0f}% — "
            "investigate bypassing techniques with [bold]evadex techniques --top 10[/bold]."
        )
    if result["fp_avg"] is not None and result["fp_avg"] > 20:
        recs.append(
            f"FP rate is {result['fp_avg']:.0f}% — scanner over-triggers on benign data. "
            "Review pattern specificity."
        )
    if result["fp_runs"] == 0:
        recs.append(
            "No false positive data — run [bold]evadex falsepos[/bold] to complete the score."
        )
    if result["coverage_pct"] < 80:
        recs.append(
            f"Only {result['coverage_pct']:.0f}% of {tier} categories tested — "
            "run [bold]evadex coverage[/bold] to see gaps."
        )

    if recs:
        console.print("  [bold]Recommendations:[/bold]")
        for r in recs:
            console.print(f"    • {r}")
        console.print()
