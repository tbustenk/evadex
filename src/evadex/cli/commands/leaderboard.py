"""evadex leaderboard — rank all scanner labels from audit history."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from evadex.audit import read_audit_entries

err_console = Console(stderr=True)


# Import grade helper from score so the two commands stay in sync.
def _grade(score: float) -> tuple[str, str]:
    if score >= 85:
        return "A", "green"
    if score >= 70:
        return "B", "cyan"
    if score >= 55:
        return "C", "yellow"
    if score >= 40:
        return "D", "dark_orange"
    return "F", "red"


def _composite(detection: float, fp_score: float, coverage: float) -> float:
    """Compute composite score with the same weights as evadex score."""
    return round(detection * 0.40 + fp_score * 0.30 + coverage * 0.20 + 50.0 * 0.10, 1)


def _build_leaderboard(audit_path: Path, last_n: int, tier: str) -> list[dict]:
    """Return one dict per scanner label, sorted by composite score descending."""
    entries = read_audit_entries(audit_path)

    # Collect unique labels
    labels: set[str] = set()
    for e in entries:
        lbl = e.get("scanner_label") or ""
        if lbl:
            labels.add(lbl)

    if not labels:
        return []

    try:
        from evadex.payloads.tiers import get_tier_categories

        tier_cats = get_tier_categories(tier)
        tier_size = len(tier_cats) if tier_cats else 102
    except Exception:
        tier_size = 102

    rows: list[dict] = []
    for label in labels:
        label_entries = [e for e in entries if e.get("scanner_label") == label]
        scan_entries = [e for e in label_entries if e.get("type") == "scan"][-last_n:]
        fp_entries = [e for e in label_entries if e.get("type") == "falsepos"][-last_n:]

        if not scan_entries:
            continue

        detection_avg = sum(e.get("pass_rate", 0.0) for e in scan_entries) / len(
            scan_entries
        )
        fp_avg = (
            sum(e.get("fp_rate", 0.0) for e in fp_entries) / len(fp_entries)
            if fp_entries
            else None
        )
        fp_score = (100.0 - fp_avg) if fp_avg is not None else 70.0

        all_cats: set[str] = set()
        for e in scan_entries:
            for c in e.get("categories", []):
                all_cats.add(c)
        coverage = min(100.0, len(all_cats) / tier_size * 100) if tier_size else 0.0

        comp = _composite(detection_avg, fp_score, coverage)

        last_ts = max(e.get("timestamp", "") for e in scan_entries)

        rows.append(
            {
                "scanner_label": label,
                "composite": comp,
                "detection": round(detection_avg, 1),
                "fp_rate": round(fp_avg, 1) if fp_avg is not None else None,
                "coverage": round(coverage, 1),
                "scan_runs": len(scan_entries),
                "fp_runs": len(fp_entries),
                "last_seen": last_ts[:10] if last_ts else "?",
            }
        )

    rows.sort(key=lambda r: -r["composite"])
    return rows


@click.command("leaderboard")
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
    help="Aggregate only the most recent N entries per scanner label.",
)
@click.option(
    "--tier",
    default="northam",
    show_default=True,
    type=click.Choice(["northam", "banking", "core", "regional", "full"]),
    help="Reference tier for coverage breadth calculation.",
)
def leaderboard(audit_log: str, last_n: int, tier: str) -> None:
    """Compare all scanner labels from scan history ranked by composite score.

    Each scanner label that appears in audit.jsonl gets a row showing its
    detection rate, false positive rate, coverage breadth, and overall score.
    Useful for A/B comparing scanner configurations or tracking regressions
    across software versions.

    \b
    Examples:
      evadex leaderboard
      evadex leaderboard --last 5
      evadex leaderboard --tier core
    """
    audit_path = Path(audit_log)
    if not audit_path.exists():
        err_console.print(
            f"[yellow]No audit log found at {audit_path}.[/yellow]\n"
            "Run [bold]evadex scan[/bold] first to build history."
        )
        sys.exit(0)

    rows = _build_leaderboard(audit_path, last_n, tier)

    if not rows:
        err_console.print(
            f"[yellow]No scanner labels found in {audit_path}.[/yellow]\n"
            "Run [bold]evadex scan --scanner-label <name>[/bold] to tag your runs."
        )
        sys.exit(0)

    console = Console()
    table = Table(
        title=f"Scanner Leaderboard  (last {last_n} runs each · tier: {tier})",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Rank", justify="right", style="dim", min_width=5)
    table.add_column("Scanner", style="bold", min_width=20)
    table.add_column("Score", justify="right", min_width=8)
    table.add_column("Grade", justify="center", min_width=6)
    table.add_column("Detection", justify="right", min_width=10)
    table.add_column("FP rate", justify="right", min_width=9)
    table.add_column("Coverage", justify="right", min_width=10)
    table.add_column("Scans", justify="right", min_width=6)
    table.add_column("Last seen", style="dim", min_width=10)

    for i, row in enumerate(rows, 1):
        grade_letter, grade_colour = _grade(row["composite"])
        fp_str = (
            f"[{'green' if row['fp_rate'] < 10 else 'yellow' if row['fp_rate'] < 30 else 'red'}]{row['fp_rate']:.1f}%[/]"
            if row["fp_rate"] is not None
            else "[dim]—[/dim]"
        )
        det_colour = (
            "green"
            if row["detection"] >= 80
            else ("yellow" if row["detection"] >= 60 else "red")
        )
        table.add_row(
            str(i),
            row["scanner_label"],
            f"[bold {grade_colour}]{row['composite']:.1f}[/bold {grade_colour}]",
            f"[bold {grade_colour}]{grade_letter}[/bold {grade_colour}]",
            f"[{det_colour}]{row['detection']:.1f}%[/{det_colour}]",
            fp_str,
            f"{row['coverage']:.1f}%",
            str(row["scan_runs"]),
            row["last_seen"],
        )

    console.print()
    console.print(table)
    console.print(f"\n[dim]{len(rows)} scanner label(s) from {audit_path}[/dim]")
