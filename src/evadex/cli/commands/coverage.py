"""evadex coverage — show which categories have evasion coverage vs gaps."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.audit import read_audit_entries
from evadex.payloads.tiers import get_tier_categories, VALID_TIERS

err_console = Console(stderr=True)


def _short_date(ts: str) -> str:
    try:
        return ts[:10]
    except Exception:
        return "?"


def _build_coverage(
    audit_path: Path,
    tier: str,
    scanner_label: Optional[str],
) -> dict:
    """Return coverage data for all categories in *tier*."""
    entries = read_audit_entries(audit_path)
    if scanner_label:
        entries = [e for e in entries if e.get("scanner_label") == scanner_label]

    scan_entries = [e for e in entries if e.get("type") == "scan"]

    tier_cats = get_tier_categories(tier)
    if not tier_cats:
        return {"tier": tier, "tier_size": 0, "categories": []}

    # Build per-category data from audit history
    cat_data: dict[str, dict] = {}
    for cat in tier_cats:
        cat_data[cat.value] = {
            "category": cat.value,
            "scanned": False,
            "last_seen": None,
            "scan_count": 0,
            "detection_rates": [],
        }

    for entry in scan_entries:
        ts = entry.get("timestamp", "")
        cats_in_entry = set(entry.get("categories", []))
        for cat_val in cats_in_entry:
            if cat_val in cat_data:
                info = cat_data[cat_val]
                info["scanned"] = True
                info["scan_count"] += 1
                if not info["last_seen"] or ts > info["last_seen"]:
                    info["last_seen"] = ts
                pr = entry.get("pass_rate")
                if pr is not None:
                    info["detection_rates"].append(pr)

    results = []
    for info in cat_data.values():
        avg_rate = None
        if info["detection_rates"]:
            avg_rate = round(
                sum(info["detection_rates"]) / len(info["detection_rates"]), 1
            )
        results.append(
            {
                "category": info["category"],
                "scanned": info["scanned"],
                "last_seen": _short_date(info["last_seen"])
                if info["last_seen"]
                else None,
                "scan_count": info["scan_count"],
                "avg_detection": avg_rate,
            }
        )

    results.sort(key=lambda r: (not r["scanned"], r["category"]))

    scanned_count = sum(1 for r in results if r["scanned"])
    return {
        "tier": tier,
        "tier_size": len(results),
        "scanned": scanned_count,
        "missing": len(results) - scanned_count,
        "coverage_pct": round(scanned_count / len(results) * 100, 1)
        if results
        else 0.0,
        "categories": results,
    }


@click.command("coverage")
@click.option(
    "--tier",
    default="northam",
    show_default=True,
    type=click.Choice(sorted(VALID_TIERS), case_sensitive=False),
    help="Tier to evaluate coverage for.",
)
@click.option(
    "--scanner-label",
    "scanner_label",
    default=None,
    help="Restrict to a specific scanner label.",
)
@click.option(
    "--audit-log",
    default="results/audit.jsonl",
    show_default=True,
    help="Path to audit.jsonl written by evadex scan.",
)
@click.option(
    "--show-all",
    "show_all",
    is_flag=True,
    default=False,
    help="Show all categories (default: only untested ones).",
)
@click.option(
    "--missing-only",
    "missing_only",
    is_flag=True,
    default=False,
    help="Show only categories never tested (overrides --show-all).",
)
def coverage(
    tier: str,
    scanner_label: Optional[str],
    audit_log: str,
    show_all: bool,
    missing_only: bool,
) -> None:
    """Show which tier categories have evasion test coverage vs gaps.

    Reads audit.jsonl to determine which payload categories have been included
    in at least one scan. Categories never tested are highlighted as gaps —
    useful for prioritising what to add to your scan rotation.

    \b
    Examples:
      evadex coverage                              # northam tier coverage
      evadex coverage --tier core                  # broader tier
      evadex coverage --show-all                   # all categories with status
      evadex coverage --missing-only               # only untested categories
      evadex coverage --scanner-label siphon-prod  # filter by scanner
    """
    audit_path = Path(audit_log)
    data = _build_coverage(audit_path, tier, scanner_label)

    if data["tier_size"] == 0:
        err_console.print(f"[red]Unknown or empty tier: {tier!r}[/red]")
        sys.exit(1)

    console = Console()

    label_str = f"  [bold]Scanner:[/bold]   {scanner_label}\n" if scanner_label else ""
    console.print()
    console.print(
        f"  [bold]Tier:[/bold]      [cyan]{tier}[/cyan] ({data['tier_size']} categories)"
    )
    if label_str:
        console.print(label_str.rstrip())

    cov = data["coverage_pct"]
    cov_colour = "green" if cov >= 80 else ("yellow" if cov >= 50 else "red")
    console.print(
        f"  [bold]Coverage:[/bold]  [{cov_colour}]{cov:.1f}%[/{cov_colour}]  "
        f"({data['scanned']} tested, {data['missing']} untested)"
    )
    console.print()

    cats = data["categories"]

    if missing_only:
        cats = [c for c in cats if not c["scanned"]]
    elif not show_all:
        # Default: show untested first (they're already sorted first), then
        # show up to 10 tested ones as a summary.
        untested = [c for c in cats if not c["scanned"]]
        tested = [c for c in cats if c["scanned"]]
        if untested:
            cats = untested + tested[:10]
            if len(tested) > 10:
                cats.append(
                    {
                        "category": f"… and {len(tested) - 10} more tested categories",
                        "scanned": True,
                        "_summary_row": True,
                    }
                )
        else:
            cats = tested

    if not cats:
        console.print(
            f"  [green]All {data['tier_size']} categories have been tested![/green]"
        )
        console.print()
        return

    table = Table(
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        pad_edge=False,
    )
    table.add_column("Status", min_width=8)
    table.add_column("Category", style="", min_width=28)
    table.add_column("Last tested", style="dim", min_width=12)
    table.add_column("Scans", justify="right", min_width=6)
    table.add_column("Avg detection", justify="right", min_width=14)

    for c in cats:
        if c.get("_summary_row"):
            table.add_row("[dim]✓[/dim]", f"[dim]{c['category']}[/dim]", "", "", "")
            continue

        if c["scanned"]:
            status = "[green]✓[/green]"
            det = c.get("avg_detection")
            det_str = (
                f"[{'green' if det >= 80 else 'yellow' if det >= 60 else 'red'}]{det:.1f}%[/]"
                if det is not None
                else "[dim]—[/dim]"
            )
            table.add_row(
                status,
                c["category"],
                c.get("last_seen") or "—",
                str(c.get("scan_count", 0)),
                det_str,
            )
        else:
            table.add_row(
                "[red]✗ gap[/red]",
                f"[bold]{c['category']}[/bold]",
                "[dim]never[/dim]",
                "0",
                "[dim]—[/dim]",
            )

    console.print(table)

    if data["missing"] > 0 and not missing_only:
        console.print()
        console.print(
            f"  [bold]Tip:[/bold] [dim]{data['missing']} untested categories above. "
            f"Add them to a scan with "
            f"[bold]evadex scan --category <name>[/bold] or run the full tier "
            f"with [bold]evadex scan --tier {tier}[/bold].[/dim]"
        )
    console.print()
