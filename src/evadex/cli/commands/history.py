"""evadex history — show past scan and falsepos run results."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

err_console = Console(stderr=True)


def _load_audit(audit_path: Path) -> list[dict]:
    if not audit_path.exists():
        return []
    entries = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _fmt_rate(entry: dict) -> str:
    if entry.get("type") == "scan":
        rate = entry.get("pass_rate")
        if rate is None:
            return "—"
        return f"{rate:.1f}%"
    elif entry.get("type") == "falsepos":
        rate = entry.get("fp_rate")
        if rate is None:
            return "—"
        return f"{rate:.1f}% FP"
    return "—"


def _fmt_total(entry: dict) -> str:
    if entry.get("type") == "scan":
        return str(entry.get("total", "—"))
    elif entry.get("type") == "falsepos":
        return str(entry.get("total_tested", "—"))
    return "—"


def _fmt_date(ts: str) -> str:
    """Shorten ISO timestamp to a readable date+time."""
    if not ts:
        return "—"
    # e.g. "2026-04-14T12:34:56.789+00:00" → "2026-04-14 12:34"
    try:
        date_part, time_part = ts[:19].split("T")
        return f"{date_part} {time_part[:5]}"
    except Exception:
        return ts[:16]


@click.command("history")
@click.option("--last", default=20, show_default=True, type=int,
              help="Number of most recent entries to show.")
@click.option("--type", "entry_type", default=None,
              type=click.Choice(["scan", "falsepos"]),
              help="Filter by entry type.")
@click.option("--results-dir", default="results", show_default=True,
              help="Path to results directory (must contain audit.jsonl).")
def history(last: int, entry_type: Optional[str], results_dir: str) -> None:
    """Show history of past scan and false positive runs.

    \b
    Examples:
      evadex history
      evadex history --last 10
      evadex history --type scan
      evadex history --type falsepos
    """
    audit_path = Path(results_dir) / "audit.jsonl"
    entries = _load_audit(audit_path)

    if not entries:
        err_console.print(
            f"[yellow]No audit entries found in {audit_path}.[/yellow]\n"
            "Run [bold]evadex scan[/bold] or [bold]evadex falsepos[/bold] to start "
            "building history, or use [bold]evadex history --results-dir PATH[/bold] "
            "to point to a different results directory."
        )
        sys.exit(0)

    if entry_type:
        entries = [e for e in entries if e.get("type") == entry_type]

    # Most-recent first, then truncate
    entries = list(reversed(entries))[:last]

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Date",          style="dim",    min_width=16)
    table.add_column("Type",          style="cyan",   min_width=8)
    table.add_column("Scanner Label", style="",       min_width=18, overflow="fold")
    table.add_column("Total",         style="",       min_width=6,  justify="right")
    table.add_column("Rate",          style="",       min_width=10, justify="right")
    table.add_column("Commit",        style="dim",    min_width=8)

    for e in entries:
        rate_str = _fmt_rate(e)
        entry_t = e.get("type", "?")

        if entry_t == "scan":
            rate = e.get("pass_rate", 0)
            colour = "green" if rate >= 80 else ("yellow" if rate >= 60 else "red")
        else:
            rate = e.get("fp_rate", 0)
            colour = "red" if rate >= 50 else ("yellow" if rate >= 20 else "green")

        table.add_row(
            _fmt_date(e.get("timestamp", "")),
            entry_t,
            e.get("scanner_label", "") or "—",
            _fmt_total(e),
            f"[{colour}]{rate_str}[/{colour}]",
            e.get("commit_hash") or "—",
        )

    console = Console()
    console.print(table)
    console.print(
        f"\n[dim]Showing {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
        f"from {audit_path}[/dim]"
    )
