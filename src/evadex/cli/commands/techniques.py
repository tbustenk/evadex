"""evadex techniques — show per-technique success rates from the audit log."""
from __future__ import annotations

import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.feedback.technique_history import (
    filter_stats,
    has_history,
    load_technique_history,
)


err_console = Console(stderr=True)


def _trend_arrow(delta: Optional[float]) -> str:
    if delta is None:
        return "[dim]—[/dim]"
    pct = delta * 100
    if pct > 0.5:
        return f"[green]↑ +{pct:.1f}%[/green]"
    if pct < -0.5:
        return f"[red]↓ {pct:+.1f}%[/red]"
    return f"[yellow]→ {pct:+.1f}%[/yellow]"


@click.command(name="techniques")
@click.option(
    "--audit-log", default="results/audit.jsonl",
    show_default=True,
    help="Path to the audit log (audit.jsonl) to read history from.",
)
@click.option(
    "--last", "last_n", default=10, type=int, show_default=True,
    help="Aggregate only the most recent N audit entries.",
)
@click.option(
    "--top", type=int, default=None,
    help="Show only the top N techniques by latest success rate.",
)
@click.option(
    "--category", default=None,
    help="Restrict to techniques whose name contains this substring "
         "(rough category match — technique names embed their family, "
         "e.g. 'unicode_zwsp', 'encoding_base64').",
)
@click.option(
    "--min-runs", type=int, default=1, show_default=True,
    help="Only show techniques with at least N data points.",
)
def techniques(
    audit_log: str, last_n: int, top: Optional[int],
    category: Optional[str], min_runs: int,
) -> None:
    """Show per-technique scanner-detection success rates from history.

    "Success" here is from the *scanner's* perspective — the fraction of
    variants the scanner caught. Lower numbers are better evasions and
    are the techniques the ``--evasion-mode adversarial`` setting will
    favour.

    \b
    Examples:
      evadex techniques                           # all techniques
      evadex techniques --top 10                  # top 10 by latest success
      evadex techniques --category credit_card    # name-substring filter
      evadex techniques --min-runs 3              # require 3+ data points
    """
    if not has_history(audit_log):
        err_console.print(
            "[yellow]No technique history found in "
            f"{audit_log}.[/yellow]\n"
            "Run a few scans with [cyan]--audit-log[/cyan] set first to "
            "build technique history. Until then, [cyan]--evasion-mode "
            "weighted/adversarial[/cyan] will fall back to random selection."
        )
        sys.exit(0)

    stats = load_technique_history(audit_log, last_n=last_n)
    if category:
        stats = {k: v for k, v in stats.items() if category.lower() in k.lower()}
    rows = filter_stats(stats, min_runs=min_runs, top=top)

    if not rows:
        err_console.print(
            "[yellow]No techniques matched the filter criteria.[/yellow]"
        )
        sys.exit(0)

    table = Table(
        title=f"Technique scanner-detection rates  "
              f"(last {last_n} runs, {len(rows)} techniques)"
    )
    table.add_column("Technique", style="cyan", no_wrap=True)
    table.add_column("Latest", justify="right")
    table.add_column("Avg", justify="right")
    table.add_column("Runs", justify="right")
    table.add_column("Trend", justify="right")
    for s in rows:
        table.add_row(
            s.technique,
            f"{s.latest_success * 100:.1f}%",
            f"{s.average_success * 100:.1f}%",
            str(s.runs),
            _trend_arrow(s.trend),
        )
    Console().print(table)
