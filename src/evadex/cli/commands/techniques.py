"""evadex techniques — show per-technique success rates from the audit log."""

from __future__ import annotations

import collections
import csv
import io
import json
import sys
from pathlib import Path
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


def _load_category_history(audit_log: str, last_n: int = 10) -> dict[str, dict]:
    """Load audit log and aggregate detection rates by payload category.

    Returns a dict of {category: {'latest': float, 'avg': float, 'runs': int, 'trend': float|None}}.
    """
    path = Path(audit_log)
    if not path.exists():
        return {}

    # Each entry in the audit log has 'results' list with {payload.category, severity}
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
    except OSError:
        return {}

    if not entries:
        return {}

    # Use last N entries
    entries = entries[-last_n:]

    # Per-entry, per-category pass rate
    cat_runs: dict[str, list[float]] = collections.defaultdict(list)
    for entry in entries:
        results = entry.get("results") or []
        if not results:
            continue
        cat_counts: dict[str, dict] = collections.defaultdict(
            lambda: {"pass": 0, "total": 0}
        )
        for r in results:
            cat = (
                (r.get("payload") or {}).get("category")
                or r.get("category")
                or "unknown"
            )
            cat_counts[cat]["total"] += 1
            if (r.get("severity") or r.get("status")) == "PASS":
                cat_counts[cat]["pass"] += 1
        for cat, counts in cat_counts.items():
            if counts["total"] > 0:
                cat_runs[cat].append(counts["pass"] / counts["total"])

    out = {}
    for cat, rates in cat_runs.items():
        if not rates:
            continue
        latest = rates[-1]
        avg = sum(rates) / len(rates)
        trend = None
        if len(rates) >= 2:
            trend = rates[-1] - rates[-2]
        out[cat] = {"latest": latest, "avg": avg, "runs": len(rates), "trend": trend}
    return out


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
    "--audit-log",
    default="results/audit.jsonl",
    show_default=True,
    help="Path to the audit log (audit.jsonl) to read history from.",
)
@click.option(
    "--last",
    "last_n",
    default=10,
    type=int,
    show_default=True,
    help="Aggregate only the most recent N audit entries.",
)
@click.option(
    "--top",
    type=int,
    default=None,
    help="Show only the top N techniques by latest success rate.",
)
@click.option(
    "--category",
    default=None,
    help="Substring match on technique *name* — not the PII payload "
    "category. Technique names embed their family ('unicode_zwsp', "
    "'encoding_base64', 'morse_space_sep'); a value like 'unicode' "
    "filters to all unicode-family techniques. Run "
    "`evadex list-techniques` for the full name list.",
)
@click.option(
    "--min-runs",
    type=int,
    default=1,
    show_default=True,
    help="Only show techniques with at least N data points.",
)
@click.option(
    "--compare",
    "compare_labels",
    nargs=2,
    default=None,
    metavar="LABEL_A LABEL_B",
    help="Show technique rates for two scanner labels side by side. "
    "Pass both labels: --compare siphon-pre-fix siphon-post-fix",
)
@click.option(
    "--export",
    "export_path",
    default=None,
    metavar="PATH",
    help="Export technique data as CSV to PATH.",
)
@click.option(
    "--by-category",
    "by_category",
    is_flag=True,
    default=False,
    help="Show detection rate per payload category instead of per technique.",
)
def techniques(
    audit_log: str,
    last_n: int,
    top: Optional[int],
    category: Optional[str],
    min_runs: int,
    compare_labels: Optional[tuple[str, str]],
    export_path: Optional[str],
    by_category: bool,
) -> None:
    """Show per-technique scanner-detection success rates from history.

    Lower rates mean better evasion — the techniques evadex scan missed most.
    Use to identify the weakest points in your scanner's detection coverage.

    \b
    Examples:
      evadex techniques                                # all techniques, from history
      evadex techniques --top 10                       # top 10 most-evading techniques
      evadex techniques --category credit_card         # filter by category name
      evadex techniques --compare pre-fix post-fix     # side-by-side scanner labels
      evadex techniques --export techniques.csv        # export as CSV
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

    if by_category:
        cat_stats = _load_category_history(audit_log, last_n=last_n)
        if not cat_stats:
            err_console.print(
                "[yellow]No category history found in "
                f"{audit_log}.[/yellow]\n"
                "Run a few scans first to build history."
            )
            sys.exit(0)

        rows = sorted(cat_stats.items(), key=lambda x: x[1]["latest"])
        if top:
            rows = rows[:top]

        def _trend_arrow_cat(trend) -> str:
            if trend is None:
                return "[dim]—[/dim]"
            pct = trend * 100
            if pct > 0.5:
                return f"[green]↑ +{pct:.1f}%[/green]"
            if pct < -0.5:
                return f"[red]↓ {pct:+.1f}%[/red]"
            return f"[yellow]→ {pct:+.1f}%[/yellow]"

        table = Table(
            title=f"Category detection rates  (last {last_n} runs, {len(rows)} categories)"
        )
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Latest", justify="right")
        table.add_column("7d Avg", justify="right")
        table.add_column("Runs", justify="right")
        table.add_column("Trend", justify="right")
        for cat, s in rows:
            table.add_row(
                cat,
                f"{s['latest'] * 100:.1f}%",
                f"{s['avg'] * 100:.1f}%",
                str(s["runs"]),
                _trend_arrow_cat(s["trend"]),
            )
        Console().print(table)
        return

    # ── Compare mode ──────────────────────────────────────────────────────────
    if compare_labels is not None:
        label_a, label_b = compare_labels
        stats_a = load_technique_history(
            audit_log, last_n=last_n, scanner_label=label_a
        )
        stats_b = load_technique_history(
            audit_log, last_n=last_n, scanner_label=label_b
        )

        if category:
            stats_a = {
                k: v for k, v in stats_a.items() if category.lower() in k.lower()
            }
            stats_b = {
                k: v for k, v in stats_b.items() if category.lower() in k.lower()
            }

        all_techs = sorted(set(stats_a) | set(stats_b))
        if not all_techs:
            err_console.print(
                f"[yellow]No technique history found for labels "
                f"'{label_a}' or '{label_b}' in {audit_log}.[/yellow]"
            )
            sys.exit(0)

        table = Table(
            title=f"Technique rates: {label_a} vs {label_b}  (last {last_n} runs)"
        )
        table.add_column("Technique", style="cyan", no_wrap=True)
        table.add_column(f"{label_a} Rate", justify="right")
        table.add_column(f"{label_b} Rate", justify="right")
        table.add_column("Delta", justify="right")

        rows = []
        for tech in all_techs:
            sa = stats_a.get(tech)
            sb = stats_b.get(tech)
            rate_a = sa.latest_success * 100 if sa else None
            rate_b = sb.latest_success * 100 if sb else None
            if rate_a is not None and rate_b is not None:
                delta = rate_b - rate_a
            else:
                delta = None
            rows.append((tech, rate_a, rate_b, delta))

        if top:
            rows = rows[:top]

        for tech, rate_a, rate_b, delta in rows:
            a_str = f"{rate_a:.1f}%" if rate_a is not None else "[dim]—[/dim]"
            b_str = f"{rate_b:.1f}%" if rate_b is not None else "[dim]—[/dim]"
            if delta is None:
                d_str = "[dim]—[/dim]"
            elif delta > 0.5:
                d_str = f"[green]+{delta:.1f}pp[/green]"
            elif delta < -0.5:
                d_str = f"[red]{delta:.1f}pp[/red]"
            else:
                d_str = f"[yellow]{delta:+.1f}pp[/yellow]"
            table.add_row(tech, a_str, b_str, d_str)

        Console().print(table)

        if export_path:
            _export_compare_csv(export_path, label_a, label_b, rows)
            err_console.print(f"[dim]Compare data exported to {export_path}[/dim]")
        return

    # ── Standard (single-label) mode ─────────────────────────────────────────
    stats = load_technique_history(audit_log, last_n=last_n)
    if category:
        stats = {k: v for k, v in stats.items() if category.lower() in k.lower()}
    rows_single = filter_stats(stats, min_runs=min_runs, top=top)

    if not rows_single:
        if category:
            err_console.print(
                f"[yellow]No technique names contain "
                f"'{category}'.[/yellow]\n"
                "[dim]--category is a substring match on the technique "
                "*name* (e.g. 'unicode', 'encoding', 'zwsp'), not the PII "
                "payload category. Run [cyan]evadex list-techniques[/cyan] "
                "to see available technique names.[/dim]"
            )
        else:
            err_console.print(
                "[yellow]No techniques matched the filter criteria.[/yellow]"
            )
        sys.exit(0)

    table = Table(
        title=f"Technique scanner-detection rates  "
        f"(last {last_n} runs, {len(rows_single)} techniques)"
    )
    table.add_column("Technique", style="cyan", no_wrap=True)
    table.add_column("Latest", justify="right")
    table.add_column("Avg", justify="right")
    table.add_column("Runs", justify="right")
    table.add_column("Trend", justify="right")
    for s in rows_single:
        table.add_row(
            s.technique,
            f"{s.latest_success * 100:.1f}%",
            f"{s.average_success * 100:.1f}%",
            str(s.runs),
            _trend_arrow(s.trend),
        )
    Console().print(table)

    if export_path:
        _export_single_csv(export_path, rows_single)
        err_console.print(f"[dim]Technique data exported to {export_path}[/dim]")


def _export_single_csv(path: str, rows: list) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["technique", "latest_rate", "avg_rate", "runs", "trend_delta"])
    for s in rows:
        trend = f"{s.trend * 100:.2f}" if s.trend is not None else ""
        writer.writerow(
            [
                s.technique,
                f"{s.latest_success * 100:.2f}",
                f"{s.average_success * 100:.2f}",
                s.runs,
                trend,
            ]
        )
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())


def _export_compare_csv(
    path: str,
    label_a: str,
    label_b: str,
    rows: list[tuple],
) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["technique", f"{label_a}_rate", f"{label_b}_rate", "delta_pp"])
    for tech, rate_a, rate_b, delta in rows:
        writer.writerow(
            [
                tech,
                f"{rate_a:.2f}" if rate_a is not None else "",
                f"{rate_b:.2f}" if rate_b is not None else "",
                f"{delta:.2f}" if delta is not None else "",
            ]
        )
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(buf.getvalue())
