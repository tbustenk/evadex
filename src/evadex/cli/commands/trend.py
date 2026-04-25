"""evadex trend — ASCII chart of detection/FP rate over time."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

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


def _get_rate(entry: dict) -> Optional[float]:
    if entry.get("type") == "scan":
        return entry.get("pass_rate")
    elif entry.get("type") == "falsepos":
        return entry.get("fp_rate")
    return None


def _short_date(ts: str) -> str:
    """Return MM-DD from ISO timestamp."""
    if not ts:
        return "??"
    try:
        # e.g. "2026-04-14T12:34:56+00:00" → "04-14"
        date_part = ts[:10]
        parts = date_part.split("-")
        return f"{parts[1]}-{parts[2]}"
    except Exception:
        return ts[:5]


def _render_chart(points: list[tuple[str, float]], width: int = 60, height: int = 12) -> str:
    """Render a simple ASCII line chart.

    *points* is a list of (label, value) tuples, value in [0, 100].
    Returns a multi-line string ready for printing.
    """
    if not points:
        return "(no data)"

    values = [v for _, v in points]
    lo = min(values)
    hi = max(values)
    # Expand range slightly so points don't crowd the top/bottom edge
    lo = max(0.0, lo - 5)
    hi = min(100.0, hi + 5)
    if hi == lo:
        lo = max(0.0, hi - 10)
        hi = min(100.0, lo + 10)

    # Build grid: height rows × width cols, each cell is a space
    grid = [[" "] * width for _ in range(height)]

    n = len(points)
    # Map each point to a column (evenly distributed)
    def col(i: int) -> int:
        if n == 1:
            return width // 2
        return round(i * (width - 1) / (n - 1))

    def row(v: float) -> int:
        # 0 → bottom row (height-1), 100 → top row (0)
        frac = (v - lo) / (hi - lo) if hi > lo else 0.5
        return height - 1 - round(frac * (height - 1))

    # Draw connecting lines between adjacent points
    for i in range(len(points) - 1):
        c1, c2 = col(i), col(i + 1)
        r1, r2 = row(values[i]), row(values[i + 1])
        # Bresenham-style horizontal walk
        dc = c2 - c1
        dr = r2 - r1
        steps = max(abs(dc), abs(dr)) or 1
        for s in range(steps + 1):
            c = c1 + round(s * dc / steps)
            r = r1 + round(s * dr / steps)
            if 0 <= r < height and 0 <= c < width:
                grid[r][c] = "·"

    # Overwrite data points with a solid marker
    for i, (_, v) in enumerate(points):
        r, c = row(v), col(i)
        if 0 <= r < height and 0 <= c < width:
            grid[r][c] = "●"

    # Y-axis labels (right-aligned, 5 chars)
    lines = []
    for r in range(height):
        y_val = hi - (hi - lo) * r / (height - 1)
        y_label = f"{y_val:4.0f}% "
        lines.append(y_label + "".join(grid[r]))

    # X-axis tick labels (first and last, and every ~10 points)
    label_row = " " * 7  # align with y-axis prefix
    label_indices = [0]
    step = max(1, n // 6)
    label_indices += list(range(step, n - 1, step))
    if n > 1:
        label_indices.append(n - 1)
    label_indices = sorted(set(label_indices))

    x_axis_chars = [" "] * width
    x_label_chars = [" "] * width
    for idx in label_indices:
        c = col(idx)
        if c < width:
            x_axis_chars[c] = "┴"
        lbl = _short_date(points[idx][0])
        # Centre the label on the column
        start = max(0, c - len(lbl) // 2)
        for j, ch in enumerate(lbl):
            if start + j < width:
                x_label_chars[start + j] = ch

    lines.append(" " * 7 + "─" * width)
    lines.append(label_row + "".join(x_label_chars))

    return "\n".join(lines)


@click.command("trend")
@click.option("--last", default=30, show_default=True, type=int,
              help="Number of most recent entries to include in the chart.")
@click.option("--type", "entry_type", default="scan",
              type=click.Choice(["scan", "falsepos"]),
              show_default=True,
              help="Which metric to chart: scan detection rate or false positive rate.")
@click.option("--scanner-label", "scanner_label", default=None,
              help="Filter to a specific scanner label.")
@click.option("--results-dir", default="results", show_default=True,
              help="Path to results directory (must contain audit.jsonl).")
@click.option("--width", default=60, show_default=True, type=int,
              help="Chart width in characters.")
@click.option("--height", default=12, show_default=True, type=int,
              help="Chart height in rows.")
def trend(
    last: int,
    entry_type: str,
    scanner_label: Optional[str],
    results_dir: str,
    width: int,
    height: int,
) -> None:
    """Show an ASCII trend chart of detection or false positive rate over time.

    Reads audit log entries produced by --audit-log in scan/falsepos runs.
    Use alongside evadex history to spot regressions across scanner releases.

    \b
    Examples:
      evadex trend                                    # detection rate chart
      evadex trend --type falsepos                    # false positive rate chart
      evadex trend --last 20 --scanner-label prod     # filter by scanner label
    """
    audit_path = Path(results_dir) / "audit.jsonl"
    entries = _load_audit(audit_path)

    if not entries:
        err_console.print(
            f"[yellow]No audit entries found in {audit_path}.[/yellow]\n"
            "Run [bold]evadex scan[/bold] or [bold]evadex falsepos[/bold] to start "
            "building history, or use [bold]evadex trend --results-dir PATH[/bold] "
            "to point to a different results directory."
        )
        sys.exit(0)

    # Filter by type
    entries = [e for e in entries if e.get("type") == entry_type]

    # Filter by scanner label
    if scanner_label:
        entries = [e for e in entries if e.get("scanner_label") == scanner_label]

    if not entries:
        label_hint = f" with label '{scanner_label}'" if scanner_label else ""
        err_console.print(
            f"[yellow]No {entry_type} entries found{label_hint} in {audit_path}.[/yellow]"
        )
        sys.exit(0)

    # Oldest → most recent, then limit
    entries = entries[-last:]

    points: list[tuple[str, float]] = []
    for e in entries:
        rate = _get_rate(e)
        if rate is None:
            continue
        points.append((e.get("timestamp", ""), rate))

    if not points:
        err_console.print("[yellow]No rate data to chart.[/yellow]")
        sys.exit(0)

    console = Console()
    metric_name = "Detection Rate" if entry_type == "scan" else "False Positive Rate"
    title_parts = [f"{metric_name} over time"]
    if scanner_label:
        title_parts.append(f"  [dim](label: {scanner_label})[/dim]")
    console.print(f"\n[bold]{''.join(title_parts)}[/bold]")
    console.print()
    chart = _render_chart(points, width=width, height=height)
    console.print(chart)
    console.print(
        f"\n[dim]{len(points)} data point(s) from {audit_path}[/dim]"
    )
