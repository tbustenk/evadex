"""evadex export — export scan results as CSV, Markdown, or Parquet."""

from __future__ import annotations

import csv
import io
import json
import sys

import click
from rich.console import Console

err_console = Console(stderr=True)


def _load(path: str) -> tuple[list[dict], dict]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        err_console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        err_console.print(f"[red]Invalid JSON in {path}: {e}[/red]")
        sys.exit(1)
    if not isinstance(data, dict) or "results" not in data:
        err_console.print(
            f"[red]{path} does not look like an evadex result file "
            "(missing 'results' key).[/red]"
        )
        sys.exit(1)
    return data["results"], data.get("meta", {})


def _to_csv(results: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["category", "technique", "value", "detected", "confidence"])
    for r in results:
        writer.writerow(
            [
                r["payload"]["category"],
                r["variant"]["technique"] or r["variant"]["generator"],
                r["payload"]["value"],
                r["detected"],
                r.get("confidence", ""),
            ]
        )
    return buf.getvalue()


def _to_parquet(results: list[dict], output_path: str) -> int:
    try:
        import pandas as pd
    except ImportError:
        err_console.print(
            "[red]pandas is required for parquet export: pip install pandas[/red]"
        )
        sys.exit(1)
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        err_console.print(
            "[red]pyarrow is required for parquet export: pip install pyarrow[/red]"
        )
        sys.exit(1)

    rows = []
    for r in results:
        rows.append(
            {
                "category": r["payload"]["category"],
                "sub_category": r["payload"].get("sub_category", ""),
                "technique": r["variant"].get("technique")
                or r["variant"].get("generator", ""),
                "strategy": r["variant"].get("strategy", ""),
                "value": r["payload"]["value"],
                "detected": bool(r.get("detected", False)),
                "confidence": r.get("confidence"),
                "scanner": r.get("scanner", ""),
                "elapsed_ms": r.get("elapsed_ms"),
            }
        )
    df = pd.DataFrame(rows)
    df.to_parquet(output_path, index=False, engine="pyarrow")
    return len(rows)


def _to_markdown(results: list[dict], meta: dict) -> str:
    scanner = meta.get("scanner") or "unknown"
    total = meta.get("total", len(results))
    pass_rate = meta.get("pass_rate", 0.0)

    lines: list[str] = [
        f"# evadex Export — {scanner}",
        "",
        f"**Scanner:** {scanner}  **Total:** {total}  **Detection rate:** {pass_rate}%",
        "",
        "| Category | Technique | Value | Detected | Confidence |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        cat = r["payload"]["category"]
        tech = r["variant"]["technique"] or r["variant"]["generator"]
        val = r["payload"]["value"].replace("|", "\\|")
        detected = "yes" if r["detected"] else "no"
        conf = r.get("confidence")
        conf_str = f"{conf:.3f}" if conf is not None else "—"
        lines.append(f"| `{cat}` | `{tech}` | `{val}` | {detected} | {conf_str} |")
    return "\n".join(lines) + "\n"


@click.command("export")
@click.argument("input_file", type=click.Path(exists=False))
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["csv", "markdown", "parquet"]),
    default="csv",
    show_default=True,
    help="Output format",
)
@click.option("--output", "-o", default=None, help="Write to file (default: stdout)")
@click.option(
    "--only-bypassed",
    "only_bypassed",
    is_flag=True,
    default=False,
    help="Only include variants that evaded detection (severity=fail)",
)
def export_cmd(
    input_file: str, fmt: str, output: str | None, only_bypassed: bool
) -> None:
    """Export scan results as CSV, Markdown, or Parquet for sharing or BI.

    \b
    Examples:
      evadex export scan.json --format csv --output findings.csv
      evadex export scan.json --format markdown --output findings.md
      evadex export scan.json --format parquet --output findings.parquet
      evadex export scan.json --format csv --only-bypassed
    """
    results, meta = _load(input_file)

    if only_bypassed:
        results = [r for r in results if not r.get("detected", False)]

    if fmt == "parquet":
        out_path = output or "evadex_export.parquet"
        n = _to_parquet(results, out_path)
        err_console.print(f"[dim]Exported {n} results to {out_path}[/dim]")
        return

    if fmt == "csv":
        rendered = _to_csv(results)
    else:
        rendered = _to_markdown(results, meta)

    if output:
        try:
            with open(output, "w", encoding="utf-8", newline="") as f:
                f.write(rendered)
        except OSError as e:
            err_console.print(
                f"[red]Cannot write output file '{output}': {e.strerror}[/red]"
            )
            sys.exit(1)
        err_console.print(f"[dim]Exported {len(results)} results to {output}[/dim]")
    else:
        click.echo(rendered, nl=False)
