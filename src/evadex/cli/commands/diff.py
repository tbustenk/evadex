"""evadex diff — variant-level comparison between two scan results.

Unlike ``evadex compare`` (which summarises detection-rate deltas at the
category/technique level), ``evadex diff`` works at the individual variant
level and answers:

  * Which specific variants does the scanner now detect that it didn't before?
    (scanner improved — "newly detected")
  * Which specific variants did it used to detect but now misses?
    (scanner regressed — "newly missed")
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import click
from rich.console import Console

err_console = Console(stderr=True)


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        err_console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        err_console.print(f"[red]Invalid JSON in {path}: {e}[/red]")
        sys.exit(1)
    if not isinstance(data, dict) or "meta" not in data or "results" not in data:
        err_console.print(
            f"[red]{path} does not look like an evadex result file "
            f"(missing 'meta' or 'results' keys).[/red]"
        )
        sys.exit(1)
    return data


def _variant_key(r: dict) -> tuple:
    """Stable key identifying a specific variant across two scans."""
    return (
        r["payload"]["value"],
        r["payload"]["category"],
        r["variant"]["generator"],
        r["variant"]["technique"],
        r["variant"]["strategy"],
        r["variant"]["value"],
    )


def _top_by_category_technique(entries: list[dict], n: int = 5) -> list[dict]:
    """Return the top *n* examples grouped by (category, technique)."""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for e in entries:
        grouped[(e["category"], e["technique"])].append(e)
    # Sort groups by count desc, then pick one example per group
    sorted_groups = sorted(grouped.items(), key=lambda kv: -len(kv[1]))
    out = []
    for (cat, tech), examples in sorted_groups[:n]:
        example = examples[0]
        out.append(
            {
                "category": cat,
                "technique": tech,
                "count": len(examples),
                "example_value": example["variant_value"],
            }
        )
    return out


def build_variant_diff(data_a: dict, data_b: dict) -> dict:
    """Compute the variant-level diff between two scan result dicts.

    Returns a dict with four lists:
      - ``newly_detected``: FAIL/absent in A, PASS in B  (scanner improved)
      - ``newly_missed``:   PASS in A, FAIL/absent in B  (scanner regressed)
      - ``unchanged_detected``: PASS in both
      - ``unchanged_missed``:   non-PASS in both
    """
    idx_a = {_variant_key(r): r for r in data_a["results"]}
    idx_b = {_variant_key(r): r for r in data_b["results"]}
    all_keys = set(idx_a) | set(idx_b)

    newly_detected: list[dict] = []
    newly_missed: list[dict] = []
    unchanged_detected: list[dict] = []
    unchanged_missed: list[dict] = []

    for key in all_keys:
        r_a = idx_a.get(key)
        r_b = idx_b.get(key)
        sev_a = r_a["severity"] if r_a else "FAIL"
        sev_b = r_b["severity"] if r_b else "FAIL"
        ref = r_b or r_a

        entry = {
            "payload_value": ref["payload"]["value"],
            "category": ref["payload"]["category"],
            "generator": ref["variant"]["generator"],
            "technique": ref["variant"]["technique"],
            "strategy": ref["variant"]["strategy"],
            "variant_value": ref["variant"]["value"],
            "a_severity": sev_a,
            "b_severity": sev_b,
        }

        if sev_a != "PASS" and sev_b == "PASS":
            newly_detected.append(entry)
        elif sev_a == "PASS" and sev_b != "PASS":
            newly_missed.append(entry)
        elif sev_a == "PASS" and sev_b == "PASS":
            unchanged_detected.append(entry)
        else:
            unchanged_missed.append(entry)

    return {
        "meta_a": data_a.get("meta", {}),
        "meta_b": data_b.get("meta", {}),
        "newly_detected": newly_detected,
        "newly_missed": newly_missed,
        "unchanged_detected": unchanged_detected,
        "unchanged_missed": unchanged_missed,
        "top_newly_detected": _top_by_category_technique(newly_detected),
        "top_newly_missed": _top_by_category_technique(newly_missed),
    }


def _render_text(diff: dict, console: Console) -> None:
    nd = diff["newly_detected"]
    nm = diff["newly_missed"]
    ud = diff["unchanged_detected"]
    um = diff["unchanged_missed"]

    console.print()
    console.print("[bold]evadex diff[/bold] — variant-level comparison")
    console.print("─" * 56)
    console.print(
        f"  [green]Newly detected (scanner improved):[/green]    "
        f"[bold]{len(nd):>6,}[/bold] variants"
    )
    console.print(
        f"  [red]Newly missed (scanner regressed):[/red]     "
        f"[bold]{len(nm):>6,}[/bold] variants"
    )
    console.print(
        f"  [dim]Unchanged detected:[/dim]                  "
        f"[bold]{len(ud):>6,}[/bold] variants"
    )
    console.print(
        f"  [dim]Unchanged missed:[/dim]                    "
        f"[bold]{len(um):>6,}[/bold] variants"
    )
    console.print()

    if diff["top_newly_detected"]:
        console.print("[green]Newly detected (top categories):[/green]")
        for ex in diff["top_newly_detected"]:
            v = ex["example_value"]
            display = v[:40] + "…" if len(v) > 40 else v
            console.print(
                f"  [dim]{ex['category']}[/dim] · "
                f"[dim]{ex['technique']}[/dim] · "
                f"[cyan]{display}[/cyan]"
                + (f"  [dim]({ex['count']} variants)[/dim]" if ex["count"] > 1 else "")
            )
        console.print()

    if diff["top_newly_missed"]:
        console.print("[red]Newly missed (top categories):[/red]")
        for ex in diff["top_newly_missed"]:
            v = ex["example_value"]
            display = v[:40] + "…" if len(v) > 40 else v
            console.print(
                f"  [dim]{ex['category']}[/dim] · "
                f"[dim]{ex['technique']}[/dim] · "
                f"[cyan]{display}[/cyan]"
                + (f"  [dim]({ex['count']} variants)[/dim]" if ex["count"] > 1 else "")
            )
        console.print()

    console.print("[dim]Use --output diff.json for machine-readable output[/dim]")
    console.print("[dim]Use --format html for visual diff report[/dim]")


def _render_html(diff: dict) -> str:
    nd = diff["newly_detected"]
    nm = diff["newly_missed"]
    ud = diff["unchanged_detected"]
    um = diff["unchanged_missed"]
    meta_a = diff.get("meta_a", {})
    meta_b = diff.get("meta_b", {})

    def _rows(entries: list[dict], color: str) -> str:
        rows = []
        for e in entries[:200]:
            v = e["variant_value"].replace("&", "&amp;").replace("<", "&lt;")[:60]
            rows.append(
                f'<tr style="color:{color}">'
                f"<td>{e['category']}</td>"
                f"<td>{e['technique']}</td>"
                f"<td>{e['strategy']}</td>"
                f"<td><code>{v}</code></td>"
                f"</tr>"
            )
        return "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>evadex diff</title>
<style>
body{{font-family:monospace;background:#111;color:#ccc;padding:2rem}}
h1{{color:#fff}}h2{{color:#aaa}}
table{{border-collapse:collapse;width:100%}}
th{{background:#222;padding:.4rem .8rem;text-align:left}}
td{{padding:.3rem .8rem;border-bottom:1px solid #222}}
.stat{{display:inline-block;margin:.5rem 1rem .5rem 0}}
.nd{{color:#4c4}}  .nm{{color:#c44}}  .dim{{color:#666}}
</style></head>
<body>
<h1>evadex diff — variant-level comparison</h1>
<p class="dim">A: {meta_a.get("scanner", "file_a")} &nbsp;→&nbsp; B: {meta_b.get("scanner", "file_b")}</p>
<div>
  <span class="stat nd">&#9650; Newly detected: <strong>{len(nd):,}</strong></span>
  <span class="stat nm">&#9660; Newly missed: <strong>{len(nm):,}</strong></span>
  <span class="stat dim">Unchanged detected: {len(ud):,}</span>
  <span class="stat dim">Unchanged missed: {len(um):,}</span>
</div>
<h2>Newly detected ({len(nd):,})</h2>
<table><tr><th>Category</th><th>Technique</th><th>Strategy</th><th>Variant</th></tr>
{_rows(nd, "#4c4")}
</table>
<h2>Newly missed ({len(nm):,})</h2>
<table><tr><th>Category</th><th>Technique</th><th>Strategy</th><th>Variant</th></tr>
{_rows(nm, "#c44")}
</table>
</body></html>"""


@click.command("diff")
@click.argument("file_a", type=click.Path(exists=False))
@click.argument("file_b", type=click.Path(exists=False))
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["text", "json", "html"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format for --output. Console summary always printed to stderr.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Write machine-readable diff to this file.",
)
def diff(file_a: str, file_b: str, fmt: str, output: str | None) -> None:
    """Compare two evadex scan results at the individual variant level.

    Reports which specific variants the scanner newly detects (improved) or
    newly misses (regressed) between two runs.

    \\b
    Examples:
      evadex diff before.json after.json
      evadex diff before.json after.json --output diff.json
      evadex diff before.json after.json --format html --output diff.html
    """
    data_a = _load(file_a)
    data_b = _load(file_b)

    result = build_variant_diff(data_a, data_b)

    # Always print the text summary to stderr
    _render_text(result, err_console)

    if output:
        if fmt == "html":
            content = _render_html(result)
        else:
            # json (or text → fallback to json for file output)
            serialisable = {
                "newly_detected_count": len(result["newly_detected"]),
                "newly_missed_count": len(result["newly_missed"]),
                "unchanged_detected_count": len(result["unchanged_detected"]),
                "unchanged_missed_count": len(result["unchanged_missed"]),
                "top_newly_detected": result["top_newly_detected"],
                "top_newly_missed": result["top_newly_missed"],
                "newly_detected": result["newly_detected"],
                "newly_missed": result["newly_missed"],
            }
            content = json.dumps(serialisable, indent=2, ensure_ascii=False)

        try:
            Path(output).write_text(content, encoding="utf-8")
        except OSError as e:
            err_console.print(
                f"[red]Cannot write output file '{output}': {e.strerror}[/red]"
            )
            sys.exit(1)
        err_console.print(f"[dim]Diff written to {output}[/dim]")
