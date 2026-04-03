import json
import sys
from collections import defaultdict

import click
from rich.console import Console

from evadex.reporters.compare_reporter import CompareReporter
from evadex.reporters.compare_html_reporter import CompareHtmlReporter

err_console = Console(stderr=True)


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        err_console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)
    except json.JSONDecodeError as e:
        err_console.print(f"[red]Invalid JSON in {path}: {e}[/red]")
        sys.exit(1)


def _index(results: list[dict]) -> dict:
    """Key: (payload_value, category, generator, technique, strategy)"""
    idx = {}
    for r in results:
        key = (
            r["payload"]["value"],
            r["payload"]["category"],
            r["variant"]["generator"],
            r["variant"]["technique"],
            r["variant"]["strategy"],
        )
        idx[key] = r
    return idx


def build_comparison(data_a: dict, data_b: dict) -> dict:
    """Build a structured comparison dict from two scan result dicts."""
    meta_a = data_a["meta"]
    meta_b = data_b["meta"]

    idx_a = _index(data_a["results"])
    idx_b = _index(data_b["results"])
    all_keys = set(idx_a) | set(idx_b)

    # Per-category aggregates
    cats_a = meta_a.get("summary_by_category", {})
    cats_b = meta_b.get("summary_by_category", {})
    all_cats = sorted(set(cats_a) | set(cats_b))
    by_category = []
    for cat in all_cats:
        a = cats_a.get(cat, {"pass": 0, "fail": 0, "error": 0})
        b = cats_b.get(cat, {"pass": 0, "fail": 0, "error": 0})
        a_tot = a["pass"] + a["fail"] + a["error"]
        b_tot = b["pass"] + b["fail"] + b["error"]
        a_rate = round(a["pass"] / a_tot * 100, 1) if a_tot else 0.0
        b_rate = round(b["pass"] / b_tot * 100, 1) if b_tot else 0.0
        by_category.append({
            "category": cat,
            "a_pass": a["pass"], "a_fail": a["fail"], "a_rate": a_rate,
            "b_pass": b["pass"], "b_fail": b["fail"], "b_rate": b_rate,
            "delta": round(b_rate - a_rate, 1),
        })

    # Per-technique aggregates
    tech_a: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
    tech_b: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
    for r in data_a["results"]:
        k = (r["variant"]["generator"], r["variant"]["technique"])
        tech_a[k][r["severity"]] += 1
    for r in data_b["results"]:
        k = (r["variant"]["generator"], r["variant"]["technique"])
        tech_b[k][r["severity"]] += 1
    all_techs = sorted(set(tech_a) | set(tech_b))
    by_technique = []
    for gen, tech in all_techs:
        a = tech_a[(gen, tech)]
        b = tech_b[(gen, tech)]
        a_tot = a["pass"] + a["fail"] + a["error"]
        b_tot = b["pass"] + b["fail"] + b["error"]
        a_rate = round(a["pass"] / a_tot * 100, 1) if a_tot else 0.0
        b_rate = round(b["pass"] / b_tot * 100, 1) if b_tot else 0.0
        delta = round(b_rate - a_rate, 1)
        if delta != 0:
            by_technique.append({
                "generator": gen, "technique": tech,
                "a_rate": a_rate, "b_rate": b_rate, "delta": delta,
            })
    by_technique.sort(key=lambda x: x["delta"])

    # Per-variant diffs
    diffs = []
    for key in sorted(all_keys):
        r_a = idx_a.get(key)
        r_b = idx_b.get(key)
        sev_a = r_a["severity"] if r_a else "absent"
        sev_b = r_b["severity"] if r_b else "absent"
        if sev_a != sev_b:
            ref = r_a or r_b
            diffs.append({
                "payload_label":  ref["payload"]["label"],
                "category":       ref["payload"]["category"],
                "generator":      ref["variant"]["generator"],
                "technique":      ref["variant"]["technique"],
                "transform_name": ref["variant"]["transform_name"],
                "strategy":       ref["variant"]["strategy"],
                "a_severity":     sev_a,
                "b_severity":     sev_b,
            })

    return {
        "label_a":  meta_a.get("scanner") or "file_a",
        "label_b":  meta_b.get("scanner") or "file_b",
        "overall": {
            "a_total":  meta_a["total"],  "b_total":  meta_b["total"],
            "a_pass":   meta_a["pass"],   "b_pass":   meta_b["pass"],
            "a_fail":   meta_a["fail"],   "b_fail":   meta_b["fail"],
            "a_errors": meta_a["error"],  "b_errors": meta_b["error"],
            "a_rate":   meta_a["pass_rate"],
            "b_rate":   meta_b["pass_rate"],
            "delta":    round(meta_b["pass_rate"] - meta_a["pass_rate"], 1),
        },
        "by_category":  by_category,
        "by_technique": by_technique,
        "diffs":        diffs,
    }


@click.command()
@click.argument("file_a", type=click.Path(exists=False))
@click.argument("file_b", type=click.Path(exists=False))
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html"]),
              default="json", show_default=True, help="Output format")
@click.option("--output", "-o", default=None, help="Write to file (default: stdout)")
@click.option("--label-a", default=None,
              help="Override label for first file (defaults to scanner field in JSON)")
@click.option("--label-b", default=None,
              help="Override label for second file (defaults to scanner field in JSON)")
def compare(file_a, file_b, fmt, output, label_a, label_b):
    """Compare two evadex scan result JSON files and report differences."""
    data_a = _load(file_a)
    data_b = _load(file_b)

    comparison = build_comparison(data_a, data_b)

    if label_a:
        comparison["label_a"] = label_a
    if label_b:
        comparison["label_b"] = label_b

    if fmt == "html":
        reporter = CompareHtmlReporter()
    else:
        reporter = CompareReporter()

    rendered = reporter.render(comparison)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(rendered)
        err_console.print(f"[dim]Comparison report written to {output}[/dim]")
    else:
        sys.stdout.buffer.write(rendered.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
