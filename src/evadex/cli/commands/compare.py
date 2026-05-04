import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import click
from rich.console import Console

from evadex.reporters.compare_reporter import CompareReporter
from evadex.reporters.compare_html_reporter import CompareHtmlReporter

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
            f"(missing 'meta' or 'results' keys). "
            f"Generate one with: evadex scan ... --output <file>[/red]"
        )
        sys.exit(1)
    return data


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
    """Build a structured comparison dict from two scan result dicts.

    Raises ValueError with a descriptive message if either argument is not a
    valid evadex result dict (missing 'meta' or 'results' keys, or meta is
    missing required counters).
    """
    for label, data in (("file_a", data_a), ("file_b", data_b)):
        if not isinstance(data, dict):
            raise ValueError(f"{label}: expected a dict, got {type(data).__name__!r}")
        for key in ("meta", "results"):
            if key not in data:
                raise ValueError(
                    f"{label}: missing required key {key!r}. "
                    "Pass a file produced by 'evadex scan'."
                )
        meta = data["meta"]
        for mkey in ("total", "pass", "fail", "error", "pass_rate"):
            if mkey not in meta:
                raise ValueError(
                    f"{label}: meta is missing required field {mkey!r}. "
                    "The file may have been produced by an incompatible evadex version."
                )

    meta_a = data_a["meta"]
    meta_b = data_b["meta"]

    idx_a = _index(data_a["results"])
    idx_b = _index(data_b["results"])
    all_keys = set(idx_a) | set(idx_b)

    # Per-category aggregates
    cats_a = meta_a.get("summary_by_category") or {}
    cats_b = meta_b.get("summary_by_category") or {}
    all_cats = sorted(set(cats_a) | set(cats_b))
    by_category = []
    for cat in all_cats:
        a = cats_a.get(cat, {"pass": 0, "fail": 0, "error": 0})
        b = cats_b.get(cat, {"pass": 0, "fail": 0, "error": 0})
        a_tot = a["pass"] + a["fail"] + a["error"]
        b_tot = b["pass"] + b["fail"] + b["error"]
        a_rate = round(a["pass"] / a_tot * 100, 1) if a_tot else 0.0
        b_rate = round(b["pass"] / b_tot * 100, 1) if b_tot else 0.0
        is_new     = a_tot == 0 and b_tot > 0
        is_removed = a_tot > 0  and b_tot == 0
        by_category.append({
            "category": cat,
            "a_pass": a["pass"], "a_fail": a["fail"], "a_rate": a_rate,
            "b_pass": b["pass"], "b_fail": b["fail"], "b_rate": b_rate,
            "delta": round(b_rate - a_rate, 1),
            "is_new": is_new,
            "is_removed": is_removed,
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
        conf_a = r_a.get("confidence") if r_a else None
        conf_b = r_b.get("confidence") if r_b else None

        severity_changed = sev_a != sev_b
        confidence_changed = (
            isinstance(conf_a, (int, float))
            and isinstance(conf_b, (int, float))
            and round(abs(conf_b - conf_a), 4) >= 0.01
        )

        if severity_changed or confidence_changed:
            ref = r_a or r_b
            entry = {
                "payload_label":  ref["payload"]["label"],
                "category":       ref["payload"]["category"],
                "generator":      ref["variant"]["generator"],
                "technique":      ref["variant"]["technique"],
                "transform_name": ref["variant"]["transform_name"],
                "strategy":       ref["variant"]["strategy"],
                "a_severity":     sev_a,
                "b_severity":     sev_b,
            }
            if conf_a is not None:
                entry["a_confidence"] = round(float(conf_a), 4)
            if conf_b is not None:
                entry["b_confidence"] = round(float(conf_b), 4)
            if confidence_changed:
                entry["confidence_delta"] = round(float(conf_b) - float(conf_a), 4)
            diffs.append(entry)

    # Build verdict for use in reporters
    overall_delta = round(meta_b["pass_rate"] - meta_a["pass_rate"], 1)
    n_improved  = sum(1 for c in by_category if c["delta"] > 0 and not c["is_new"])
    n_regressed = sum(1 for c in by_category if c["delta"] < 0 and not c["is_removed"])
    n_new       = sum(1 for c in by_category if c["is_new"])
    worst_reg   = sorted([c for c in by_category if c["delta"] < 0], key=lambda x: x["delta"])
    if overall_delta > 0:
        verdict = "IMPROVED"
    elif overall_delta < 0:
        verdict = "REGRESSED"
    else:
        verdict = "UNCHANGED"

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
            "delta":    overall_delta,
        },
        "by_category":  by_category,
        "by_technique": by_technique,
        "diffs":        diffs,
        "verdict": {
            "verdict":     verdict,
            "n_improved":  n_improved,
            "n_regressed": n_regressed,
            "n_new":       n_new,
            "worst_regressed": worst_reg[0]["category"] if worst_reg else None,
        },
    }


def _print_visual_diff(comparison: dict, console: Console) -> None:
    """Print trend-arrow comparison summary to *console* (stderr)."""
    overall = comparison["overall"]
    label_a = comparison["label_a"]
    label_b = comparison["label_b"]
    delta   = overall["delta"]
    a_rate  = overall["a_rate"]
    b_rate  = overall["b_rate"]

    def _arrow(d: float) -> str:
        if d > 0:
            return "[green]▲[/green]"
        if d < 0:
            return "[red]▼[/red]"
        return "→"

    def _sign(d: float) -> str:
        return f"+{d:.1f}pp" if d > 0 else f"{d:.1f}pp"

    console.print()
    console.print(f"[bold]evadex compare[/bold]  [dim]{label_a}[/dim] → [dim]{label_b}[/dim]")
    console.print("─" * 65)

    # Overall detection rate row
    rate_color = "green" if delta >= 0 else "red"
    console.print(
        f"  [dim]Detection Rate[/dim]    "
        f"[blue]{a_rate:>6.1f}%[/blue]  →  [cyan]{b_rate:>6.1f}%[/cyan]"
        f"   {_arrow(delta)} [{rate_color}]{_sign(delta)}[/{rate_color}]"
        + ("  [green]✓ improved[/green]" if delta > 0
           else "  [red]✗ regressed[/red]" if delta < 0
           else "  [dim]→ unchanged[/dim]")
    )

    # Per-category summary
    by_cat    = comparison.get("by_category", [])
    improved  = [c for c in by_cat if c["delta"] > 0 and not c.get("is_new")]
    regressed = [c for c in by_cat if c["delta"] < 0 and not c.get("is_removed")]
    new_cats  = [c for c in by_cat if c.get("is_new")]
    removed   = [c for c in by_cat if c.get("is_removed")]
    unchanged = [c for c in by_cat if c["delta"] == 0
                 and not c.get("is_new") and not c.get("is_removed")]

    if by_cat:
        console.print()
        console.print("  [bold]Category Changes[/bold]")
        for c in sorted(improved, key=lambda x: -x["delta"])[:5]:
            console.print(
                f"    [green]✓ improved[/green]  "
                f"[dim]{c['category']:<30}[/dim]  "
                f"[blue]{c['a_rate']:.1f}%[/blue] → [cyan]{c['b_rate']:.1f}%[/cyan]  "
                f"[green]+{c['delta']:.1f}pp[/green]"
            )
        for c in sorted(regressed, key=lambda x: x["delta"])[:5]:
            warn = "  [yellow]⚠ investigate[/yellow]" if abs(c["delta"]) >= 10 else ""
            console.print(
                f"    [red]✗ regressed[/red]  "
                f"[dim]{c['category']:<30}[/dim]  "
                f"[blue]{c['a_rate']:.1f}%[/blue] → [cyan]{c['b_rate']:.1f}%[/cyan]  "
                f"[red]{c['delta']:.1f}pp[/red]{warn}"
            )
        for c in new_cats[:3]:
            console.print(
                f"    [green]+ new[/green]        "
                f"[dim]{c['category']:<30}[/dim]  "
                f"[dim]—[/dim] → [cyan]{c['b_rate']:.1f}%[/cyan]  [dim]new category[/dim]"
            )
        for c in removed[:3]:
            console.print(
                f"    [dim]- removed[/dim]    "
                f"[dim]{c['category']:<30}[/dim]  "
                f"[blue]{c['a_rate']:.1f}%[/blue] → [dim]—[/dim]  [dim]removed[/dim]"
            )
        if unchanged:
            console.print(
                f"    [dim]→ unchanged[/dim]  [dim]{len(unchanged)} "
                f"categor{'y' if len(unchanged) == 1 else 'ies'} unchanged[/dim]"
            )

    # Per-technique diff (>5pp delta only)
    big_tech = [t for t in comparison.get("by_technique", []) if abs(t["delta"]) >= 5]
    if big_tech:
        console.print()
        console.print("  [bold]Technique Changes[/bold] [dim](>5pp delta)[/dim]")
        for t in sorted(big_tech, key=lambda x: x["delta"]):
            td = t["delta"]
            col = "green" if td > 0 else "red"
            note = "[green]✓ Siphon improved[/green]" if td > 0 else "[red]✗ regression[/red]"
            console.print(
                f"    [{col}]{'▲' if td > 0 else '▼'}[/{col}] "
                f"[dim]{t['technique']:<28}[/dim]  "
                f"[blue]{t['a_rate']:.1f}%[/blue] → [cyan]{t['b_rate']:.1f}%[/cyan]  "
                f"[{col}]{_sign(td)}[/{col}]  {note}"
            )

    # Verdict
    console.print()
    console.print("─" * 65)
    v = comparison.get("verdict", {})
    verdict_str = v.get("verdict", "UNCHANGED")
    n_imp = (v.get("n_improved") or 0) + (v.get("n_new") or 0)
    n_reg = v.get("n_regressed") or 0
    worst = v.get("worst_regressed")

    if verdict_str == "IMPROVED":
        vtag = "[green]IMPROVED[/green]"
        summary = f"detection up {abs(delta):.1f}pp"
    elif verdict_str == "REGRESSED":
        vtag = "[red]REGRESSED[/red]"
        summary = f"detection down {abs(delta):.1f}pp"
    else:
        vtag = "[dim]UNCHANGED[/dim]"
        summary = "no overall change"

    cat_note = ""
    if n_imp and n_reg:
        cat_note = f", {n_imp} improved, {n_reg} regressed"
    elif n_imp:
        cat_note = f", {n_imp} categor{'y' if n_imp == 1 else 'ies'} improved"
    elif n_reg:
        cat_note = f", {n_reg} categor{'y' if n_reg == 1 else 'ies'} regressed"

    investigate = f" ({worst} — investigate)" if worst and n_reg else ""

    console.print(f"Verdict: {vtag} — {summary}{cat_note}{investigate}")
    console.print("─" * 65)
    console.print()


def _parse_since(since_str: str) -> datetime:
    """Parse a --since value into a UTC datetime.

    Accepts relative periods (``7d``, ``2w``, ``1m``) or absolute dates
    (``2026-04-20``).
    """
    since_str = since_str.strip()
    m = re.fullmatch(r"(\d+)([dwm])", since_str, re.IGNORECASE)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        now = datetime.now(timezone.utc)
        if unit == "d":
            return now - timedelta(days=n)
        if unit == "w":
            return now - timedelta(weeks=n)
        if unit == "m":
            return now - timedelta(days=n * 30)
    try:
        dt = datetime.fromisoformat(since_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    raise click.BadParameter(
        f"Cannot parse {since_str!r}. "
        "Use a relative period like '7d', '2w', '1m', or a date like '2026-04-20'.",
        param_hint="'--since'",
    )


def _find_scan_before(before_dt: datetime,
                      scan_dir: Path = Path("results/scans")) -> str | None:
    """Return the most-recent scan file archived before *before_dt*."""
    if not scan_dir.exists():
        return None
    _TS_RE = re.compile(r"scan_(\d{8}T\d{6}Z)_")
    best_path: str | None = None
    best_dt: datetime | None = None
    for p in scan_dir.glob("scan_*.json"):
        m = _TS_RE.match(p.name)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts < before_dt and (best_dt is None or ts > best_dt):
            best_dt = ts
            best_path = str(p)
    return best_path


def _find_latest_scan(scan_dir: Path = Path("results/scans")) -> str | None:
    """Return the most-recent scan file in *scan_dir*."""
    if not scan_dir.exists():
        return None
    _TS_RE = re.compile(r"scan_(\d{8}T\d{6}Z)_")
    best_path: str | None = None
    best_dt: datetime | None = None
    for p in scan_dir.glob("scan_*.json"):
        m = _TS_RE.match(p.name)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if best_dt is None or ts > best_dt:
            best_dt = ts
            best_path = str(p)
    return best_path


@click.command()
@click.argument("files", nargs=-1, type=click.Path(exists=False))
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html"]),
              default="json", show_default=True, help="Output format")
@click.option("--output", "-o", default=None, help="Write to file (default: stdout)")
@click.option("--label-a", default=None,
              help="Override label for first file (defaults to scanner field in JSON)")
@click.option("--label-b", default=None,
              help="Override label for second file (defaults to scanner field in JSON)")
@click.option("--since", "since_str", default=None,
              help="Auto-resolve the baseline (file_a) as the most recent scan before "
                   "this date/period (e.g. '7d', '2w', '2026-04-20'). "
                   "With one positional arg it is file_b; with none, latest is file_b.")
@click.option("--c2-url", "c2_url", default=None, envvar="EVADEX_C2_URL",
              help="Siphon-C2 management-plane URL. The comparison is pushed to "
                   "POST /v1/evadex/compare. Failures log a warning; never fail the run.")
@click.option("--c2-key", "c2_key", default=None, envvar="EVADEX_C2_KEY",
              help="API key sent as 'x-api-key' to Siphon-C2. Falls back to EVADEX_C2_KEY.")
def compare(files, fmt, output, label_a, label_b, since_str, c2_url, c2_key):
    """Compare two evadex scan result JSON files and report differences.

    \b
    Usage:
      evadex compare a.json b.json              # compare two explicit files
      evadex compare b.json --since 7d          # b.json vs scan from 7 days ago
      evadex compare --since 7d                 # latest scan vs 7 days ago
      evadex compare --since 2026-04-20         # latest vs specific date
      evadex compare a.json b.json --format html --output diff.html
    """
    # ── Resolve file_a and file_b ─────────────────────────────────────────────
    if since_str is not None:
        since_dt = _parse_since(since_str)
        if len(files) == 0:
            resolved_b = _find_latest_scan()
            if resolved_b is None:
                err_console.print(
                    "[red]--since: no archived scans found in results/scans/.[/red]"
                )
                sys.exit(1)
        elif len(files) == 1:
            resolved_b = files[0]
        else:
            # Both provided + --since: use them directly (--since is ignored)
            resolved_b = files[1]
        resolved_a = _find_scan_before(since_dt)
        if resolved_a is None:
            err_console.print(
                f"[red]--since {since_str!r}: no archived scan found before "
                f"{since_dt.date().isoformat()} in results/scans/.[/red]"
            )
            sys.exit(1)
        err_console.print(
            f"[dim]--since {since_str!r}: "
            f"[bold]{Path(resolved_a).name}[/bold] → "
            f"[bold]{Path(resolved_b).name}[/bold][/dim]"
        )
        path_a, path_b = resolved_a, resolved_b
    else:
        if len(files) != 2:
            err_console.print(
                "[red]compare requires two positional arguments, or use --since: "
                "evadex compare a.json b.json[/red]"
            )
            sys.exit(1)
        path_a, path_b = files[0], files[1]

    data_a = _load(path_a)
    data_b = _load(path_b)

    comparison = build_comparison(data_a, data_b)

    if label_a:
        comparison["label_a"] = label_a
    if label_b:
        comparison["label_b"] = label_b

    # Always print the visual diff to stderr
    _print_visual_diff(comparison, err_console)

    if fmt == "html":
        reporter = CompareHtmlReporter()
    else:
        reporter = CompareReporter()

    rendered = reporter.render(comparison)

    if output:
        try:
            with open(output, "w", encoding="utf-8") as f:
                f.write(rendered)
        except OSError as e:
            err_console.print(f"[red]Cannot write output file '{output}': {e.strerror}[/red]")
            sys.exit(1)
        err_console.print(f"[dim]Comparison report written to {output}[/dim]")
    else:
        click.echo(rendered)

    # ── Siphon-C2 push ────────────────────────────────────────────────────────
    from evadex.reporters.c2_reporter import push_comparison, resolve_c2_config
    _c2_url, _c2_key = resolve_c2_config(c2_url, c2_key)
    if _c2_url:
        push_comparison(_c2_url, _c2_key, comparison=comparison)
