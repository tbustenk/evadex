"""evadex matches — what the scanner matched on, grouped by confidence.

Reads a scan JSON (``evadex scan ... -o scan.json``) and groups every
scanner finding stored in ``raw_response.matches`` into confidence bands.
For each band it lists which rules fired, how often, on how many variants,
and whether the rule is relevant to the payload's category (see
:mod:`evadex.core.relevance`) or is a format collision.

Only adapters that keep per-match detail in ``raw_response`` (``siphon-cli``)
produce findings here; other adapters' scans report zero matches.
"""

from __future__ import annotations

import json
import sys
import unicodedata
from collections import defaultdict

import click
from rich.console import Console
from rich.table import Table

from evadex.cli.commands.replay import _load_scan
from evadex.core.relevance import RELEVANT_SCANNER_LABELS, is_match_relevant

err_console = Console(stderr=True)

DEFAULT_BANDS = (0.9, 0.6)
_BAND_NAMES = ("high", "medium", "low")
_EXAMPLE_WIDTH = 40


def _parse_bands(ctx, param, value: str) -> tuple[float, float]:
    try:
        high, medium = (float(x) for x in value.split(","))
    except ValueError:
        raise click.BadParameter("expected two numbers, e.g. 0.9,0.6")
    if not 0.0 <= medium < high <= 1.0:
        raise click.BadParameter("need 0 <= medium < high <= 1")
    return high, medium


def _band(conf: float, bands: tuple[float, float]) -> str:
    high, medium = bands
    if conf >= high:
        return "high"
    if conf >= medium:
        return "medium"
    return "low"


def _relevance(cat_name: str, match: dict) -> str:
    """``relevant``, ``collision``, or ``unmapped`` when the map has no entry."""
    if cat_name not in RELEVANT_SCANNER_LABELS:
        return "unmapped"
    return "relevant" if is_match_relevant(cat_name, match) else "collision"


def summarize_matches(
    results: list[dict],
    bands: tuple[float, float] = DEFAULT_BANDS,
    category: str | None = None,
    min_confidence: float = 0.0,
) -> dict:
    """Group the findings in scan *results* by confidence band and rule.

    Returns ``{"bands": {...}, "rules": {band: [rule, ...]}, ...}`` where each
    rule row carries its match / variant counts, confidence range, the
    payload categories it fired on, a relevance verdict and one example of
    matched text. Rows are sorted by match count, most first.
    """
    rows: dict[tuple, dict] = {}
    band_totals = {b: {"matches": 0, "variants": set()} for b in _BAND_NAMES}
    variants_scanned = 0
    variants_with_matches = 0

    for idx, r in enumerate(results):
        cat_name = (r.get("payload") or {}).get("category", "")
        if category and cat_name != category:
            continue
        variants_scanned += 1
        raw = r.get("raw_response")
        matches = raw.get("matches") if isinstance(raw, dict) else None
        kept = False
        for m in matches or []:
            if not isinstance(m, dict):
                continue
            conf = float(m.get("confidence") or 0.0)
            if conf < min_confidence:
                continue
            kept = True
            band = _band(conf, bands)
            rule = m.get("sub_category") or m.get("category") or "(unlabelled)"
            verdict = _relevance(cat_name, m)
            key = (band, rule, m.get("category") or "", verdict)
            row = rows.get(key)
            if row is None:
                row = rows[key] = {
                    "rule": rule,
                    "scanner_category": m.get("category") or "",
                    "relevance": verdict,
                    "matches": 0,
                    "variants": set(),
                    "payload_categories": defaultdict(int),
                    "min_confidence": conf,
                    "max_confidence": conf,
                    "example": m.get("text") or "",
                    "example_technique": (r.get("variant") or {}).get("technique", ""),
                }
            row["matches"] += 1
            row["variants"].add(idx)
            row["payload_categories"][cat_name] += 1
            row["min_confidence"] = min(row["min_confidence"], conf)
            row["max_confidence"] = max(row["max_confidence"], conf)
            band_totals[band]["matches"] += 1
            band_totals[band]["variants"].add(idx)
        variants_with_matches += kept

    by_band: dict[str, list[dict]] = {b: [] for b in _BAND_NAMES}
    for (band, *_), row in rows.items():
        by_band[band].append(
            {
                **row,
                "variants": len(row["variants"]),
                "payload_categories": dict(
                    sorted(row["payload_categories"].items(), key=lambda kv: -kv[1])
                ),
                "min_confidence": round(row["min_confidence"], 4),
                "max_confidence": round(row["max_confidence"], 4),
            }
        )
    for band_rows in by_band.values():
        band_rows.sort(key=lambda row: (-row["matches"], row["rule"]))

    high, medium = bands
    return {
        "thresholds": {"high": high, "medium": medium},
        "category": category,
        "min_confidence": min_confidence,
        "variants_scanned": variants_scanned,
        "variants_with_matches": variants_with_matches,
        "bands": {
            b: {
                "matches": t["matches"],
                "variants": len(t["variants"]),
                "rules": len(by_band[b]),
            }
            for b, t in band_totals.items()
        },
        "rules": by_band,
    }


def _visible(ch: str) -> str:
    if ch == "\n":
        return "⏎"
    # Zero-width / bidi / control characters would print as nothing and make
    # an evasion look like the plain value — show where they are.
    if unicodedata.category(ch) in ("Cf", "Cc") or (ch.isspace() and ch != " "):
        return "·"
    return ch


def _clip(text: str, width: int = _EXAMPLE_WIDTH) -> str:
    text = "".join(_visible(ch) for ch in text)
    return text if len(text) <= width else text[: width - 1] + "…"


_RELEVANCE_STYLE = {
    "relevant": "[green]relevant[/green]",
    "collision": "[red]collision[/red]",
    "unmapped": "[dim]unmapped[/dim]",
}
_BAND_TITLE = {
    "high": "[bold green]High confidence[/bold green]",
    "medium": "[bold yellow]Medium confidence[/bold yellow]",
    "low": "[bold red]Low confidence[/bold red]",
}


def _print_tables(summary: dict, top: int, show_examples: bool) -> None:
    console = Console()
    high = summary["thresholds"]["high"]
    medium = summary["thresholds"]["medium"]
    ranges = {
        "high": f">= {high:g}",
        "medium": f"{medium:g} – {high:g}",
        "low": f"< {medium:g}",
    }

    overview = Table(title="Scanner matches by confidence", title_justify="left")
    overview.add_column("Band")
    overview.add_column("Confidence")
    overview.add_column("Matches", justify="right")
    overview.add_column("Variants", justify="right")
    overview.add_column("Rules", justify="right")
    for b in _BAND_NAMES:
        t = summary["bands"][b]
        overview.add_row(
            _BAND_TITLE[b],
            ranges[b],
            str(t["matches"]),
            str(t["variants"]),
            str(t["rules"]),
        )
    console.print(overview)
    console.print(
        f"{summary['variants_with_matches']} of {summary['variants_scanned']} "
        "variants had at least one match."
    )
    if show_examples:
        console.print(
            "[dim]· in an example = invisible or non-space whitespace character[/dim]"
        )

    for b in _BAND_NAMES:
        rows = summary["rules"][b]
        if not rows:
            continue
        table = Table(title=f"{_BAND_TITLE[b]} ({ranges[b]})", title_justify="left")
        table.add_column("Rule", no_wrap=True)
        table.add_column("Scanner category", style="dim", overflow="fold")
        table.add_column("Relevance", no_wrap=True)
        table.add_column("Matches", justify="right", no_wrap=True)
        table.add_column("Variants", justify="right", no_wrap=True)
        table.add_column("Conf.", justify="right", no_wrap=True)
        table.add_column("Fired on", overflow="fold")
        if show_examples:
            table.add_column("Example match", overflow="fold")
            table.add_column("Technique", style="dim")
        for row in rows[:top] if top else rows:
            lo, hi = row["min_confidence"], row["max_confidence"]
            conf = f"{lo:g}" if lo == hi else f"{lo:g}–{hi:g}"
            cats = ", ".join(
                f"{c} ({n})" for c, n in list(row["payload_categories"].items())[:3]
            )
            cells = [
                row["rule"],
                row["scanner_category"],
                _RELEVANCE_STYLE[row["relevance"]],
                str(row["matches"]),
                str(row["variants"]),
                conf,
                cats,
            ]
            if show_examples:
                cells += [_clip(row["example"]), row["example_technique"]]
            table.add_row(*cells)
        hidden = len(rows) - top if top else 0
        console.print(table)
        if hidden > 0:
            console.print(
                f"[dim]… {hidden} more rule(s); use --top 0 to show all[/dim]"
            )


@click.command("matches")
@click.argument("scan_file", type=click.Path(dir_okay=False))
@click.option(
    "--bands",
    default="0.9,0.6",
    show_default=True,
    callback=_parse_bands,
    help="High and medium thresholds: high >= first, medium >= second, low below.",
)
@click.option(
    "--category", default=None, help="Only results for this payload category."
)
@click.option(
    "--min-confidence",
    type=click.FloatRange(0.0, 1.0),
    default=0.0,
    show_default=True,
    help="Ignore matches below this confidence.",
)
@click.option(
    "--top",
    type=click.IntRange(min=0),
    default=15,
    show_default=True,
    help="Rules shown per band (0 = all). Table output only.",
)
@click.option(
    "--examples/--no-examples",
    default=True,
    show_default=True,
    help="Show one example of matched text per rule.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
def matches(
    scan_file: str,
    bands: tuple[float, float],
    category: str | None,
    min_confidence: float,
    top: int,
    examples: bool,
    fmt: str,
) -> None:
    """Show what the scanner matched on in SCAN_FILE, grouped by confidence.

    \b
    Examples:
      evadex matches results.json
      evadex matches results.json --category credit_card --top 0
      evadex matches results.json --bands 0.95,0.8 --format json
    """
    data = _load_scan(scan_file)
    summary = summarize_matches(data["results"], bands, category, min_confidence)
    if summary["variants_scanned"] == 0:
        err_console.print(
            f"[yellow]No results{' for category ' + category if category else ''} "
            f"in {scan_file}.[/yellow]",
            soft_wrap=True,
        )
    elif summary["variants_with_matches"] == 0:
        err_console.print(
            "[yellow]No scanner matches recorded. Only the siphon-cli adapter "
            "stores per-match detail in raw_response.[/yellow]",
            soft_wrap=True,
        )

    if fmt == "json":
        if not examples:
            for rows in summary["rules"].values():
                for row in rows:
                    row.pop("example", None)
                    row.pop("example_technique", None)
        sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
        return
    _print_tables(summary, top, examples)
