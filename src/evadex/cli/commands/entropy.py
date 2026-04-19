"""evadex entropy — targeted harness for Siphon's entropy scan modes.

Siphon (dlpscan-rs) classifies high-entropy tokens with three gating modes:

    gated       — flag only if a keyword (``secret``, ``key``, ``token``, …)
                  appears within 80 chars of the token.
    assignment  — flag only if the token is preceded by an assignment pattern
                  (``KEY=``, ``"key":``, ``export KEY=``, …).
    all         — flag every high-entropy token regardless of context.

This command submits a fixed set of high-entropy secret payloads in three
contexts (bare / gated / assignment) and reports which evadex entropy
category is caught under which mode. It's the quickest way to validate a
scanner configuration before running a full ``evadex scan``.
"""
from __future__ import annotations

import asyncio
import json
import math
import sys
from collections import Counter
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.core.registry import get_adapter, get_generator, load_builtins
from evadex.core.result import Payload, Variant
from evadex.payloads.builtins import ENTROPY_CATEGORIES, get_payloads


err_console = Console(stderr=True)


MODE_CHOICES = ["gated", "assignment", "all", "off"]


# The contexts we submit for every bare entropy value.
#
# "bare"       — value on its own; only `all` mode should catch this.
# "gated"      — value next to a keyword Siphon looks for; `gated` & `all` catch.
# "assignment" — value in `KEY=VALUE`; `assignment` & `all` catch.
CONTEXTS = ("bare", "gated", "assignment")


def _shannon_entropy(s: str) -> float:
    """Per-character Shannon entropy, matching Siphon's ``char_entropy``."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _wrap_context(value: str, context: str) -> str:
    """Return *value* wrapped for submission in the named context."""
    if context == "bare":
        return value
    if context == "gated":
        return f"api_key: {value}"
    if context == "assignment":
        return f"SECRET_TOKEN={value}"
    raise ValueError(f"Unknown context: {context!r}")


def _core_token(value: str) -> str:
    """Strip ``KEY=`` / ``keyword:`` prefixes to expose the raw secret."""
    for sep in ("=", ": ", ":"):
        if sep in value:
            tail = value.split(sep, 1)[1].strip()
            if tail:
                return tail
    return value


async def _submit_one(adapter, payload: Payload, text: str) -> dict:
    variant = Variant(
        value=text,
        generator="entropy",
        technique="entropy_probe",
        transform_name="Entropy probe",
        strategy="text",
    )
    try:
        result = await adapter.submit(payload, variant)
        return {
            "detected": bool(result.detected),
            "confidence": result.confidence,
            "error": result.error,
            "entropy_classification": result.entropy_classification,
        }
    except Exception as exc:
        return {
            "detected": False,
            "confidence": None,
            "error": str(exc),
            "entropy_classification": None,
        }


async def _probe_payloads(adapter, payloads, concurrency: int) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)

    async def probe(payload: Payload, context: str) -> dict:
        text = _wrap_context(_core_token(payload.value), context)
        async with sem:
            res = await _submit_one(adapter, payload, text)
        return {
            "category": payload.category.value,
            "label": payload.label,
            "context": context,
            "submitted": text,
            "core_entropy": round(_shannon_entropy(_core_token(payload.value)), 3),
            **res,
        }

    tasks = [probe(p, ctx) for p in payloads for ctx in CONTEXTS]
    return list(await asyncio.gather(*tasks))


async def _probe_evasions(adapter, payloads, concurrency: int) -> list[dict]:
    """Run entropy_evasion variants and report which techniques defeat detection."""
    try:
        generator = get_generator("entropy_evasion")
    except KeyError:
        return []

    sem = asyncio.Semaphore(concurrency)

    async def probe(payload: Payload, variant: Variant) -> dict:
        async with sem:
            try:
                result = await adapter.submit(payload, variant)
                detected = bool(result.detected)
                error = result.error
            except Exception as exc:
                detected = False
                error = str(exc)
        return {
            "category": payload.category.value,
            "label": payload.label,
            "technique": variant.technique,
            "transform_name": variant.transform_name,
            "submitted": variant.value,
            "detected": detected,
            "error": error,
        }

    tasks = []
    for p in payloads:
        for variant in generator.generate(p.value):
            tasks.append(probe(p, variant))
    return list(await asyncio.gather(*tasks))


def _summarise(results: list[dict]) -> dict:
    """Group detection counts by (mode-like) context."""
    summary: dict = {}
    for r in results:
        ctx = r["context"]
        cat = r["category"]
        bucket = summary.setdefault(cat, {c: {"tested": 0, "detected": 0} for c in CONTEXTS})
        bucket[ctx]["tested"] += 1
        if r["detected"]:
            bucket[ctx]["detected"] += 1
    return summary


def _render_table(summary: dict, *, mode_filter: Optional[str]) -> Table:
    table = Table(title="Entropy detection by context")
    table.add_column("Category", style="cyan")
    table.add_column("Bare (all)", justify="right")
    table.add_column("Gated (gated/all)", justify="right")
    table.add_column("Assignment (assign/all)", justify="right")

    def cell(stat):
        t, d = stat["tested"], stat["detected"]
        if t == 0:
            return "—"
        colour = "green" if d == t else ("red" if d == 0 else "yellow")
        return f"[{colour}]{d}/{t}[/{colour}]"

    for cat in sorted(summary):
        b = summary[cat]
        table.add_row(cat, cell(b["bare"]), cell(b["gated"]), cell(b["assignment"]))
    if mode_filter:
        table.caption = f"mode: {mode_filter}"
    return table


def _render_evasion_table(evasion_results: list[dict]) -> Optional[Table]:
    if not evasion_results:
        return None
    # Bucket by technique: detected / total
    tech_stats: dict = {}
    for r in evasion_results:
        t = r["technique"]
        s = tech_stats.setdefault(t, {"tested": 0, "defeated": 0, "transform": r["transform_name"]})
        s["tested"] += 1
        if not r["detected"]:
            s["defeated"] += 1

    table = Table(title="Evasion techniques vs entropy detection")
    table.add_column("Technique", style="cyan")
    table.add_column("Transform")
    table.add_column("Defeated / Tested", justify="right")

    for name, s in sorted(tech_stats.items(), key=lambda kv: -kv[1]["defeated"]):
        total = s["tested"]
        defeated = s["defeated"]
        colour = "red" if defeated == total else ("yellow" if defeated else "green")
        table.add_row(name, s["transform"], f"[{colour}]{defeated}/{total}[/{colour}]")
    return table


@click.command("entropy")
@click.option("--tool", "-t", default="siphon", show_default=True,
              help="DLP adapter to probe.")
@click.option("--url", default="http://localhost:8000", show_default=True,
              help="Base URL for HTTP-based adapters.")
@click.option("--api-key", default=None, envvar="EVADEX_API_KEY",
              help="API key (falls back to EVADEX_API_KEY).")
@click.option("--mode", "mode", type=click.Choice(MODE_CHOICES), default=None,
              help="Siphon entropy mode the adapter is configured for. "
                   "When set, only contexts that mode is expected to catch "
                   "are submitted and a per-mode coverage score is reported.")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="Request timeout in seconds.")
@click.option("--concurrency", default=5, show_default=True, type=int,
              help="Max concurrent scanner requests.")
@click.option("--include-evasion/--no-evasion", default=True, show_default=True,
              help="Run entropy_evasion variants and report which techniques "
                   "defeat the scanner's entropy detection.")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]),
              default="table", show_default=True, help="Output format.")
@click.option("--output", "-o", default=None, metavar="PATH",
              help="Write JSON report to file.")
def entropy(
    tool: str,
    url: str,
    api_key: Optional[str],
    mode: Optional[str],
    timeout: float,
    concurrency: int,
    include_evasion: bool,
    fmt: str,
    output: Optional[str],
) -> None:
    """Test Siphon's entropy scan modes (gated, assignment, all, off).

    Submits each entropy payload in three contexts — bare, gated (next to a
    keyword), and in a KEY=VALUE assignment — and reports which mode catches
    which category. Pass --mode off to confirm that no entropy detection
    occurs when the scanner has entropy disabled. Also runs the
    ``entropy_evasion`` generator so you can see which evasion techniques
    defeat entropy-based detection.

    \b
    Examples:
      # Sanity-check all three modes at once
      evadex entropy --tool siphon --url http://localhost:8000 --api-key $EVADEX_API_KEY

      # When Siphon is configured with entropy_scan=gated
      evadex entropy --tool siphon --mode gated

      # JSON report
      evadex entropy --tool siphon -o entropy_report.json -f json
    """
    load_builtins()

    payloads = get_payloads(ENTROPY_CATEGORIES, include_heuristic=True)
    if not payloads:
        err_console.print("[red]No entropy payloads registered. Build broken?[/red]")
        sys.exit(1)

    config: dict = {"base_url": url, "timeout": timeout}
    if api_key:
        config["api_key"] = api_key
    try:
        adapter = get_adapter(tool, config)
    except KeyError as e:
        err_console.print(f"[red]{e.args[0]}[/red]")
        sys.exit(1)

    if not asyncio.run(adapter.health_check()):
        err_console.print(
            f"[red]Health check failed for adapter '{tool}'. "
            f"Is the scanner reachable at {url}?[/red]"
        )
        sys.exit(1)

    err_console.print(
        f"[dim]Probing [bold]{tool}[/bold] at {url} — "
        f"{len(payloads)} payloads × {len(CONTEXTS)} contexts[/dim]"
    )

    probe_results = asyncio.run(_probe_payloads(adapter, payloads, concurrency))
    evasion_results = (
        asyncio.run(_probe_evasions(adapter, payloads, concurrency))
        if include_evasion else []
    )

    summary = _summarise(probe_results)

    # Expected-detection map: which contexts SHOULD be caught per mode.
    expected_by_mode = {
        "off":        set(),
        "gated":      {"gated"},
        "assignment": {"assignment"},
        "all":        set(CONTEXTS),
    }
    mode_assessment: dict = {}
    if mode:
        expected = expected_by_mode[mode]
        caught_expected = 0
        total_expected = 0
        for cat, buckets in summary.items():
            for ctx, stat in buckets.items():
                if ctx in expected:
                    total_expected += stat["tested"]
                    caught_expected += stat["detected"]
        coverage = round(
            (caught_expected / total_expected * 100) if total_expected else 0.0,
            1,
        )
        mode_assessment = {
            "mode": mode,
            "expected_contexts": sorted(expected),
            "total_expected": total_expected,
            "detected_expected": caught_expected,
            "coverage_pct": coverage,
        }

    # Render
    table = _render_table(summary, mode_filter=mode)
    err_console.print(table)
    evasion_table = _render_evasion_table(evasion_results)
    if evasion_table is not None:
        err_console.print(evasion_table)
    if mode_assessment:
        ma = mode_assessment
        colour = "green" if ma["coverage_pct"] >= 90 else ("yellow" if ma["coverage_pct"] >= 50 else "red")
        err_console.print(
            f"\n[{colour}]mode={ma['mode']}: "
            f"{ma['detected_expected']}/{ma['total_expected']} "
            f"({ma['coverage_pct']}%) of expected detections[/{colour}]"
        )

    report = {
        "tool": tool,
        "url": url,
        "mode": mode,
        "contexts": list(CONTEXTS),
        "summary": summary,
        "probe_results": probe_results,
        "evasion_results": evasion_results,
        "mode_assessment": mode_assessment or None,
    }

    if fmt == "json" or output:
        rendered = json.dumps(report, indent=2, ensure_ascii=False)
        if output:
            try:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(rendered)
            except OSError as e:
                err_console.print(
                    f"[red]Cannot write output file '{output}': {e.strerror}[/red]"
                )
                sys.exit(1)
            err_console.print(f"[dim]Report written to {output}[/dim]")
        else:
            sys.stdout.write(rendered + "\n")
