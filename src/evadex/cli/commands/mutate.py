"""evadex mutate — adaptive variant generation from bypassing results.

Reads a past ``evadex scan`` JSON, takes the variants that *bypassed* the
scanner, and breeds new evasion candidates from them via the
:class:`~evadex.mutate.engine.MutationEngine` (perturbation, intensification,
combination, crossover). Optionally re-tests the offspring against the current
scanner in one pass so you learn immediately whether the scanner has a
*neighbourhood* of blind spots around each survivor, not just the exact strings
it already missed.

The adapter wiring for ``--test`` is deliberately shared with ``evadex replay``
(same ``--tool`` / ``--url`` / ``--transport`` / ``--exe`` resolution), so a
scanner reachable by ``replay`` is reachable by ``mutate --test`` with the same
flags. ``--output`` emits a scan-format JSON so bred candidates flow straight
into ``evadex compare`` / ``evadex replay`` like any other scan.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

# Reuse replay's battle-tested scan loading + adapter resolution rather than
# re-deriving them — they already handle corrupt rows, exe auto-detection and
# the siphon-cli transport quirks.
from evadex.cli.commands.replay import (
    _auto_detect_exe,
    _load_scan,
    _reconstruct,
    _resolve_adapter_config,
)

console = Console()
err_console = Console(stderr=True)

_TYPE_STYLES = {
    "combination": "blue",
    "intensification": "yellow",
    "crossover": "magenta",
    "perturbation": "cyan",
}


# ── Candidate selection ─────────────────────────────────────────────────────
def _select_bypassed(
    results: list, category: Optional[str], limit: Optional[int]
) -> list:
    """Keep genuine survivors: not detected, no adapter error, optional filters.

    An errored original never produced a real bypass signal, so it is not
    breeding stock — mirrors ``replay --failed-only`` semantics.
    """
    out = [r for r in results if not r.detected and not r.error]
    if category:
        cat = category.lower()
        out = [r for r in out if r.payload.category.value.lower() == cat]
    if limit is not None and limit >= 0:
        out = out[:limit]
    return out


# ── Evolution ───────────────────────────────────────────────────────────────
def _evolve(
    survivors: list,
    generations: int,
    mutations_per_variant: int,
    crossover: bool,
    seed: int,
) -> list:
    """Run the mutation engine for ``generations`` rounds.

    Each round breeds ``mutations_per_variant`` offspring per candidate, dedupes
    globally by value (so we never test the same string twice), and — when
    ``crossover`` is set — splices random pairs of the round's survivors. The
    next round evolves from *this* round's fresh offspring, so pressure
    compounds generation over generation.
    """
    from evadex.mutate.engine import MutationCandidate, MutationEngine

    engine = MutationEngine(seed=seed)
    all_mutations: list = []
    seen_values: set[str] = {s.variant.value for s in survivors}
    current = [MutationCandidate.from_result(r, generation=0) for r in survivors]

    for gen in range(generations):
        fresh: list = []
        for cand in current:
            for mv in engine.mutate(cand, mutations_per_variant):
                if mv.value in seen_values:
                    continue
                seen_values.add(mv.value)
                fresh.append(mv)

        if crossover and len(current) >= 2:
            # A handful of crossovers per round — pair each candidate with a
            # deterministic partner so seeds stay reproducible.
            for i in range(len(current)):
                a = current[i]
                b = current[(i + 1) % len(current)]
                mv = engine.crossover(a, b)
                if mv and mv.value not in seen_values:
                    seen_values.add(mv.value)
                    fresh.append(mv)

        all_mutations.extend(fresh)
        err_console.print(
            f"  Generation {gen + 1}/{generations}: "
            f"[green]{len(fresh)}[/green] new variants"
        )
        if not fresh:
            break
        current = [MutationCandidate.from_mutated(mv) for mv in fresh]

    return all_mutations


# ── Testing bred variants against the current scanner ───────────────────────
async def _test_mutations(adapter, mutations: list, concurrency: int) -> dict:
    """Submit every bred variant to ``adapter``; return {value: ScanResult}.

    Concurrency and per-variant error isolation mirror ``core.engine.Engine`` /
    ``replay`` — a failed submission becomes an ERROR result, not an abort.
    """
    from evadex.core.result import ScanResult

    sem = asyncio.Semaphore(concurrency)
    results: dict = {}

    async def _one(mv) -> None:
        async with sem:
            payload = mv.source_payload
            variant = mv.to_variant()
            start = time.perf_counter()
            try:
                res = await adapter.submit(payload, variant)
                res.duration_ms = (time.perf_counter() - start) * 1000
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:  # noqa: BLE001 — engine parity
                res = ScanResult(
                    payload=payload,
                    variant=variant,
                    detected=False,
                    error=str(e),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            results[mv.value] = res

    await adapter.setup()
    try:
        tasks = [asyncio.create_task(_one(mv)) for mv in mutations]
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=err_console,
            transient=True,
        ) as progress:
            tid = progress.add_task(
                f"Testing {len(tasks)} mutations...", total=len(tasks)
            )
            for coro in asyncio.as_completed(tasks):
                await coro
                progress.advance(tid)
    finally:
        await adapter.teardown()
    return results


def _test_summary(results: dict) -> tuple[int, int, int, float]:
    detected = sum(1 for r in results.values() if r.detected and not r.error)
    errors = sum(1 for r in results.values() if r.error)
    total = len(results)
    bypassed = total - detected - errors
    rate = bypassed / total * 100 if total else 0.0
    return bypassed, detected, errors, rate


# ── ScanResult assembly for --output ────────────────────────────────────────
def _to_scan_results(mutations: list, test_results: Optional[dict]) -> list:
    """Turn bred variants into ScanResults for JsonReporter / --output.

    When ``--test`` ran we have real outcomes; otherwise the candidates are
    untested and recorded as ``detected=False`` (an honest default — they have
    not yet been shown to the scanner).
    """
    from evadex.core.result import Payload, PayloadCategory, ScanResult

    out: list = []
    for mv in mutations:
        if test_results is not None and mv.value in test_results:
            out.append(test_results[mv.value])
            continue
        payload = mv.source_payload or Payload(
            value="", category=PayloadCategory.UNKNOWN, label="mutated"
        )
        out.append(ScanResult(payload=payload, variant=mv.to_variant(), detected=False))
    return out


# ── Rendering ───────────────────────────────────────────────────────────────
def _print_table(mutations: list, test_results: Optional[dict]) -> None:
    table = Table(title="Bred Evasion Variants")
    table.add_column("Category", style="dim")
    table.add_column("Technique")
    table.add_column("Type")
    table.add_column("Gen", justify="right")
    table.add_column("Value", max_width=44, overflow="fold")
    if test_results is not None:
        table.add_column("Result", justify="center")

    for mv in mutations[:50]:
        style = _TYPE_STYLES.get(mv.mutation_type, "white")
        val = mv.value.replace("\n", " ").replace("\r", " ")
        if len(val) > 44:
            val = val[:41] + "..."
        row = [
            mv.category,
            mv.base_technique,
            f"[{style}]{mv.mutation_type}[/{style}]",
            str(mv.generation),
            val,
        ]
        if test_results is not None:
            res = test_results.get(mv.value)
            if res is None or res.error:
                row.append("[dim]?[/dim]")
            elif res.detected:
                row.append("[green]caught[/green]")
            else:
                row.append("[red]bypass[/red]")
        table.add_row(*row)

    console.print(table)
    if len(mutations) > 50:
        err_console.print(f"[dim]... and {len(mutations) - 50} more[/dim]")


def _print_summary(mutations: list, test_results: Optional[dict]) -> None:
    by_type = Counter(m.mutation_type for m in mutations)
    by_category = Counter(m.category for m in mutations)
    by_gen = Counter(m.generation for m in mutations)

    err_console.print("\n[bold]Mutation summary[/bold]")
    err_console.print(f"  Total bred: {len(mutations)}")
    err_console.print("  By type:")
    for t, n in by_type.most_common():
        err_console.print(f"    {t}: {n}")
    err_console.print("  By category (top 5):")
    for cat, n in by_category.most_common(5):
        err_console.print(f"    {cat}: {n}")
    err_console.print("  By generation:")
    for gen, n in sorted(by_gen.items()):
        err_console.print(f"    gen {gen}: {n}")
    if test_results is not None:
        bypassed, detected, errors, rate = _test_summary(test_results)
        total = len(test_results)
        err_console.print("\n[bold]Test against current scanner[/bold]")
        err_console.print(f"  [red]Bypassed: {bypassed}/{total} ({rate:.1f}%)[/red]")
        err_console.print(f"  [green]Detected: {detected}/{total}[/green]")
        if errors:
            err_console.print(f"  [yellow]Errors:   {errors}/{total}[/yellow]")
        if rate > 50:
            err_console.print(
                "\n[yellow]⚠ Majority of bred variants still bypass — the "
                "scanner has a neighbourhood of blind spots around these "
                "survivors.[/yellow]"
            )


# ── Command ─────────────────────────────────────────────────────────────────
@click.command("mutate")
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--generations",
    default=1,
    show_default=True,
    type=int,
    help="How many rounds to evolve; each round breeds from the previous one.",
)
@click.option(
    "--mutations-per-variant",
    default=5,
    show_default=True,
    type=int,
    help="Offspring bred per surviving variant, per generation (max 8).",
)
@click.option(
    "--crossover/--no-crossover",
    default=False,
    help="Also splice pairs of survivors together (crossover breeding).",
)
@click.option("--category", default=None, help="Only breed from this category.")
@click.option(
    "--limit",
    default=100,
    show_default=True,
    type=int,
    help="Max surviving variants to breed from.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Write bred variants as a scan-format JSON (feeds compare / replay).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "summary", "json"]),
    default="summary",
    show_default=True,
    help="Console output format.",
)
@click.option(
    "--seed",
    default=42,
    show_default=True,
    type=int,
    help="RNG seed — same seed + scan breeds the same variants.",
)
@click.option(
    "--test",
    "do_test",
    is_flag=True,
    default=False,
    help="Immediately submit bred variants to the current scanner.",
)
# ── adapter options (mirror evadex replay) ──────────────────────────────────
@click.option(
    "--tool",
    "-t",
    default="siphon-cli",
    show_default=True,
    help="DLP adapter for --test. Same choices as 'evadex scan'.",
)
@click.option("--exe", "executable", default=None, help="Path to scanner executable.")
@click.option(
    "--url",
    default="http://localhost:8080",
    show_default=True,
    help="Adapter base URL.",
)
@click.option(
    "--api-key", default=None, envvar="EVADEX_API_KEY", help="API key for adapter."
)
@click.option(
    "--timeout",
    default=30.0,
    show_default=True,
    type=float,
    help="Request timeout (s).",
)
@click.option(
    "--transport",
    default="cli",
    type=click.Choice(["cli", "http"]),
    show_default=True,
    help="siphon-cli transport (subprocess vs HTTP).",
)
@click.option(
    "--cmd-style",
    default=None,
    type=click.Choice(["python", "rust", "binary", "cargo"]),
    help="Adapter command style (see 'evadex scan').",
)
@click.option(
    "--min-confidence",
    default=None,
    type=float,
    help="Confidence floor passed to the adapter (0.0-1.0).",
)
@click.option(
    "--wrap-context/--no-wrap-context",
    "wrap_context",
    default=None,
    help="Embed each variant in a keyword sentence before submission. "
    "Auto-enabled for siphon-cli / --cmd-style rust unless disabled.",
)
@click.option(
    "--concurrency",
    default=32,
    show_default=True,
    type=int,
    help="Max concurrent submissions when --test is used.",
)
def mutate(
    scan_file: str,
    generations: int,
    mutations_per_variant: int,
    crossover: bool,
    category: Optional[str],
    limit: int,
    output: Optional[str],
    fmt: str,
    seed: int,
    do_test: bool,
    tool: str,
    executable: Optional[str],
    url: str,
    api_key: Optional[str],
    timeout: float,
    transport: str,
    cmd_style: Optional[str],
    min_confidence: Optional[float],
    wrap_context: Optional[bool],
    concurrency: int,
) -> None:
    """Evolve bypassing variants from a past scan into new evasion candidates.

    SCAN_FILE is a JSON file produced by 'evadex scan'. Variants that bypassed
    the scanner are used as breeding stock; offspring are produced by
    perturbation, intensification, combination and (optionally) crossover.

    \b
    Examples:
      # Breed candidates from every survivor and print a summary
      evadex mutate results/scans/pre_fix.json

      # Breed and immediately test them against the current scanner
      evadex mutate results/scans/pre_fix.json --test --tool siphon-cli

      # Focus on credit cards, evolve 3 generations with crossover, save output
      evadex mutate pre_fix.json --category credit_card --generations 3 \\
          --crossover -o results/mutations/gen3.json
    """
    from evadex.core.registry import get_adapter, load_builtins

    load_builtins()

    data = _load_scan(scan_file)
    originals = _reconstruct(data)
    survivors = _select_bypassed(originals, category, limit)
    if not survivors:
        err_console.print(
            "[yellow]No bypassing variants to breed from"
            + (f" in category '{category}'" if category else "")
            + ".[/yellow]"
        )
        raise SystemExit(0)

    err_console.print(f"\n[bold]evadex mutate[/bold] — {Path(scan_file).name}")
    err_console.print(
        f"[dim]Breeding stock: {len(survivors)} surviving variant(s) · "
        f"{generations} generation(s) · {mutations_per_variant} per variant"
        + (" · crossover" if crossover else "")
        + f" · seed {seed}[/dim]"
    )

    mutations = _evolve(survivors, generations, mutations_per_variant, crossover, seed)
    if not mutations:
        err_console.print("[yellow]No new variants were bred.[/yellow]")
        raise SystemExit(0)

    err_console.print(f"\nTotal bred: [bold]{len(mutations)}[/bold] variant(s)")

    # ── Optional: test against the current scanner ──────────────────────────
    test_results: Optional[dict] = None
    if do_test:
        auto_wrap = tool == "siphon-cli" or cmd_style == "rust"
        effective_wrap = auto_wrap if wrap_context is None else wrap_context
        if tool in ("dlpscan-cli", "siphon-cli") and not executable:
            executable = _auto_detect_exe(tool)
        config = _resolve_adapter_config(
            url=url,
            api_key=api_key,
            timeout=timeout,
            executable=executable,
            transport=transport,
            cmd_style=cmd_style,
            wrap_context=effective_wrap,
            min_confidence=min_confidence,
        )
        try:
            adapter = get_adapter(tool, config)
        except KeyError as e:
            err_console.print(f"[red]{e.args[0]}[/red]")
            raise SystemExit(1)
        if not asyncio.run(adapter.health_check()):
            err_console.print(
                f"[red]Health check failed for adapter '{tool}'. "
                f"Is the scanner installed / reachable?[/red]"
            )
            raise SystemExit(1)
        test_results = asyncio.run(_test_mutations(adapter, mutations, concurrency))

    # ── Console output ──────────────────────────────────────────────────────
    if fmt == "table":
        _print_table(mutations, test_results)
    elif fmt == "summary":
        _print_summary(mutations, test_results)
    elif fmt == "json":
        payload = {
            "meta": {
                "source_scan": Path(scan_file).name,
                "generations": generations,
                "mutations_per_variant": mutations_per_variant,
                "crossover": crossover,
                "seed": seed,
                "total": len(mutations),
                "tested": test_results is not None,
            },
            "mutations": [m.to_dict() for m in mutations],
        }
        if test_results is not None:
            bypassed, detected, errors, rate = _test_summary(test_results)
            payload["meta"]["bypass_rate"] = round(rate, 1)
            payload["meta"]["bypassed"] = bypassed
            payload["meta"]["detected"] = detected
        sys.stdout.buffer.write(
            json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
        )
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()

    # ── Scan-format output for compare / replay ─────────────────────────────
    if output:
        from evadex.reporters.json_reporter import JsonReporter

        scan_results = _to_scan_results(mutations, test_results)
        label = f"mutate({Path(scan_file).stem})"
        rendered = JsonReporter(scanner_label=label).render(scan_results)
        out_path = Path(output)
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        err_console.print(f"[dim]Bred variants written to {output}[/dim]")
        if test_results is not None:
            err_console.print(
                f"[dim]Diff against the source with: "
                f"evadex compare {scan_file} {output}[/dim]"
            )
