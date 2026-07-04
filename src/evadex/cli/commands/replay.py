"""evadex replay — re-run the exact payloads from a past scan.

Unlike ``evadex scan``, which *regenerates* variants from the built-in
generators, ``replay`` reads a previous scan's JSON, reconstructs every
``(Payload, Variant)`` pair verbatim (same obfuscated value, same generator /
technique / strategy) and re-submits it to the *current* scanner. That makes it
the tool for answering one question precisely: "did my scanner change fix the
things that were bypassing before, without breaking anything that worked?"

Because a scan JSON is just a list of ``ScanResult.to_dict()`` snapshots, we can
round-trip each record through ``ScanResult.from_dict`` to recover the original
payload/variant/outcome, submit the variant again, and diff old-vs-new. The
replay results are emitted in the same JSON shape ``evadex scan`` produces, so
``evadex compare old.json replay.json`` works with no extra plumbing.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
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

console = Console()
err_console = Console(stderr=True)


# ── Outcome classification ──────────────────────────────────────────────────
# Outcomes are named from the scanner's point of view. "detected" = scanner
# caught the evasion (good). Original outcome comes from the scan file; the new
# outcome comes from re-submitting to the current scanner.
NEWLY_DETECTED = "newly_detected"  # bypassed before, caught now  → fix confirmed
STILL_BYPASSING = "still_bypassing"  # bypassed before and now     → not yet fixed
NEWLY_FAILING = "newly_failing"  # caught before, bypassed now → regression
UNCHANGED_DETECTED = "unchanged_detected"  # caught before and now
ERROR = "error"  # adapter raised on re-submission


def _classify_outcome(was_detected: bool, detected_now: bool) -> str:
    if not was_detected and detected_now:
        return NEWLY_DETECTED
    if not was_detected and not detected_now:
        return STILL_BYPASSING
    if was_detected and not detected_now:
        return NEWLY_FAILING
    return UNCHANGED_DETECTED


# ── Scan-file loading / reconstruction ──────────────────────────────────────
def _load_scan(scan_file: str) -> dict:
    """Load a scan JSON file, exiting with a clear message on failure."""
    path = Path(scan_file)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        err_console.print(
            f"[red]Scan file not found: {scan_file}[/red]", soft_wrap=True
        )
        raise SystemExit(1)
    except json.JSONDecodeError as e:
        err_console.print(
            f"[red]Scan file is not valid JSON: {e}[/red]", soft_wrap=True
        )
        raise SystemExit(1)
    if not isinstance(data, dict) or "results" not in data:
        # soft_wrap keeps the message on one logical line so it isn't hard-
        # wrapped mid-sentence at the console's width (80 cols when stderr is
        # not a TTY, e.g. under CI / CliRunner), which would split the phrase
        # tests grep for across a newline.
        err_console.print(
            f"[red]{scan_file} does not look like an evadex scan file "
            f"(missing 'results' key). Produce one with: evadex scan ... -o <file>[/red]",
            soft_wrap=True,
        )
        raise SystemExit(1)
    return data


def _reconstruct(data: dict) -> list:
    """Rebuild original ScanResult objects from a scan JSON's ``results`` list.

    Records that cannot be reconstructed (partial/corrupt entries, or values
    from an unknown PayloadCategory) are skipped rather than aborting the whole
    replay — a single malformed row shouldn't sink a 20k-variant replay.
    """
    from evadex.core.result import ScanResult

    out = []
    for rd in data.get("results", []):
        if not isinstance(rd, dict):
            continue
        try:
            out.append(ScanResult.from_dict(rd))
        except (KeyError, ValueError, TypeError):
            continue
    return out


def _filter_results(
    results: list,
    failed_only: bool,
    category: Optional[str],
    technique: Optional[str],
    limit: Optional[int],
) -> list:
    """Apply --failed-only / --category / --technique / --limit filters."""
    out = results
    if failed_only:
        # A genuine bypass = scanner did not detect it and there was no adapter
        # error the first time round. Errored originals are excluded — they
        # never produced a real "bypassed" signal to confirm a fix against.
        out = [r for r in out if not r.detected and not r.error]
    if category:
        cat = category.lower()
        out = [r for r in out if r.payload.category.value.lower() == cat]
    if technique:
        tech = technique.lower()
        out = [
            r
            for r in out
            if (r.variant.technique or "").lower() == tech
            or (r.variant.generator or "").lower() == tech
        ]
    if limit is not None and limit >= 0:
        out = out[:limit]
    return out


# ── Adapter wiring (mirrors evadex scan's resolution) ───────────────────────
def _resolve_adapter_config(
    url: str,
    api_key: Optional[str],
    timeout: float,
    executable: Optional[str],
    transport: str,
    cmd_style: Optional[str],
    wrap_context: bool,
    min_confidence: Optional[float],
) -> dict:
    config: dict = {"base_url": url, "api_key": api_key, "timeout": timeout}
    if executable:
        config["executable"] = executable
    if transport and transport != "cli":
        config["transport"] = transport
    if cmd_style:
        config["cmd_style"] = cmd_style
    if wrap_context:
        config["wrap_context"] = True
    if min_confidence is not None:
        config["min_confidence"] = float(min_confidence)
    return config


def _auto_detect_exe(tool: str) -> Optional[str]:
    """Best-effort discovery of the scanner binary on PATH (as scan does)."""
    import shutil

    sfx = ".exe" if sys.platform == "win32" else ""
    names = (
        ["siphon", f"siphon{sfx}"]
        if tool == "siphon-cli"
        else ["dlpscan", f"dlpscan{sfx}", "dlpscan-rs"]
    )
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    if tool == "siphon-cli":
        cargo = Path.home() / ".cargo" / "bin" / f"siphon{sfx}"
        if cargo.exists():
            return str(cargo)
    return None


# ── Replay execution ────────────────────────────────────────────────────────
async def _replay_variants(adapter, originals: list, concurrency: int) -> list:
    """Re-submit each original variant to *adapter*; return (original, new) pairs.

    Concurrency and per-variant error handling mirror ``core.engine.Engine`` so
    a failing submission becomes an ERROR ScanResult instead of aborting.
    """
    from evadex.core.result import ScanResult

    sem = asyncio.Semaphore(concurrency)

    async def _one(original) -> tuple:
        async with sem:
            start = time.perf_counter()
            try:
                new = await adapter.submit(original.payload, original.variant)
                new.duration_ms = (time.perf_counter() - start) * 1000
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:  # noqa: BLE001 — engine parity
                new = ScanResult(
                    payload=original.payload,
                    variant=original.variant,
                    detected=False,
                    error=str(e),
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
            return original, new

    await adapter.setup()
    try:
        tasks = [asyncio.create_task(_one(r)) for r in originals]
        pairs: list = []
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
                f"Replaying {len(tasks)} variants...", total=len(tasks)
            )
            for coro in asyncio.as_completed(tasks):
                pairs.append(await coro)
                progress.advance(tid)
        return pairs
    finally:
        await adapter.teardown()


# ── Rendering ───────────────────────────────────────────────────────────────
_OUTCOME_STYLES = {
    NEWLY_DETECTED: ("green", "✓ Fixed"),
    STILL_BYPASSING: ("red", "✗ Still bypassing"),
    NEWLY_FAILING: ("yellow", "⚠ Regression"),
    UNCHANGED_DETECTED: ("dim", "— Unchanged"),
    ERROR: ("red", "! Error"),
}


def _tally(pairs: list) -> dict:
    counts = {
        NEWLY_DETECTED: 0,
        STILL_BYPASSING: 0,
        NEWLY_FAILING: 0,
        UNCHANGED_DETECTED: 0,
        ERROR: 0,
    }
    for original, new in pairs:
        if new.error:
            counts[ERROR] += 1
            continue
        counts[_classify_outcome(original.detected, new.detected)] += 1
    return counts


def _print_summary(pairs: list, counts: dict, original_label: str, replay_label: str):
    total = len(pairs)
    err_console.print("[bold]Replay summary[/bold]")
    err_console.print(f"  Original:  {original_label}")
    err_console.print(f"  Current:   {replay_label}")
    err_console.print(f"  Variants:  {total}")
    err_console.print()
    if counts[NEWLY_DETECTED]:
        err_console.print(
            f"  [green]✓ Newly detected:    {counts[NEWLY_DETECTED]}/{total}[/green]"
            f"  — fix confirmed"
        )
    if counts[STILL_BYPASSING]:
        err_console.print(
            f"  [red]✗ Still bypassing:   {counts[STILL_BYPASSING]}/{total}[/red]"
            f"  — not yet fixed"
        )
    if counts[NEWLY_FAILING]:
        err_console.print(
            f"  [yellow]⚠ Newly failing:     {counts[NEWLY_FAILING]}/{total}[/yellow]"
            f"  — regression introduced"
        )
    if counts[UNCHANGED_DETECTED]:
        err_console.print(
            f"  [dim]— Unchanged (caught): {counts[UNCHANGED_DETECTED]}/{total}[/dim]"
        )
    if counts[ERROR]:
        err_console.print(f"  [red]! Errors:            {counts[ERROR]}/{total}[/red]")
    err_console.print()

    if counts[STILL_BYPASSING] == 0 and counts[NEWLY_FAILING] == 0:
        err_console.print(
            "[green bold]✓ No variants bypassing and no regressions.[/green bold]"
        )
    elif counts[NEWLY_FAILING] > 0:
        err_console.print(
            "[yellow bold]⚠ Regression detected — investigate newly-failing "
            "variants.[/yellow bold]"
        )
    else:
        err_console.print(
            f"[yellow]{counts[STILL_BYPASSING]} variant(s) still bypassing.[/yellow]"
        )


def _print_table(pairs: list, counts: dict):
    table = Table(title="Replay Results")
    table.add_column("Category", style="dim")
    table.add_column("Technique", style="dim")
    table.add_column("Value", max_width=40, overflow="fold")
    table.add_column("Before", justify="center")
    table.add_column("After", justify="center")
    table.add_column("Outcome")

    for original, new in pairs:
        outcome = (
            ERROR if new.error else _classify_outcome(original.detected, new.detected)
        )
        style, label = _OUTCOME_STYLES.get(outcome, ("dim", outcome))
        val = original.variant.value.replace("\n", " ").replace("\r", " ")
        if len(val) > 40:
            val = val[:37] + "..."
        table.add_row(
            original.payload.category.value,
            original.variant.technique or original.variant.generator,
            val,
            "✓" if original.detected else "✗",
            "✓" if (new.detected and not new.error) else "✗",
            f"[{style}]{label}[/{style}]",
        )
    console.print(table)
    err_console.print(
        f"\n[green]Newly detected: {counts[NEWLY_DETECTED]}[/green]  "
        f"[red]Still bypassing: {counts[STILL_BYPASSING]}[/red]  "
        f"[yellow]Newly failing: {counts[NEWLY_FAILING]}[/yellow]"
    )


# ── Command ─────────────────────────────────────────────────────────────────
@click.command("replay")
@click.argument("scan_file", type=click.Path(exists=True))
@click.option(
    "--tool",
    "-t",
    default="siphon-cli",
    show_default=True,
    help="DLP adapter to replay against. Same choices as 'evadex scan'.",
)
@click.option(
    "--failed-only",
    is_flag=True,
    default=False,
    help="Only replay variants that bypassed (were not detected) in the "
    "original scan — the CI-friendly 'did my fix work?' mode.",
)
@click.option("--category", default=None, help="Filter to a specific category.")
@click.option(
    "--technique",
    default=None,
    help="Filter to a specific technique (matches technique or generator name).",
)
@click.option(
    "--limit", default=None, type=int, help="Max number of variants to replay."
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Write replay results as a scan-format JSON (feeds 'evadex compare').",
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
    "--scanner-label",
    default="replay",
    show_default=True,
    help="Scanner label recorded in the replay JSON meta.",
)
@click.option(
    "--concurrency",
    default=32,
    show_default=True,
    type=int,
    help="Max concurrent submissions.",
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
def replay(
    scan_file: str,
    tool: str,
    failed_only: bool,
    category: Optional[str],
    technique: Optional[str],
    limit: Optional[int],
    output: Optional[str],
    fmt: str,
    scanner_label: str,
    concurrency: int,
    executable: Optional[str],
    url: str,
    api_key: Optional[str],
    timeout: float,
    transport: str,
    cmd_style: Optional[str],
    min_confidence: Optional[float],
    wrap_context: Optional[bool],
) -> None:
    """Re-run the exact payloads from a past scan against the current scanner.

    SCAN_FILE is a JSON file produced by 'evadex scan'. Every variant is
    replayed verbatim (same value, technique and strategy) and its old outcome
    is diffed against the new one.

    \b
    Examples:
      # Confirm a fix caught everything that was bypassing before
      evadex replay results/scans/pre_fix.json --failed-only

      # Full before/after table for one category
      evadex replay results/scans/pre_fix.json --category credit_card --format table

      # Produce a scan-format JSON and diff it with the original
      evadex replay pre_fix.json --failed-only -o replay.json
      evadex compare pre_fix.json replay.json
    """
    from evadex.core.registry import get_adapter, load_builtins
    from evadex.reporters.json_reporter import JsonReporter

    load_builtins()

    data = _load_scan(scan_file)
    original_label = (data.get("meta") or {}).get("scanner") or "unknown"
    originals = _reconstruct(data)
    if not originals:
        err_console.print(
            "[red]No replayable variants found in scan file.[/red] "
            "The file may be empty or from an incompatible evadex version."
        )
        raise SystemExit(1)

    selected = _filter_results(originals, failed_only, category, technique, limit)
    if not selected:
        err_console.print("[yellow]No variants match the given filters.[/yellow]")
        raise SystemExit(0)

    # Resolve wrap_context the same way scan does: auto-on for the Rust scanners
    # unless the operator explicitly opted out with --no-wrap-context.
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

    err_console.print(f"\n[bold]evadex replay[/bold] — {Path(scan_file).name}")
    err_console.print(f"[dim]Original scan: {original_label}[/dim]")
    err_console.print(
        f"[dim]Replaying {len(selected)} variant(s)"
        + (" (failed only)" if failed_only else "")
        + f" against {tool}[/dim]\n"
    )

    pairs = asyncio.run(_replay_variants(adapter, selected, concurrency))
    counts = _tally(pairs)
    new_results = [new for _orig, new in pairs]

    if fmt == "summary":
        _print_summary(pairs, counts, original_label, scanner_label)
    elif fmt == "table":
        _print_table(pairs, counts)
    elif fmt == "json":
        rendered = JsonReporter(scanner_label=scanner_label).render(new_results)
        sys.stdout.buffer.write(rendered.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()

    if output:
        rendered = JsonReporter(scanner_label=scanner_label).render(new_results)
        out_path = Path(output)
        if out_path.parent and not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        err_console.print(f"[dim]Replay results written to {output}[/dim]")
        err_console.print(
            f"[dim]Diff against the original with: "
            f"evadex compare {scan_file} {output}[/dim]"
        )

    # CI gate: when confirming a fix (--failed-only), a non-empty
    # still-bypassing set means the fix is incomplete → non-zero exit.
    if failed_only and counts[STILL_BYPASSING] > 0:
        raise SystemExit(1)
