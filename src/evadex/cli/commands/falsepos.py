"""evadex falsepos — false positive rate measurement command.

Generates structurally plausible but provably invalid values (e.g. 16-digit
numbers that fail Luhn, SSNs with reserved area codes) and submits them to
the scanner to measure false positive rate.

Phase 3 of the GAN-inspired design:
  Phase 1: evasion testing (false negatives)
  Phase 2: fix suggestions + regression tests
  Phase 3: false positive measurement (this command)
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

import click
from rich.console import Console

from evadex.core.registry import load_builtins, get_adapter
from evadex.core.result import Payload, PayloadCategory, Variant
from evadex.falsepos.generators import (
    FALSEPOS_GENERATORS,
    is_match_relevant,
    wrap_with_context,
)

err_console = Console(stderr=True)

_CATEGORY_CHOICES = click.Choice(sorted(FALSEPOS_GENERATORS.keys()))


async def _scan_values(
    adapter,
    cat_name: str,
    values: list[str],
    concurrency: int,
    wrap_context: bool = False,
    strict_category: bool = True,
) -> list[tuple[str, bool]]:
    """Scan *values* through *adapter* and return (value, was_flagged) pairs.

    When *wrap_context* is True, each value is embedded in a category-specific
    keyword sentence before submission — the scanner sees realistic surrounding
    text while the reported value remains the original invalid value.

    When *strict_category* is True (default), a match only counts as an FP
    when the scanner's (sub_)category is on the relevance list for
    *cat_name*. This prevents wrap-template prose from triggering unrelated
    scanner rules (e.g. a Corporate-Classification hit on "do not
    distribute") from being counted as a *cat_name* false positive. Pass
    ``strict_category=False`` for the legacy "any match counts" semantics.
    """
    sem = asyncio.Semaphore(concurrency)

    # Resolve PayloadCategory for the dummy Payload (UNKNOWN if category
    # doesn't exist in the enum, which won't happen for the supported cats).
    try:
        dummy_cat = PayloadCategory(cat_name)
    except ValueError:
        dummy_cat = PayloadCategory.UNKNOWN

    async def _one(v: str) -> tuple[str, bool]:
        async with sem:
            submit_text = wrap_with_context(cat_name, v) if wrap_context else v
            p = Payload(submit_text, dummy_cat, f"falsepos:{cat_name}")
            var = Variant(submit_text, "falsepos", "falsepos_value", "False positive test value", strategy="text")
            try:
                result = await adapter.submit(p, var)
            except Exception:
                return v, False
            if not strict_category:
                return v, result.detected
            matches = result.raw_response.get("matches", []) if isinstance(result.raw_response, dict) else []
            flagged = any(is_match_relevant(cat_name, m) for m in matches)
            return v, flagged

    return list(await asyncio.gather(*[_one(v) for v in values]))


@click.command("falsepos")
@click.option("--tool", "-t", default="dlpscan-cli", show_default=True,
              help="DLP adapter to use.")
@click.option("--category", "categories", multiple=True, type=_CATEGORY_CHOICES,
              help="Category to test. Repeat for multiple. Default: all supported.")
@click.option("--count", default=100, show_default=True, type=int,
              help="Number of false positive values to generate per category.")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "table"]),
              default="table", show_default=True,
              help="Output format. 'table' prints a summary to stdout; "
                   "'json' writes the full report.")
@click.option("--output", "-o", default=None, metavar="PATH",
              help="Write JSON report to file instead of stdout.")
@click.option("--url", default="http://localhost:8080", show_default=True,
              help="Base URL for HTTP-based adapters.")
@click.option("--exe", "executable", default=None,
              help="Path to scanner executable (dlpscan-cli / siphon-cli).")
@click.option("--cmd-style", "cmd_style", default=None,
              type=click.Choice(["python", "rust", "binary", "cargo"]),
              help="Command format. dlpscan-cli: 'python' or 'rust'. "
                   "siphon-cli: 'binary' or 'cargo'.")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="Request timeout in seconds.")
@click.option("--concurrency", default=5, show_default=True, type=int,
              help="Max concurrent scanner requests.")
@click.option("--seed", default=None, type=int,
              help="RNG seed for reproducible false positive values.")
@click.option("--require-context", "require_context", is_flag=True, default=False,
              help="Pass --require-context to dlpscan-rs: only flag matches when surrounding "
                   "keywords are present. Requires --cmd-style rust.")
@click.option("--wrap-context", "wrap_context", is_flag=True, default=False,
              help="Embed each invalid value in a realistic category-specific sentence before "
                   "submitting. Simulates how sensitive data appears in real documents. "
                   "Use with --require-context for the most realistic false positive measurement.")
@click.option("--no-strict-category", "no_strict_category", is_flag=True, default=False,
              help="Disable category-relevance filtering. By default a match only counts as "
                   "an FP for the tested category when the scanner's sub_category is on the "
                   "relevance list (e.g. 'USA SSN' for ssn). Pass --no-strict-category to "
                   "revert to the legacy 'any match counts' semantics — useful when probing "
                   "what the scanner actually fires on.")
@click.option("--c2-url", "c2_url", default=None, envvar="EVADEX_C2_URL",
              help="Siphon-C2 management-plane URL. The false-positive report is pushed "
                   "to POST /v1/evadex/falsepos. Failures log a warning; never fail the run.")
@click.option("--c2-key", "c2_key", default=None, envvar="EVADEX_C2_KEY",
              help="API key sent as 'x-api-key' to Siphon-C2. Falls back to EVADEX_C2_KEY.")
def falsepos(
    tool: str,
    categories: tuple[str, ...],
    count: int,
    fmt: str,
    output: Optional[str],
    url: str,
    executable: Optional[str],
    cmd_style: Optional[str],
    timeout: float,
    concurrency: int,
    seed: Optional[int],
    require_context: bool,
    wrap_context: bool,
    no_strict_category: bool,
    c2_url: Optional[str],
    c2_key: Optional[str],
) -> None:
    """Test how often the scanner incorrectly flags non-sensitive data.

    Generates structurally plausible but provably invalid values — Luhn-failing
    credit cards, SSNs with reserved area codes — then submits them to the
    scanner. Any match is a false positive.

    \b
    Examples:
      evadex falsepos                     # auto-detect scanner, 100 test values
      evadex falsepos --count 500         # more thorough test
      evadex falsepos --wrap-context      # test with surrounding keywords
    """
    load_builtins()

    active_cats = list(categories) if categories else sorted(FALSEPOS_GENERATORS.keys())

    # ── Resolve adapter ───────────────────────────────────────────────────────
    config: dict = {"base_url": url, "timeout": timeout}
    if executable:
        config["executable"] = executable
    if cmd_style:
        config["cmd_style"] = cmd_style
    if require_context:
        config["require_context"] = True
    try:
        adapter = get_adapter(tool, config)
    except KeyError as e:
        err_console.print(f"[red]{e.args[0]}[/red]")
        sys.exit(1)

    if not asyncio.run(adapter.health_check()):
        if tool in ("dlpscan-cli", "siphon-cli"):
            _default_exe = "siphon" if tool == "siphon-cli" else "dlpscan"
            _exe_name = executable or _default_exe
            hint = (
                f" Is [bold]{_exe_name}[/bold] installed and on PATH? "
                "Use --exe to specify a different path."
            )
        else:
            hint = f" Is the scanner reachable at {url}?"
        err_console.print(f"[red]Health check failed for adapter '{tool}'.{hint}[/red]")
        sys.exit(1)

    # ── Mode summary ─────────────────────────────────────────────────────────
    mode_parts = []
    if require_context:
        mode_parts.append("require-context")
    if wrap_context:
        mode_parts.append("wrap-context")
    mode_label = ", ".join(mode_parts) if mode_parts else "baseline (no context)"
    err_console.print(
        f"[dim]Running false positive test against [bold]{tool}[/bold]  "
        f"mode: {mode_label}[/dim]"
    )

    # ── Scan each category ────────────────────────────────────────────────────

    by_category: dict[str, dict] = {}
    total_tested = 0
    total_flagged = 0

    for cat_name in active_cats:
        gen_fn = FALSEPOS_GENERATORS[cat_name]
        values = gen_fn(count, seed=seed)

        scan_pairs = asyncio.run(
            _scan_values(
                adapter, cat_name, values, concurrency,
                wrap_context=wrap_context,
                strict_category=not no_strict_category,
            )
        )

        flagged_values = [v for v, detected in scan_pairs if detected]
        cat_total = len(values)
        n_flagged = len(flagged_values)
        fp_rate = round(n_flagged / cat_total * 100, 1) if cat_total else 0.0

        by_category[cat_name] = {
            "total": cat_total,
            "flagged": n_flagged,
            "false_positive_rate": fp_rate,
            "flagged_values": flagged_values,
        }
        total_tested += cat_total
        total_flagged += n_flagged

        colour = "red" if n_flagged else "green"
        err_console.print(
            f"  [{colour}]{cat_name:<22}  "
            f"{n_flagged}/{cat_total} flagged  ({fp_rate}%)[/{colour}]"
        )

    overall_rate = round(total_flagged / total_tested * 100, 1) if total_tested else 0.0
    err_console.print()
    err_console.print(
        f"[bold]Overall false positive rate: {overall_rate}%[/bold]  "
        f"({total_flagged}/{total_tested})"
    )
    err_console.print()

    report = {
        "tool": tool,
        "count_per_category": count,
        "require_context": require_context,
        "wrap_context": wrap_context,
        "strict_category": not no_strict_category,
        "mode": mode_label,
        "total_tested": total_tested,
        "total_flagged": total_flagged,
        "overall_false_positive_rate": overall_rate,
        "by_category": by_category,
    }

    # ── Archive: save timestamped copy and append to audit.jsonl ─────────────
    from evadex.archive import (
        archive_falsepos, append_results_audit,
        build_falsepos_audit_entry, get_commit_hash,
    )
    _scanner_label = f"{tool}:{mode_label}" if mode_label != "baseline (no context)" else tool
    _archive_path = archive_falsepos(report, scanner_label=_scanner_label)
    _commit = get_commit_hash()
    _audit_entry = build_falsepos_audit_entry(
        tool=tool,
        categories=active_cats,
        total_tested=total_tested,
        total_flagged=total_flagged,
        fp_rate=overall_rate,
        archive_file=str(_archive_path),
        commit_hash=_commit,
        scanner_label=_scanner_label,
    )
    append_results_audit(_audit_entry)

    # ── Siphon-C2 push ────────────────────────────────────────────────────────
    from evadex.reporters.c2_reporter import push_falsepos_report, resolve_c2_config
    _c2_url, _c2_key = resolve_c2_config(c2_url, c2_key)
    if _c2_url:
        push_falsepos_report(_c2_url, _c2_key, report=report)

    # ── Output ────────────────────────────────────────────────────────────────
    if fmt == "json" or output:
        rendered = json.dumps(report, indent=2)
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
