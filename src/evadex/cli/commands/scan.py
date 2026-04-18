import asyncio
import json
import sys
from collections import defaultdict
import click
from click.core import ParameterSource
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from evadex.cli.commands.compare import build_comparison
from evadex.config import load_config, find_config
from evadex.core.registry import load_builtins, get_adapter, get_generator
from evadex.core.engine import Engine
from evadex.core.result import Payload, PayloadCategory, SeverityLevel
from evadex.payloads.builtins import get_payloads, detect_category, HEURISTIC_CATEGORIES
from evadex.payloads.tiers import get_tier_categories, VALID_TIERS
from evadex.reporters.json_reporter import JsonReporter
from evadex.reporters.html_reporter import HtmlReporter

err_console = Console(stderr=True)

STRATEGY_CHOICES = click.Choice(["text", "docx", "pdf", "xlsx"])
CATEGORY_CHOICES = click.Choice([c.value for c in PayloadCategory])
TIER_CHOICES = click.Choice(sorted(VALID_TIERS), case_sensitive=False)


_GENERATOR_LABELS: dict[str, str] = {
    "unicode_encoding":   "Unicode encoding",
    "delimiter":          "Delimiter variation",
    "splitting":          "Value splitting",
    "leetspeak":          "Leetspeak substitution",
    "regional_digits":    "Regional digit scripts",
    "structural":         "Structural manipulation",
    "encoding":           "Encoding obfuscation",
    "context_injection":  "Context injection",
    "unicode_whitespace": "Unicode whitespace",
    "bidirectional":      "Bidirectional text",
    "soft_hyphen":        "Invisible separator injection",
    "morse_code":         "Morse code encoding",
}


def _gen_label(name: str) -> str:
    return _GENERATOR_LABELS.get(name, name)


def _key_findings(results, err_console) -> None:
    """Print plain-English findings synthesised from scan results."""
    if not results:
        return

    total_fails = sum(1 for r in results if r.severity == SeverityLevel.FAIL)

    if total_fails == 0:
        err_console.print("  [bold]Key Findings:[/bold]")
        err_console.print("    [green]• Scanner detected all variants — no bypass techniques succeeded[/green]")
        err_console.print()
        return

    findings: list[str] = []

    # ── Per-generator bypass rates ────────────────────────────────────────────
    by_gen: dict = defaultdict(lambda: {"total": 0, "fail": 0})
    for r in results:
        by_gen[r.variant.generator]["total"] += 1
        if r.severity == SeverityLevel.FAIL:
            by_gen[r.variant.generator]["fail"] += 1

    gen_rates = {
        g: round(c["fail"] / c["total"] * 100, 1)
        for g, c in by_gen.items() if c["total"]
    }
    ranked_gens = sorted(gen_rates.items(), key=lambda kv: kv[1], reverse=True)

    # Finding 1: generator with highest bypass rate
    if ranked_gens:
        top_gen, top_rate = ranked_gens[0]
        label = _gen_label(top_gen)
        if top_rate >= 80:
            findings.append(f"[red]{label} consistently evades detection ({top_rate}% bypass)[/red]")
        elif top_rate >= 50:
            findings.append(f"[red]{label} shows highest bypass rate ({top_rate}%)[/red]")
        else:
            findings.append(f"[yellow]{label} shows highest bypass rate ({top_rate}%)[/yellow]")

    # Finding 2: generator that bypasses across the broadest spread of categories
    by_gen_cats: dict = defaultdict(set)
    for r in results:
        if r.severity == SeverityLevel.FAIL:
            by_gen_cats[r.variant.generator].add(r.payload.category.value)

    all_cats = {r.payload.category.value for r in results}
    top_gen_name = ranked_gens[0][0] if ranked_gens else None
    broad = [
        (g, cats) for g, cats in by_gen_cats.items()
        if g != top_gen_name
        and len(cats) >= max(2, len(all_cats) // 2)
        and gen_rates.get(g, 0) >= 30
    ]
    if broad:
        broad_gen, broad_cats = max(broad, key=lambda x: len(x[1]))
        rate = gen_rates.get(broad_gen, 0)
        findings.append(
            f"[yellow]{_gen_label(broad_gen)} bypasses detection across "
            f"{len(broad_cats)} of {len(all_cats)} tested categories ({rate}% overall)[/yellow]"
        )

    # Finding 3: payload category most exposed
    by_cat: dict = defaultdict(lambda: {"total": 0, "fail": 0})
    for r in results:
        by_cat[r.payload.category.value]["total"] += 1
        if r.severity == SeverityLevel.FAIL:
            by_cat[r.payload.category.value]["fail"] += 1

    cat_rates = {
        c: round(v["fail"] / v["total"] * 100, 1)
        for c, v in by_cat.items() if v["total"]
    }
    if len(cat_rates) > 1:
        worst_cat = max(cat_rates, key=lambda c: cat_rates[c])
        worst_rate = cat_rates[worst_cat]
        if worst_rate >= 40:
            readable = worst_cat.replace("_", " ").title()
            findings.append(
                f"[yellow]{readable} payloads most exposed ({worst_rate}% bypass rate)[/yellow]"
            )

    # Finding 4: file-strategy gap vs plain text
    by_strat: dict = defaultdict(lambda: {"total": 0, "fail": 0})
    for r in results:
        by_strat[r.variant.strategy]["total"] += 1
        if r.severity == SeverityLevel.FAIL:
            by_strat[r.variant.strategy]["fail"] += 1

    if "text" in by_strat and len(by_strat) > 1:
        t = by_strat["text"]
        text_rate = round(t["fail"] / t["total"] * 100, 1) if t["total"] else 0.0
        file_total = sum(v["total"] for s, v in by_strat.items() if s != "text")
        file_fail  = sum(v["fail"]  for s, v in by_strat.items() if s != "text")
        file_rate  = round(file_fail / file_total * 100, 1) if file_total else 0.0
        gap = round(file_rate - text_rate, 1)
        if abs(gap) >= 5:
            if gap > 0:
                findings.append(
                    f"[yellow]File extraction strategies bypass detection {gap}pp more than plain text "
                    f"({file_rate}% vs {text_rate}%)[/yellow]"
                )
            else:
                findings.append(
                    f"[green]File extraction pipeline adds {abs(gap)}pp additional filtering vs plain text "
                    f"({file_rate}% vs {text_rate}% bypass)[/green]"
                )

    # Finding 5: zero-bypass technique classes (good news)
    zero_gens = sorted(g for g, rate in gen_rates.items() if rate == 0)
    if zero_gens and len(zero_gens) <= 4:
        labels = ", ".join(_gen_label(g) for g in zero_gens)
        noun = "technique" if len(zero_gens) == 1 else "techniques"
        findings.append(
            f"[green]{labels}: 0% bypass — scanner handles "
            f"{'this' if len(zero_gens) == 1 else 'these'} {noun} well[/green]"
        )

    if not findings:
        return

    err_console.print("  [bold]Key Findings:[/bold]")
    for f in findings:
        err_console.print(f"    • {f}")
    err_console.print()


def _print_summary(results, err_console):
    """Print a structured, human-readable summary to stderr."""
    total  = len(results)
    passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
    fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
    errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)
    pass_rate = round(passes / total * 100, 1) if total else 0.0

    err_console.print()
    err_console.print("[bold]=== Evadex Summary ===[/bold]")
    err_console.print(f"  Total tests:    {total}")
    err_console.print(f"  [green]Detected:       {passes}[/green]")
    err_console.print(f"  [red]Bypassed:       {fails}[/red]")
    if errors:
        err_console.print(f"  [yellow]Errors:         {errors}[/yellow]")
    err_console.print(f"  Detection Rate: {pass_rate}%")
    err_console.print()

    # Group by generator (technique category)
    by_gen = defaultdict(lambda: {"total": 0, "bypassed": 0})
    for r in results:
        by_gen[r.variant.generator]["total"] += 1
        if r.severity == SeverityLevel.FAIL:
            by_gen[r.variant.generator]["bypassed"] += 1

    ranked = sorted(
        by_gen.items(),
        key=lambda kv: kv[1]["bypassed"] / kv[1]["total"] if kv[1]["total"] else 0,
        reverse=True,
    )

    err_console.print("  [bold]By Technique Category:[/bold]")
    for gen, counts in sorted(by_gen.items()):
        n, b = counts["total"], counts["bypassed"]
        rate = round(b / n * 100, 1) if n else 0.0
        err_console.print(f"    {gen:<25}  {b}/{n} bypassed  ({rate}%)")
    err_console.print()

    top = ranked[:5]
    if top:
        err_console.print("  [bold]Top Bypass Categories:[/bold]")
        for i, (gen, counts) in enumerate(top, 1):
            n, b = counts["total"], counts["bypassed"]
            rate = round(b / n * 100, 1) if n else 0.0
            err_console.print(f"    {i}. [cyan]{gen}[/cyan] — {rate}% bypass ({b}/{n})")
    err_console.print()

    _key_findings(results, err_console)

    return total, passes, fails, errors, pass_rate


@click.command()
@click.pass_context
@click.option("--config", "config_path", default=None, metavar="PATH",
              help="Path to evadex.yaml config file. Config values are defaults; "
                   "CLI flags override them. Auto-discovered from the current directory "
                   "if evadex.yaml exists and --config is not passed.")
@click.option("--tool", "-t", default="dlpscan-cli", show_default=True,
              help="DLP adapter to use. Built-in adapters: dlpscan-cli, dlpscan, presidio.")
@click.option("--input", "-i", "input_value", default=None,
              help="Single value to test (if omitted, runs all built-ins)")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html"]),
              default="json", show_default=True, help="Output format")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
@click.option("--url", default="http://localhost:8080", show_default=True,
              help="Adapter base URL")
@click.option("--api-key", default=None, envvar="EVADEX_API_KEY",
              help="API key for adapter")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="Request timeout in seconds")
@click.option("--strategy", "strategies", multiple=True, type=STRATEGY_CHOICES,
              help="Submission strategies to use (default: all). Repeat for multiple.")
@click.option("--concurrency", default=20, show_default=True, type=int,
              help="Max concurrent requests")
@click.option("--category", "categories", multiple=True, type=CATEGORY_CHOICES,
              help="Filter built-in payloads by category. Repeat for multiple.")
@click.option("--variant-group", "variant_groups", multiple=True,
              help="Limit to specific generator names. Repeat for multiple.")
@click.option("--include-heuristic", "include_heuristic", is_flag=True, default=False,
              help="Also run heuristic categories (JWT, AWS key). See README for limitations.")
@click.option("--tier", "tier", default=None, type=TIER_CHOICES, show_default=False,
              help=(
                  "Payload tier to run. One of: banking (default), core, regional, full. "
                  "Ignored when --category is also specified."
              ))
@click.option("--scanner-label", "scanner_label", default="", show_default=False,
              help="Label for this scanner in JSON output (e.g. 'python-1.3.0' or 'rust-2.0.0')")
@click.option("--exe", "executable", default=None, show_default=False,
              help="Path to scanner executable (dlpscan-cli adapter only)")
@click.option("--cmd-style", "cmd_style", default=None,
              type=click.Choice(["python", "rust"]), show_default=False,
              help="Command format for dlpscan-cli: 'python' (-f json) or 'rust' (--format json scan)")
@click.option("--min-detection-rate", "min_detection_rate", default=None, type=float,
              help="Exit with code 1 if detection rate falls below this threshold (0-100). "
                   "For CI/CD pipeline integration.")
@click.option("--baseline", "save_baseline", default=None,
              help="Save this run's JSON results to a baseline file for future comparison.")
@click.option("--compare-baseline", "compare_baseline", default=None,
              help="Compare this run against a saved baseline JSON and report regressions.")
@click.option("--audit-log", "audit_log", default=None,
              help="Append a one-line JSON audit record for this run to a file. "
                   "Created (with parent directories) if it does not exist. "
                   "Can also be set via 'audit_log' in evadex.yaml.")
@click.option("--feedback-report", "feedback_report", default=None, metavar="PATH",
              help="Save a structured JSON feedback report to PATH. Contains per-technique "
                   "evasion counts, fix suggestions, and the generated regression test code.")
@click.option("--require-context", "require_context", is_flag=True, default=False,
              help="Pass --require-context to dlpscan-rs: only flag matches when surrounding "
                   "keywords are present. Reduces false positives but may also reduce detection "
                   "rate for variants lacking keyword context. Requires --cmd-style rust.")
@click.option("--wrap-context", "wrap_context", is_flag=True, default=False,
              help="Embed every variant value in a realistic keyword sentence before submission. "
                   "dlpscan-rs requires surrounding context words to flag matches — submitting a "
                   "bare value produces misleading (artificially low) detection rates. "
                   "Automatically enabled when --cmd-style rust is used. "
                   "Pass --no-wrap-context to disable.")
@click.option("--no-wrap-context", "no_wrap_context", is_flag=True, default=False,
              help="Explicitly disable context wrapping even when --cmd-style rust is active.")
@click.option("--c2-url", "c2_url", default=None, envvar="EVADEX_C2_URL",
              help="Siphon-C2 management-plane URL (e.g. http://c2.internal:9090). "
                   "Scan results are pushed to POST /v1/evadex/scan. A failure or "
                   "unreachable C2 is logged as a warning but never fails the scan.")
@click.option("--c2-key", "c2_key", default=None, envvar="EVADEX_C2_KEY",
              help="API key sent as 'x-api-key' to Siphon-C2 (same format as the "
                   "core Siphon API). Falls back to EVADEX_C2_KEY env var.")
def scan(
    ctx,
    config_path, tool, input_value, fmt, output, url, api_key, timeout,
    strategies, concurrency, categories, variant_groups, include_heuristic,
    tier, scanner_label, executable, cmd_style, min_detection_rate,
    save_baseline, compare_baseline, audit_log, feedback_report,
    require_context, wrap_context, no_wrap_context,
    c2_url, c2_key,
):
    """Run DLP evasion tests."""
    load_builtins()

    # Early guard: --baseline and --compare-baseline must not point to the same file.
    # Writing the baseline happens before comparison, so using the same path destroys
    # the original baseline and the comparison always shows zero delta.
    if save_baseline and compare_baseline:
        from pathlib import Path
        if Path(save_baseline).resolve() == Path(compare_baseline).resolve():
            err_console.print(
                "[red]Error: --baseline and --compare-baseline cannot point to the same file. "
                "Use separate paths: save the baseline first, then compare against it in a later run.[/red]"
            )
            sys.exit(1)

    # ── Config file ───────────────────────────────────────────────────────────
    cfg = None
    if config_path:
        cfg = load_config(config_path)
    else:
        auto_path = find_config()
        if auto_path:
            err_console.print(f"[dim]Using config: {auto_path}[/dim]")
            cfg = load_config(auto_path)

    # Apply config values as defaults for any option not explicitly passed on
    # the CLI (source == DEFAULT).  CLI flags always win.
    if cfg is not None:
        def _is_default(name: str) -> bool:
            return ctx.get_parameter_source(name) == ParameterSource.DEFAULT

        if _is_default("tool") and cfg.tool is not None:
            tool = cfg.tool
        if _is_default("strategies") and cfg.strategy is not None:
            strategies = tuple(cfg.strategy)
        if _is_default("fmt") and cfg.format is not None:
            fmt = cfg.format
        if _is_default("output") and cfg.output is not None:
            output = cfg.output
        if _is_default("timeout") and cfg.timeout is not None:
            timeout = cfg.timeout
        if _is_default("concurrency") and cfg.concurrency is not None:
            concurrency = cfg.concurrency
        if _is_default("categories") and cfg.categories:
            categories = tuple(cfg.categories)
        if _is_default("include_heuristic") and cfg.include_heuristic is not None:
            include_heuristic = cfg.include_heuristic
        if _is_default("scanner_label") and cfg.scanner_label is not None:
            scanner_label = cfg.scanner_label
        if _is_default("executable") and cfg.exe is not None:
            executable = cfg.exe
        if _is_default("cmd_style") and cfg.cmd_style is not None:
            cmd_style = cfg.cmd_style
        if _is_default("min_detection_rate") and cfg.min_detection_rate is not None:
            min_detection_rate = cfg.min_detection_rate
        if _is_default("audit_log") and cfg.audit_log is not None:
            audit_log = cfg.audit_log
        if _is_default("require_context") and cfg.require_context is not None:
            require_context = cfg.require_context
        if not wrap_context and not no_wrap_context and cfg.wrap_context is not None:
            wrap_context = cfg.wrap_context
        if _is_default("tier") and cfg.tier is not None:
            tier = cfg.tier
        if _is_default("c2_url") and cfg.c2_url is not None:
            c2_url = cfg.c2_url
        if _is_default("c2_key") and cfg.c2_key is not None:
            c2_key = cfg.c2_key

    # ── Auto-enable wrap_context for dlpscan-rs ───────────────────────────────
    # dlpscan-rs requires surrounding context keywords to fire most rules.
    # Submitting a bare value (no sentence context) produces artificially low
    # detection rates that do not reflect real-world scanner behaviour.
    # When --cmd-style rust is active and the user has not explicitly opted out
    # with --no-wrap-context, enable context wrapping automatically.
    effective_cmd_style = cmd_style or "python"
    if not no_wrap_context and not wrap_context and effective_cmd_style == "rust":
        wrap_context = True
    if no_wrap_context:
        wrap_context = False

    # ── Heuristic warning ─────────────────────────────────────────────────────
    if include_heuristic:
        err_console.print(
            "[yellow]Warning: --include-heuristic is enabled. Heuristic categories (JWT, AWS key) "
            "rely on fixed-prefix or high-entropy patterns that DLP scanners match differently than "
            "structured formats. Evasion results for these categories may not reflect real-world "
            "detection risk and should be interpreted with caution.[/yellow]"
        )

    # Resolve strategies
    active_strategies = list(strategies) if strategies else ["text", "docx", "pdf", "xlsx"]

    # Resolve payloads
    if input_value:
        category = detect_category(input_value)
        payloads = [Payload(
            value=input_value,
            category=category,
            label=f"Custom ({category.value})",
        )]
    else:
        if categories:
            # Explicit --category always wins over --tier
            filter_cats = {PayloadCategory(c) for c in categories}
            if not include_heuristic:
                heuristic_requested = filter_cats & HEURISTIC_CATEGORIES
                if heuristic_requested:
                    names = ", ".join(c.value for c in heuristic_requested)
                    err_console.print(
                        f"[red]Error: category '{names}' is heuristic. "
                        f"Add --include-heuristic to include it.[/red]"
                    )
                    sys.exit(1)
        else:
            # No explicit category: resolve from tier (default: banking)
            effective_tier = tier or "banking"
            tier_cats = get_tier_categories(effective_tier)
            filter_cats = tier_cats  # None for full tier → no category filter
            if effective_tier == "banking" and not tier:
                err_console.print(
                    f"[dim]Tier: banking (default) — use --tier full for all payloads[/dim]"
                )
            elif tier:
                err_console.print(f"[dim]Tier: {effective_tier}[/dim]")
        payloads = get_payloads(filter_cats, include_heuristic=include_heuristic)

    if not payloads:
        err_console.print("[red]No payloads to test.[/red]")
        sys.exit(1)

    # Resolve adapter
    config = {"base_url": url, "api_key": api_key, "timeout": timeout}
    if executable:
        config["executable"] = executable
    if cmd_style:
        config["cmd_style"] = cmd_style
    if require_context:
        config["require_context"] = True
    if wrap_context:
        config["wrap_context"] = True
    try:
        adapter = get_adapter(tool, config)
    except KeyError as e:
        err_console.print(f"[red]{e.args[0]}[/red]")
        sys.exit(1)

    # Pre-flight health check
    if not asyncio.run(adapter.health_check()):
        if tool == "dlpscan-cli":
            _exe_name = executable or "dlpscan"
            hint = (
                f" Is [bold]{_exe_name}[/bold] installed and on PATH? "
                f"Use --exe to specify a different path."
            )
        else:
            hint = f" Is the scanner reachable at {url}?"
        err_console.print(f"[red]Health check failed for adapter '{tool}'.{hint}[/red]")
        sys.exit(1)

    # Resolve generators
    if variant_groups:
        try:
            generators = [get_generator(name) for name in variant_groups]
        except KeyError as e:
            err_console.print(f"[red]{e.args[0]}[/red]")
            sys.exit(1)
    else:
        generators = None  # use all registered

    # Run engine with live progress bar on stderr
    if tool == "dlpscan-cli":
        err_console.print(f"[dim]Running evadex scan against [bold]{tool}[/bold]...[/dim]")
    else:
        err_console.print(f"[dim]Running evadex scan against [bold]{tool}[/bold] at {url}...[/dim]")
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=err_console,
        transient=True,
    )
    progress_task_id = None

    def on_result(result, completed, total):
        if progress_task_id is not None:
            label = result.payload.label
            progress.update(
                progress_task_id,
                completed=completed,
                total=total,
                description=f"[dim]{label[:35]}[/dim]",
            )

    engine = Engine(
        adapter=adapter,
        generators=generators,
        concurrency=concurrency,
        strategies=active_strategies,
        on_result=on_result,
    )

    with progress:
        progress_task_id = progress.add_task("[dim]Starting...[/dim]", total=None)
        results = engine.run(payloads)

    # Summary
    total, passes, fails, errors, pass_rate = _print_summary(results, err_console)

    # Report
    reporter = HtmlReporter() if fmt == "html" else JsonReporter(scanner_label=scanner_label)
    rendered = reporter.render(results)

    # ── Archive: save timestamped copy and append to audit.jsonl ─────────────
    if fmt == "json":
        from evadex.archive import (
            archive_scan, append_results_audit,
            build_scan_audit_entry, get_commit_hash,
        )
        _archive_path = archive_scan(rendered, scanner_label)
        _commit = get_commit_hash()
        _audit_entry = build_scan_audit_entry(
            scanner_label=scanner_label,
            tool=tool,
            categories=list(categories) if categories else [],
            strategies=active_strategies,
            total=total,
            passes=passes,
            fails=fails,
            pass_rate=pass_rate,
            archive_file=str(_archive_path),
            commit_hash=_commit,
        )
        append_results_audit(_audit_entry)

    if output:
        try:
            with open(output, "w", encoding="utf-8") as f:
                f.write(rendered)
        except OSError as e:
            err_console.print(f"[red]Cannot write output file '{output}': {e.strerror}[/red]")
            sys.exit(1)
        err_console.print(f"[dim]Report written to {output}[/dim]")
        err_console.print(
            "[yellow]Note: output file may contain obfuscated variants of sensitive test values "
            "(credit card numbers, SSNs, etc.). Restrict access to this file accordingly.[/yellow]"
        )
    else:
        sys.stdout.buffer.write(rendered.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()

    # ── Feedback: fix suggestions, regression file, and optional report ────────
    evasions = [r for r in results if r.severity == SeverityLevel.FAIL]
    if evasions:
        from evadex.feedback.suggestions import get_suggestions
        from evadex.feedback.regression_writer import write_regression_file

        suggestions = get_suggestions(results)
        if suggestions:
            err_console.print("[bold]=== Fix Suggestions ===[/bold]")
            for s in suggestions:
                err_console.print(
                    f"  [cyan]• {s.technique}[/cyan] [dim]({s.generator})[/dim]"
                )
                err_console.print(f"    {s.suggested_fix}")
            err_console.print()

        reg_path = "evadex_regressions.py"
        try:
            write_regression_file(results, reg_path)
            err_console.print(f"[dim]Regression tests written to {reg_path}[/dim]")
        except OSError as e:
            err_console.print(
                f"[yellow]Warning: could not write regression file '{reg_path}': {e.strerror}[/yellow]"
            )

    if feedback_report:
        from evadex.feedback.report import write_feedback_report
        try:
            write_feedback_report(results, feedback_report, scanner_label=scanner_label)
            err_console.print(f"[dim]Feedback report written to {feedback_report}[/dim]")
        except OSError as e:
            err_console.print(
                f"[red]Cannot write feedback report '{feedback_report}': {e.strerror}[/red]"
            )
            sys.exit(1)

    # --baseline: save a copy of the JSON result as a reference file
    if save_baseline:
        baseline_rendered = JsonReporter(scanner_label=scanner_label).render(results)
        try:
            with open(save_baseline, "w", encoding="utf-8") as f:
                f.write(baseline_rendered)
        except OSError as e:
            err_console.print(f"[red]Cannot write baseline file '{save_baseline}': {e.strerror}[/red]")
            sys.exit(1)
        err_console.print(f"[dim]Baseline saved to {save_baseline}[/dim]")

    # --compare-baseline: diff current run against saved baseline
    if compare_baseline:
        try:
            with open(compare_baseline, encoding="utf-8") as f:
                baseline_data = json.load(f)
        except FileNotFoundError:
            err_console.print(f"[red]Baseline file not found: {compare_baseline}[/red]")
            sys.exit(1)
        except json.JSONDecodeError as e:
            err_console.print(f"[red]Baseline file is not valid JSON: {e}[/red]")
            sys.exit(1)
        if not isinstance(baseline_data, dict) or "meta" not in baseline_data or "results" not in baseline_data:
            err_console.print(
                f"[red]Baseline file does not look like an evadex result file "
                f"(missing 'meta' or 'results' keys). "
                f"Generate a baseline with: evadex scan ... --baseline <file>[/red]"
            )
            sys.exit(1)
        current_data = json.loads(JsonReporter(scanner_label=scanner_label).render(results))
        try:
            comp = build_comparison(baseline_data, current_data)
        except (KeyError, TypeError, ValueError) as e:
            err_console.print(f"[red]Baseline comparison failed — baseline file may be from an incompatible evadex version: {e}[/red]")
            sys.exit(1)
        delta = comp["overall"]["delta"]
        regressions = [d for d in comp["diffs"] if d["b_severity"] == "fail" and d["a_severity"] == "pass"]
        improvements = [d for d in comp["diffs"] if d["b_severity"] == "pass" and d["a_severity"] == "fail"]
        err_console.print(
            f"\n[bold]Baseline comparison:[/bold] "
            f"{'[red]' if delta < 0 else '[green]'}{delta:+.1f} pp[/{'red' if delta < 0 else 'green'}] "
            f"vs {comp['label_a']}"
        )
        if regressions:
            err_console.print(f"[red]  {len(regressions)} regression(s) — variants now evading that baseline caught:[/red]")
            for r in regressions[:20]:
                err_console.print(f"    [dim]{r['category']}[/dim]  {r['payload_label']}  [cyan]{r['generator']}[/cyan]/{r['technique']}")
            if len(regressions) > 20:
                err_console.print(f"    [dim]... and {len(regressions) - 20} more[/dim]")
        if improvements:
            err_console.print(f"[green]  {len(improvements)} improvement(s) — variants now caught that baseline missed[/green]")
        if not regressions and not improvements:
            err_console.print("[green]  No changes vs baseline.[/green]")

    # --audit-log: append run record before exit-code check so the entry is written
    # regardless of whether the detection-rate gate passes or fails.
    if audit_log:
        from evadex.audit import append_audit_entry
        append_audit_entry(
            audit_log,
            scanner_label=scanner_label,
            tool=tool,
            strategies=active_strategies,
            categories=list(categories) if categories else [],
            include_heuristic=include_heuristic,
            total=total,
            passes=passes,
            fails=fails,
            errors=errors,
            pass_rate=pass_rate,
            output_file=output,
            baseline_saved=save_baseline,
            compare_baseline=compare_baseline,
            min_detection_rate=min_detection_rate,
            exit_code=(
                1 if (min_detection_rate is not None and pass_rate < min_detection_rate)
                else 0
            ),
        )

    # Siphon-C2 push. Uses the already-rendered JSON so we don't re-serialise
    # and so the C2 payload exactly matches what was written to --output.
    # Never blocks or fails the scan (c2_reporter swallows errors) — the
    # management plane is explicitly "not critical path" per the Siphon
    # architecture docs.
    from evadex.reporters.c2_reporter import push_scan_results, resolve_c2_config
    _c2_url, _c2_key = resolve_c2_config(c2_url, c2_key)
    if _c2_url:
        try:
            _rendered_json = json.loads(rendered) if fmt == "json" else None
        except (ValueError, TypeError):
            _rendered_json = None
        _meta = (_rendered_json or {}).get("meta", {}) if isinstance(_rendered_json, dict) else {}
        _fail_findings = [
            r for r in (_rendered_json or {}).get("results", [])
            if isinstance(r, dict) and r.get("severity") == "fail"
        ][:50] if isinstance(_rendered_json, dict) else []
        push_scan_results(
            _c2_url, _c2_key,
            scanner_label=scanner_label,
            tool=tool,
            categories=list(categories) if categories else [],
            strategies=active_strategies,
            total=total, passes=passes, fails=fails, errors=errors,
            pass_rate=pass_rate,
            by_category=_meta.get("summary_by_category") or {},
            by_technique=_meta.get("summary_by_generator") or {},
            fail_findings=_fail_findings,
        )

    # --min-detection-rate: CI/CD gate (checked last so report is always written first)
    if min_detection_rate is not None:
        if pass_rate < min_detection_rate:
            err_console.print(
                f"[red][bold]FAIL:[/bold] Detection rate {pass_rate}% is below "
                f"required minimum {min_detection_rate}%[/red]"
            )
            sys.exit(1)
        else:
            err_console.print(
                f"[green][bold]PASS:[/bold] Detection rate {pass_rate}% meets "
                f"minimum threshold {min_detection_rate}%[/green]"
            )
