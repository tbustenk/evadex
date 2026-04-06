import sys
import click
from click.core import ParameterSource
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from evadex.core.registry import load_builtins, get_adapter, all_generators, get_generator
from evadex.core.engine import Engine
from evadex.core.result import Payload, PayloadCategory, SeverityLevel
from evadex.payloads.builtins import get_payloads, detect_category, HEURISTIC_CATEGORIES
from evadex.reporters.json_reporter import JsonReporter
from evadex.reporters.html_reporter import HtmlReporter

err_console = Console(stderr=True)

STRATEGY_CHOICES = click.Choice(["text", "docx", "pdf", "xlsx"])
CATEGORY_CHOICES = click.Choice([c.value for c in PayloadCategory])


@click.command()
@click.pass_context
@click.option("--config", "config_path", default=None, metavar="PATH",
              help="Path to evadex.yaml config file. Config values are defaults; "
                   "CLI flags override them. Auto-discovered from the current directory "
                   "if evadex.yaml exists and --config is not passed.")
@click.option("--tool", "-t", default="dlpscan-cli", show_default=True, help="DLP adapter to use")
@click.option("--input", "-i", "input_value", default=None,
              help="Single value to test (if omitted, runs all built-ins)")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html"]),
              default="json", show_default=True)
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
@click.option("--url", default="http://localhost:8080", show_default=True,
              help="Adapter base URL")
@click.option("--api-key", default=None, envvar="EVADEX_API_KEY",
              help="API key for adapter")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="Request timeout in seconds")
@click.option("--strategy", "strategies", multiple=True, type=STRATEGY_CHOICES,
              help="Submission strategies to use (default: all). Repeat for multiple.")
@click.option("--concurrency", default=5, show_default=True, type=int,
              help="Max concurrent requests")
@click.option("--category", "categories", multiple=True, type=CATEGORY_CHOICES,
              help="Filter built-in payloads by category. Repeat for multiple.")
@click.option("--variant-group", "variant_groups", multiple=True,
              help="Limit to specific generator names. Repeat for multiple.")
@click.option("--include-heuristic", "include_heuristic", is_flag=True, default=False,
              help="Also run heuristic categories (JWT, AWS key). See README for limitations.")
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
def scan(
    ctx,
    config_path, tool, input_value, fmt, output, url, api_key, timeout,
    strategies, concurrency, categories, variant_groups, include_heuristic,
    scanner_label, executable, cmd_style, min_detection_rate,
    save_baseline, compare_baseline,
):
    """Run DLP evasion tests."""
    load_builtins()

    # ── Config file ───────────────────────────────────────────────────────────
    from evadex.config import load_config, find_config
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
        filter_cats = {PayloadCategory(c) for c in categories} if categories else None
        if filter_cats and not include_heuristic:
            heuristic_requested = filter_cats & HEURISTIC_CATEGORIES
            if heuristic_requested:
                names = ", ".join(c.value for c in heuristic_requested)
                err_console.print(
                    f"[red]Error: category '{names}' is heuristic. "
                    f"Add --include-heuristic to include it.[/red]"
                )
                sys.exit(1)
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
    try:
        adapter = get_adapter(tool, config)
    except KeyError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)

    # Pre-flight health check
    import asyncio as _asyncio
    if not _asyncio.run(adapter.health_check()):
        err_console.print(f"[red]Health check failed for adapter '{tool}'. Is the scanner available?[/red]")
        sys.exit(1)

    # Resolve generators
    if variant_groups:
        try:
            generators = [get_generator(name) for name in variant_groups]
        except KeyError as e:
            err_console.print(f"[red]{e}[/red]")
            sys.exit(1)
    else:
        generators = None  # use all registered

    # Run engine with live progress bar on stderr
    err_console.print(
        f"[dim]Running evadex scan against [bold]{tool}[/bold] at {url}...[/dim]"
    )
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
    total  = len(results)
    passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
    fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
    errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)
    pass_rate = round(passes / total * 100, 1) if total else 0.0
    parts  = [f"[green]{passes} detected[/green]", f"[red]{fails} evaded[/red]"]
    if errors:
        parts.append(f"[yellow]{errors} errors[/yellow]")
    err_console.print(f"[green]Done.[/green] {total} tests \u2014 " + ", ".join(parts))

    # Report
    reporter = HtmlReporter() if fmt == "html" else JsonReporter(scanner_label=scanner_label)
    rendered = reporter.render(results)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(rendered)
        err_console.print(f"[dim]Report written to {output}[/dim]")
        err_console.print(
            "[yellow]Note: output file may contain obfuscated variants of sensitive test values "
            "(credit card numbers, SSNs, etc.). Restrict access to this file accordingly.[/yellow]"
        )
    else:
        sys.stdout.buffer.write(rendered.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()

    # --baseline: save a copy of the JSON result as a reference file
    if save_baseline:
        baseline_rendered = JsonReporter(scanner_label=scanner_label).render(results)
        with open(save_baseline, "w", encoding="utf-8") as f:
            f.write(baseline_rendered)
        err_console.print(f"[dim]Baseline saved to {save_baseline}[/dim]")

    # --compare-baseline: diff current run against saved baseline
    if compare_baseline:
        import json as _json
        from evadex.cli.commands.compare import build_comparison
        try:
            with open(compare_baseline, encoding="utf-8") as f:
                baseline_data = _json.load(f)
        except FileNotFoundError:
            err_console.print(f"[red]Baseline file not found: {compare_baseline}[/red]")
            sys.exit(1)
        current_data = _json.loads(JsonReporter(scanner_label=scanner_label).render(results))
        comp = build_comparison(baseline_data, current_data)
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
