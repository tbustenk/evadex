import sys
import click
from rich.console import Console
from evadex.core.registry import load_builtins, get_adapter, all_generators, get_generator
from evadex.core.engine import Engine
from evadex.core.result import Payload, PayloadCategory
from evadex.payloads.builtins import get_payloads, detect_category
from evadex.reporters.json_reporter import JsonReporter
from evadex.reporters.html_reporter import HtmlReporter

err_console = Console(stderr=True)

STRATEGY_CHOICES = click.Choice(["text", "docx", "pdf", "xlsx"])
CATEGORY_CHOICES = click.Choice([c.value for c in PayloadCategory])


@click.command()
@click.option("--tool", "-t", default="dlpscan", show_default=True, help="DLP adapter to use")
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
def scan(
    tool, input_value, fmt, output, url, api_key, timeout,
    strategies, concurrency, categories, variant_groups,
):
    """Run DLP evasion tests."""
    load_builtins()

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
        payloads = get_payloads(filter_cats)

    if not payloads:
        err_console.print("[red]No payloads to test.[/red]")
        sys.exit(1)

    # Resolve adapter
    config = {"base_url": url, "api_key": api_key, "timeout": timeout}
    try:
        adapter = get_adapter(tool, config)
    except KeyError as e:
        err_console.print(f"[red]{e}[/red]")
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

    # Run engine
    err_console.print(
        f"[dim]Running evadex scan against [bold]{tool}[/bold] at {url}...[/dim]"
    )
    engine = Engine(
        adapter=adapter,
        generators=generators,
        concurrency=concurrency,
        strategies=active_strategies,
    )
    results = engine.run(payloads)

    # Summary
    from evadex.core.result import SeverityLevel
    total  = len(results)
    passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
    fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
    errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)
    parts  = [f"[green]{passes} detected[/green]", f"[red]{fails} evaded[/red]"]
    if errors:
        parts.append(f"[yellow]{errors} errors[/yellow]")
    err_console.print(f"[green]Done.[/green] {total} tests \u2014 " + ", ".join(parts))

    # Report
    reporter = HtmlReporter() if fmt == "html" else JsonReporter()
    rendered = reporter.render(results)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(rendered)
        err_console.print(f"[dim]Report written to {output}[/dim]")
    else:
        sys.stdout.buffer.write(rendered.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
