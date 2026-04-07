import sys
import click
from rich.console import Console
from rich.table import Table
from evadex.core.registry import load_builtins, all_generators

console = Console()


@click.command("list-techniques")
@click.option("--generator", "-g", "filter_gen", default=None,
              help="Show only techniques from this generator")
def list_techniques(filter_gen):
    """List all registered evasion generators and their techniques."""
    load_builtins()
    generators = all_generators()

    if filter_gen:
        generators = [g for g in generators if g.name == filter_gen]
        if not generators:
            console.print(f"[red]No generator named {filter_gen!r}[/red]")
            sys.exit(1)

    total = 0
    for gen in generators:
        # Collect techniques by running generate on a representative value
        # that exercises all branches (alphanumeric, has digits and letters)
        sample = "4532015112830366"
        try:
            variants = list(gen.generate(sample))
        except Exception as exc:
            console.print(f"[red]Error loading generator {gen.name!r}: {exc}[/red]")
            variants = []

        # Deduplicate by technique name
        seen = {}
        for v in variants:
            if v.technique not in seen:
                seen[v.technique] = v.transform_name

        cats = gen.applicable_categories
        if cats:
            cats_str = ", ".join(sorted(c.value for c in cats))
        else:
            cats_str = "all"

        table = Table(
            title=f"[bold accent]{gen.name}[/bold accent]  [dim](applies to: {cats_str})[/dim]",
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            title_justify="left",
        )
        table.add_column("Technique", style="cyan", min_width=36)
        table.add_column("Description", min_width=50)

        for technique, description in sorted(seen.items()):
            table.add_row(technique, description)

        console.print(table)
        total += len(seen)

    console.print(f"[dim]{total} technique(s) across {len(generators)} generator(s)[/dim]")
