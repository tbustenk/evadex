import click
from rich.console import Console
from rich.table import Table
from evadex.core.result import CATEGORY_TYPES, CategoryType
from evadex.payloads.builtins import BUILTIN_PAYLOADS

console = Console()


@click.command("list-payloads")
@click.option("--type", "filter_type", type=click.Choice(["structured", "heuristic"]),
              default=None, help="Filter by structured or heuristic type")
def list_payloads(filter_type):
    """List all built-in test payloads."""
    payloads = BUILTIN_PAYLOADS
    if filter_type:
        target = CategoryType.STRUCTURED if filter_type == "structured" else CategoryType.HEURISTIC
        payloads = [p for p in payloads if CATEGORY_TYPES.get(p.category) == target]

    table = Table(show_header=True, header_style="bold dim", border_style="dim")
    table.add_column("Label", style="bold", min_width=30)
    table.add_column("Value", style="cyan", min_width=36)
    table.add_column("Category", style="blue", min_width=14)
    table.add_column("Type", min_width=10)

    for p in payloads:
        cat_type = CATEGORY_TYPES.get(p.category)
        type_str = cat_type.value if cat_type else "unknown"
        type_style = "green" if type_str == "structured" else "yellow"
        table.add_row(
            p.label,
            p.value,
            p.category.value,
            f"[{type_style}]{type_str}[/{type_style}]",
        )

    console.print(table)
    console.print(f"[dim]{len(payloads)} payload(s)[/dim]")
