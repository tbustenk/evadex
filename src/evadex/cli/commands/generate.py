"""evadex generate command — create test documents filled with synthetic sensitive data."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from evadex.core.result import PayloadCategory

err_console = Console(stderr=True)

_FORMAT_CHOICES = click.Choice(["xlsx", "docx", "pdf", "csv", "txt"], case_sensitive=False)
_CATEGORY_CHOICES = click.Choice(
    [c.value for c in PayloadCategory if c != PayloadCategory.UNKNOWN],
    case_sensitive=False,
)


@click.command("generate")
@click.option(
    "--format", "fmt",
    required=True,
    type=_FORMAT_CHOICES,
    help="Output file format.",
)
@click.option(
    "--category", "categories",
    multiple=True,
    type=_CATEGORY_CHOICES,
    metavar="CATEGORY",
    help=(
        "Payload category to include.  Repeat for multiple categories. "
        "Omit to include all structured categories."
    ),
)
@click.option(
    "--count",
    default=100,
    show_default=True,
    type=click.IntRange(1, 10_000),
    help="Number of test values to generate per category.",
)
@click.option(
    "--evasion-rate",
    default=0.5,
    show_default=True,
    type=click.FloatRange(0.0, 1.0),
    help="Proportion of values that are evasion variants (0.0–1.0).",
)
@click.option(
    "--keyword-rate",
    default=0.5,
    show_default=True,
    type=click.FloatRange(0.0, 1.0),
    help="Proportion of values wrapped in keyword context sentences (0.0–1.0).",
)
@click.option(
    "--technique", "techniques",
    multiple=True,
    metavar="TECHNIQUE",
    help=(
        "Limit evasion variants to a specific technique name.  "
        "Repeat for multiple.  Omit for random selection."
    ),
)
@click.option(
    "--random", "random_mode",
    is_flag=True,
    default=False,
    help="Randomise categories, evasion rate, and keyword rate.",
)
@click.option(
    "--seed",
    type=int,
    default=None,
    metavar="INT",
    help="Integer seed for reproducible output.",
)
@click.option(
    "--output",
    required=True,
    type=click.Path(),
    metavar="PATH",
    help="Output file path (must match --format extension).",
)
@click.option(
    "--include-heuristic",
    is_flag=True,
    default=False,
    help="Include heuristic payload categories (AWS keys, tokens, JWT, etc.).",
)
def generate(
    fmt: str,
    categories: tuple[str, ...],
    count: int,
    evasion_rate: float,
    keyword_rate: float,
    techniques: tuple[str, ...],
    random_mode: bool,
    seed: int | None,
    output: str,
    include_heuristic: bool,
) -> None:
    """Generate test documents filled with synthetic sensitive data for DLP testing.

    Values are embedded in realistic business sentences, tables, and paragraphs.
    Evasion variants apply the same obfuscation techniques used by evadex scan.

    \b
    Examples:
      evadex generate --format csv  --category credit_card --count 200 --output cards.csv
      evadex generate --format xlsx --category ssn --category iban --count 50  --output test.xlsx
      evadex generate --format docx --evasion-rate 0.6 --technique homoglyph_substitution --output doc.docx
      evadex generate --format txt  --random --count 100 --seed 42 --output test.txt
    """
    # ── Validate output path ───────────────────────────────────────────────
    out = Path(output)
    if not out.parent.exists():
        err_console.print(
            f"[red]Cannot write '{output}': parent directory does not exist.[/red]"
        )
        sys.exit(1)

    # ── Build config ───────────────────────────────────────────────────────
    from evadex.generate.generator import GenerateConfig, generate_entries

    cats = [PayloadCategory(c) for c in categories] if categories else None
    techs = list(techniques) if techniques else None

    config = GenerateConfig(
        fmt=fmt,
        categories=cats,
        count=count,
        evasion_rate=evasion_rate,
        keyword_rate=keyword_rate,
        techniques=techs,
        random_mode=random_mode,
        seed=seed,
        output=output,
        include_heuristic=include_heuristic,
    )

    # ── Generate entries ───────────────────────────────────────────────────
    err_console.print(f"[bold]evadex generate[/bold] — format=[cyan]{fmt}[/cyan]  "
                      f"count=[cyan]{count}[/cyan]  evasion-rate=[cyan]{evasion_rate}[/cyan]")
    if seed is not None:
        err_console.print(f"  seed: [dim]{seed}[/dim]")

    entries = generate_entries(config)
    if not entries:
        err_console.print("[yellow]No payloads matched the requested categories — nothing generated.[/yellow]")
        sys.exit(1)

    evasion_count = sum(1 for e in entries if e.technique is not None)
    err_console.print(
        f"  [dim]{len(entries)} entries "
        f"({evasion_count} evasion variants, "
        f"{len(entries) - evasion_count} plain)[/dim]"
    )

    # ── Write output ───────────────────────────────────────────────────────
    from evadex.generate.writers import get_writer

    writer = get_writer(fmt)
    try:
        writer(entries, output)
    except OSError as exc:
        err_console.print(f"[red]Cannot write '{output}': {exc.strerror}[/red]")
        sys.exit(1)

    err_console.print(f"[green]✓ Written:[/green] {output}")
