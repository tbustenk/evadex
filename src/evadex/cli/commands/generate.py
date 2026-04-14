"""evadex generate command — create test documents filled with synthetic sensitive data."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from evadex.core.result import PayloadCategory
from evadex.payloads.tiers import get_tier_categories, VALID_TIERS

err_console = Console(stderr=True)

_FORMAT_CHOICES = click.Choice(["xlsx", "docx", "pdf", "csv", "txt"], case_sensitive=False)
_CATEGORY_CHOICES = click.Choice(
    [c.value for c in PayloadCategory if c != PayloadCategory.UNKNOWN],
    case_sensitive=False,
)
_TIER_CHOICES = click.Choice(sorted(VALID_TIERS), case_sensitive=False)

_VALID_BATCH_FORMATS = {"xlsx", "docx", "pdf", "csv", "txt"}


@click.command("generate")
@click.option(
    "--format", "fmt",
    default=None,
    type=_FORMAT_CHOICES,
    help="Output file format (single format). Use --formats for multiple.",
)
@click.option(
    "--formats", "batch_formats",
    default=None,
    metavar="FMT,FMT,...",
    help=(
        "Comma-separated list of formats to generate in one pass.  "
        "Output is the path stem; extensions are appended automatically.  "
        "Example: --formats xlsx,docx,pdf --output reports/test  "
        "→ test.xlsx, test.docx, test.pdf"
    ),
)
@click.option(
    "--tier", "tier",
    default=None,
    type=_TIER_CHOICES,
    help=(
        "Payload tier to use when --category is not specified.  "
        "One of: banking (default), core, regional, full."
    ),
)
@click.option(
    "--category", "categories",
    multiple=True,
    type=_CATEGORY_CHOICES,
    metavar="CATEGORY",
    help=(
        "Payload category to include.  Repeat for multiple categories. "
        "Overrides --tier when set."
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
    help=(
        "Output file path.  With --format, must match the format extension.  "
        "With --formats, treated as a stem — extensions are appended."
    ),
)
@click.option(
    "--include-heuristic",
    is_flag=True,
    default=False,
    help="Include heuristic payload categories (AWS keys, tokens, JWT, etc.).",
)
@click.option(
    "--language",
    default="en",
    show_default=True,
    type=click.Choice(["en", "fr-CA"], case_sensitive=False),
    help="Language for keyword context sentences: 'en' (English) or 'fr-CA' (Canadian French).",
)
def generate(
    fmt: str | None,
    batch_formats: str | None,
    tier: str | None,
    categories: tuple[str, ...],
    count: int,
    evasion_rate: float,
    keyword_rate: float,
    techniques: tuple[str, ...],
    random_mode: bool,
    seed: int | None,
    output: str,
    include_heuristic: bool,
    language: str,
) -> None:
    """Generate test documents filled with synthetic sensitive data for DLP testing.

    Values are embedded in realistic business sentences, tables, and paragraphs.
    Evasion variants apply the same obfuscation techniques used by evadex scan.

    \b
    Examples:
      evadex generate --format csv  --category credit_card --count 200 --output cards.csv
      evadex generate --format xlsx --category ssn --category iban --count 50  --output test.xlsx
      evadex generate --formats xlsx,docx,pdf --tier banking --count 100 --output reports/banking
      evadex generate --format docx --evasion-rate 0.6 --technique homoglyph_substitution --output doc.docx
      evadex generate --format txt  --random --count 100 --seed 42 --output test.txt
    """
    # ── Validate format args ───────────────────────────────────────────────────
    if not fmt and not batch_formats:
        raise click.UsageError("Provide --format or --formats.")
    if fmt and batch_formats:
        raise click.UsageError("--format and --formats are mutually exclusive.")

    # Parse --formats into a list
    formats: list[str]
    if batch_formats:
        formats = [f.strip().lower() for f in batch_formats.split(",") if f.strip()]
        bad = [f for f in formats if f not in _VALID_BATCH_FORMATS]
        if bad:
            raise click.UsageError(
                f"Unknown format(s) in --formats: {', '.join(bad)}. "
                f"Valid: {', '.join(sorted(_VALID_BATCH_FORMATS))}"
            )
        if not formats:
            raise click.UsageError("--formats must contain at least one format.")
    else:
        formats = [fmt]  # type: ignore[list-item]

    # ── Validate output path ───────────────────────────────────────────────────
    out = Path(output)
    if not out.parent.exists():
        err_console.print(
            f"[red]Cannot write '{output}': parent directory does not exist.[/red]"
        )
        sys.exit(1)

    # For --formats, output is a stem (no extension check required).
    # For single --format, we tolerate any path (existing behaviour).

    # ── Resolve categories ─────────────────────────────────────────────────────
    from evadex.generate.generator import GenerateConfig, generate_entries

    if categories:
        cats = [PayloadCategory(c) for c in categories]
    else:
        effective_tier = tier or "banking"
        tier_cats = get_tier_categories(effective_tier)
        # tier_cats is None for full tier → generate_entries gets cats=None → all structured
        cats = list(tier_cats) if tier_cats is not None else None
        if not tier:
            err_console.print(
                f"[dim]Tier: banking (default) — use --tier full for all categories[/dim]"
            )
        else:
            err_console.print(f"[dim]Tier: {effective_tier}[/dim]")

    techs = list(techniques) if techniques else None

    # ── Generate entries once (shared across all formats) ─────────────────────
    err_console.print(
        f"[bold]evadex generate[/bold] — "
        f"format=[cyan]{', '.join(formats)}[/cyan]  "
        f"count=[cyan]{count}[/cyan]  evasion-rate=[cyan]{evasion_rate}[/cyan]"
    )
    if seed is not None:
        err_console.print(f"  seed: [dim]{seed}[/dim]")

    # Build config with a placeholder fmt (overridden per-format during writing)
    config = GenerateConfig(
        fmt=formats[0],
        categories=cats,
        count=count,
        evasion_rate=evasion_rate,
        keyword_rate=keyword_rate,
        techniques=techs,
        random_mode=random_mode,
        seed=seed,
        output=output,
        include_heuristic=include_heuristic,
        language=language,
    )

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

    # ── Write output for each format ──────────────────────────────────────────
    from evadex.generate.writers import get_writer

    for write_fmt in formats:
        # Determine output path: stem + extension for --formats, original path for --format
        if batch_formats:
            out_path = str(out.with_suffix(f".{write_fmt}"))
        else:
            out_path = output

        writer = get_writer(write_fmt)
        try:
            writer(entries, out_path)
        except OSError as exc:
            err_console.print(f"[red]Cannot write '{out_path}': {exc.strerror}[/red]")
            sys.exit(1)

        err_console.print(f"[green]✓ Written:[/green] {out_path}")
