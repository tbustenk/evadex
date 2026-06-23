"""evadex explain — show what evadex generates for a category/technique pair.

Produces a human-readable breakdown of:
  - What sample value is used for the category
  - What variants the technique family generates
  - Why a DLP scanner may miss each variant
  - The recommended scanner fix
"""

from __future__ import annotations

import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.core.registry import load_builtins, all_generators
from evadex.core.result import PayloadCategory
from evadex.payloads.builtins import BUILTIN_PAYLOADS

err_console = Console(stderr=True)

# Per-technique family context and fix rationale — mirrors list_techniques.py
_FAMILY_FIX: dict[str, str] = {
    "unicode_whitespace": (
        "NFKC-normalise and strip all non-ASCII whitespace characters before pattern matching."
    ),
    "unicode_encoding": (
        "NFKC-normalise, then apply the Unicode TR39 confusables map to fold "
        "Cyrillic/Greek/fullwidth back to ASCII."
    ),
    "bidirectional": (
        "Flag or reject any input containing U+202A..U+202E or U+2066..U+2069 "
        "regardless of pattern match."
    ),
    "soft_hyphen": (
        "Strip U+00AD before matching; log any strip that removes more than two "
        "characters as an evasion signal."
    ),
    "encoding": (
        "Heuristically detect and decode common encodings (base64, hex, percent, "
        "HTML entities) before pattern matching."
    ),
    "encoding_chains": (
        "Decode iteratively to a bounded depth (3-4 layers); log any match that "
        "required >= 2 decodes."
    ),
    "splitting": (
        "Use a sliding window that joins across whitespace/trivial separators; "
        "strip HTML tags before scanning."
    ),
    "structural": (
        "Allow a broader length range; detect common rotations; scan structured "
        "formats by value, not by raw bytes."
    ),
    "delimiter": (
        "Accept a broader delimiter character class in patterns, or normalise "
        "delimiters before matching."
    ),
    "leetspeak": "Run a leetspeak-to-ASCII normaliser before pattern matching.",
    "regional_digits": (
        "Use \\d in Unicode mode, or normalise digit scripts to ASCII via "
        "unicodedata.decimal() before matching."
    ),
    "morse_code": (
        "Detect high concentrations of . and - with consistent group separators "
        "and decode heuristically."
    ),
    "context_injection": (
        "Apply pattern matchers independently of volume filters; don't let a "
        "low-entropy wrapper cancel a high-confidence match."
    ),
    "entropy_evasion": (
        "Combine entropy with keyword proximity — a low-entropy string near the "
        "word 'password' is still a finding."
    ),
    "archive_evasion": (
        "Enable recursive archive extraction with a depth cap to avoid zip bombs."
    ),
    "barcode_evasion": (
        "Enable image OCR + barcode decoding for content that may contain printed "
        "forms (statements, invoices, shipping labels)."
    ),
    "capital_markets": (
        "Add financial-instrument identifier patterns (CUSIP, ISIN, SEDOL, LEI, "
        "FIGI, etc.) to the detection ruleset."
    ),
}


def _find_sample(category_value: str) -> Optional[str]:
    """Return a sample value for the given PayloadCategory enum value string."""
    for p in BUILTIN_PAYLOADS:
        if p.category.value == category_value:
            return p.value
    return None


def _list_categories() -> list[str]:
    return sorted(c.value for c in PayloadCategory)


def _list_generators() -> list[str]:
    load_builtins()
    return sorted(g.name for g in all_generators())


@click.command("explain")
@click.option(
    "--category",
    "category_value",
    required=True,
    help=(
        "Payload category to explain (e.g. credit_card, ssn, iban). "
        "Run [evadex list-payloads] for the full list."
    ),
)
@click.option(
    "--technique",
    "technique_family",
    default=None,
    help=(
        "Evasion technique family to explain (e.g. encoding, unicode_encoding, "
        "splitting). Omit to show all families that apply to the category."
    ),
)
@click.option(
    "--sample",
    "custom_sample",
    default=None,
    help="Override the built-in sample value for the category.",
)
@click.option(
    "--max-variants",
    "max_variants",
    default=20,
    show_default=True,
    type=int,
    help="Maximum number of variant examples to show per technique family.",
)
def explain(
    category_value: str,
    technique_family: Optional[str],
    custom_sample: Optional[str],
    max_variants: int,
) -> None:
    """Show what evadex generates for a category/technique pair.

    Displays the variant values that would be submitted to a scanner for the
    given payload category and evasion technique, along with the detection
    rationale and recommended scanner fix.

    \b
    Examples:
      evadex explain --category credit_card --technique encoding
      evadex explain --category ssn --technique splitting
      evadex explain --category iban
      evadex explain --category credit_card --technique encoding --sample 4111111111111111
    """
    # Validate category
    valid_cats = _list_categories()
    if category_value not in valid_cats:
        err_console.print(
            f"[red]Unknown category: {category_value!r}[/red]\n"
            "Run [bold]evadex list-payloads[/bold] for valid category names."
        )
        sys.exit(1)

    try:
        target_cat = PayloadCategory(category_value)
    except ValueError:
        err_console.print(f"[red]Unknown category: {category_value!r}[/red]")
        sys.exit(1)

    sample = custom_sample or _find_sample(category_value)
    if not sample:
        err_console.print(
            f"[yellow]No built-in sample found for category '{category_value}'.[/yellow]\n"
            "Provide one with [bold]--sample VALUE[/bold]."
        )
        sys.exit(1)

    load_builtins()
    generators = all_generators()

    # Filter to applicable generators
    applicable = []
    for g in generators:
        cats = g.applicable_categories
        if cats is None or target_cat in cats:
            applicable.append(g)

    if technique_family:
        applicable = [g for g in applicable if g.name == technique_family]
        if not applicable:
            valid_gens = _list_generators()
            err_console.print(
                f"[red]No generator named {technique_family!r} applies to "
                f"category '{category_value}'.[/red]\n"
                f"Available generators: {', '.join(valid_gens)}"
            )
            sys.exit(1)

    console = Console()
    console.print()
    console.print(f"[bold]Category:[/bold]  [cyan]{category_value}[/cyan]")
    console.print(f"[bold]Sample value:[/bold]  [green]{sample}[/green]")
    console.print(
        f"[bold]Generators:[/bold]  {len(applicable)} applicable "
        f"({'filtered to: ' + technique_family if technique_family else 'all'})"
    )
    console.print()

    for gen in applicable:
        try:
            variants = list(gen.generate(sample))
        except Exception as exc:
            console.print(
                f"[red]Error generating variants for {gen.name!r}: {exc}[/red]"
            )
            continue

        if not variants:
            continue

        # Deduplicate by technique name, keeping first occurrence
        seen: dict[str, tuple[str, str]] = {}
        for v in variants:
            if v.technique not in seen:
                seen[v.technique] = (v.transform_name, v.value)

        fix = _FAMILY_FIX.get(gen.name, "No specific fix documented.")

        console.print(
            f"[bold cyan]{gen.name}[/bold cyan]  [dim]({len(seen)} technique(s))[/dim]"
        )
        console.print(
            "  [white]Why it evades:[/white] Pattern scanners see the "
            "transformed form — not the canonical value — and fail to match."
        )
        console.print(f"  [white]Fix:[/white] {fix}")
        console.print()

        table = Table(
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            pad_edge=False,
        )
        table.add_column("Technique", style="cyan", min_width=28)
        table.add_column("Description", min_width=36)
        table.add_column("Example output", style="green", min_width=20, overflow="fold")

        for i, (technique, (desc, output)) in enumerate(sorted(seen.items())):
            if i >= max_variants:
                table.add_row(
                    "[dim]…[/dim]",
                    f"[dim]{len(seen) - max_variants} more (use --max-variants to show)[/dim]",
                    "",
                )
                break
            display = output if len(output) <= 52 else output[:49] + "..."
            table.add_row(technique, desc, display)

        console.print(table)
        console.print()
