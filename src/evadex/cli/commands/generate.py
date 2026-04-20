"""evadex generate command — create test documents filled with synthetic sensitive data."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from evadex.core.result import PayloadCategory
from evadex.payloads.tiers import get_tier_categories, VALID_TIERS

err_console = Console(stderr=True)

_ALL_FORMATS = [
    "xlsx", "docx", "pdf", "csv", "txt", "eml", "msg",
    "json", "xml", "sql", "log",
    # Barcode/QR image formats — require `pip install evadex[barcodes]`.
    "png", "jpg", "multi_barcode_png",
    # Siphon EDM bulk-registration format.
    "edm_json",
    # Data-format extractors — `parquet` requires `pip install evadex[data-formats]`
    # (pyarrow); `sqlite` uses stdlib only.
    "parquet", "sqlite",
    # Archive and message-format extractors — `7z` requires
    # `pip install evadex[archives]` (py7zr); the rest use stdlib only.
    "zip", "zip_nested", "7z", "mbox", "ics", "warc",
]
_FORMAT_CHOICES = click.Choice(_ALL_FORMATS, case_sensitive=False)
_BARCODE_TYPE_CHOICES = click.Choice(
    ["qr", "code128", "ean13", "pdf417", "datamatrix", "random"],
    case_sensitive=False,
)
_CATEGORY_CHOICES = click.Choice(
    [c.value for c in PayloadCategory if c != PayloadCategory.UNKNOWN],
    case_sensitive=False,
)
_TIER_CHOICES = click.Choice(sorted(VALID_TIERS), case_sensitive=False)
_TEMPLATE_CHOICES = click.Choice(
    ["generic", "invoice", "statement", "hr_record", "audit_report",
     "source_code", "config_file", "chat_log", "medical_record",
     "env_file", "secrets_file", "code_with_secrets", "lsh_variants"],
    case_sensitive=False,
)

_VALID_BATCH_FORMATS = set(_ALL_FORMATS)

# Logical format → real on-disk extension. Most formats use their own
# name, but a few alias (sqlite → .db, multi_barcode_png → .png,
# zip_nested → .zip — all carry the same magic / MIME).
_FORMAT_EXTENSION = {
    "sqlite": "db",
    "multi_barcode_png": "png",
    "zip_nested": "zip",
}


def _parse_key_int_pair(value: str) -> tuple[str, int]:
    """Parse 'key:int' into (key, int)."""
    if ":" not in value:
        raise click.BadParameter(f"Expected key:value format, got {value!r}")
    k, v = value.rsplit(":", 1)
    try:
        return k, int(v)
    except ValueError:
        raise click.BadParameter(f"Expected integer after ':', got {v!r}")


def _parse_key_float_pair(value: str) -> tuple[str, float]:
    """Parse 'key:float' into (key, float)."""
    if ":" not in value:
        raise click.BadParameter(f"Expected key:value format, got {value!r}")
    k, v = value.rsplit(":", 1)
    try:
        return k, float(v)
    except ValueError:
        raise click.BadParameter(f"Expected number after ':', got {v!r}")


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
# ── Part 2: Granular amount options ──────────────────────────────────────────
@click.option(
    "--count-per-category",
    multiple=True,
    metavar="CATEGORY:COUNT",
    help=(
        "Override count for a specific category.  Repeat for multiple.  "
        "Example: --count-per-category credit_card:200 --count-per-category sin:50"
    ),
)
@click.option(
    "--total",
    type=click.IntRange(1, 100_000),
    default=None,
    metavar="N",
    help=(
        "Generate exactly N records distributed evenly across selected categories.  "
        "Mutually exclusive with --count."
    ),
)
@click.option(
    "--density",
    default="medium",
    show_default=True,
    type=click.Choice(["low", "medium", "high"], case_sensitive=False),
    help=(
        "Controls how frequently sensitive values appear in filler text.  "
        "low=one per paragraph, medium=one per 2-3 sentences, high=almost every sentence."
    ),
)
# ── Part 3: Granular evasion options ─────────────────────────────────────────
@click.option(
    "--technique-group",
    multiple=True,
    metavar="GENERATOR",
    help=(
        "Limit evasion variants to a specific generator family.  "
        "Repeat for multiple.  Example: --technique-group unicode_encoding"
    ),
)
@click.option(
    "--technique-mix",
    default=None,
    metavar="GEN:PROP,...",
    help=(
        "Exact proportion per technique group.  "
        "Example: --technique-mix unicode_encoding:0.4,encoding:0.3,splitting:0.3  "
        "Proportions must sum to 1.0."
    ),
)
@click.option(
    "--evasion-per-category",
    multiple=True,
    metavar="CATEGORY:RATE",
    help=(
        "Override evasion rate for a specific category.  Repeat for multiple.  "
        "Example: --evasion-per-category credit_card:0.7 --evasion-per-category sin:0.2"
    ),
)
@click.option(
    "--evasion-mode",
    type=click.Choice(["random", "weighted", "adversarial", "exhaustive"],
                      case_sensitive=False),
    default="random",
    show_default=True,
    help=(
        "How to pick evasion techniques. "
        "'random' = uniform; "
        "'weighted' = bias toward techniques that have evaded best in past audit history; "
        "'adversarial' = only techniques with ≤ 50% historical detection; "
        "'exhaustive' = deterministic first-match. "
        "Reads history from --audit-log (default: results/audit.jsonl). "
        "Falls back to random with a warning if no history exists yet."
    ),
)
@click.option(
    "--audit-log",
    default="results/audit.jsonl",
    show_default=True,
    metavar="PATH",
    help=(
        "Audit-log path used by --evasion-mode weighted/adversarial to "
        "load technique history. Ignored for random and exhaustive modes."
    ),
)
# ── Part 4: Template / noise options ─────────────────────────────────────────
@click.option(
    "--template",
    default="generic",
    show_default=True,
    type=_TEMPLATE_CHOICES,
    help=(
        "Document template controlling structure and tone.  "
        "Options: generic, invoice, statement, hr_record, audit_report, "
        "source_code, config_file, chat_log, medical_record, "
        "env_file, secrets_file, code_with_secrets, lsh_variants "
        "(N near-duplicate sections of a base banking memo for testing "
        "Siphon's LSH document-similarity engine — split on '--- VARIANT N ---')."
    ),
)
@click.option(
    "--noise-level",
    default="medium",
    show_default=True,
    type=click.Choice(["low", "medium", "high"], case_sensitive=False),
    help=(
        "Controls ratio of filler text to sensitive values.  "
        "low=mostly values, medium=balanced, high=lots of business text."
    ),
)
@click.option(
    "--barcode-type",
    "barcode_type",
    default="qr",
    show_default=True,
    type=_BARCODE_TYPE_CHOICES,
    help=(
        "Barcode encoding for --format png|jpg|multi_barcode_png.  "
        "qr (default, unicode up to 4296 chars), code128 (ASCII 1D), "
        "ean13 (13 digits, padded from value), pdf417 (2D, requires pdf417gen), "
        "datamatrix (2D, requires pylibdmtx), or random (mixed)."
    ),
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
    count_per_category: tuple[str, ...],
    total: int | None,
    density: str,
    technique_group: tuple[str, ...],
    technique_mix: str | None,
    evasion_per_category: tuple[str, ...],
    evasion_mode: str,
    audit_log: str,
    template: str,
    noise_level: str,
    barcode_type: str,
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
      evadex generate --format json --tier banking --total 1000 --output export.json
      evadex generate --format xlsx --tier banking --evasion-rate 0.5 --technique-group unicode_encoding --output test.xlsx
      evadex generate --format docx --tier banking --template statement --count 100 --output stmt.docx
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

    # ── Parse granular options ────────────────────────────────────────────────
    parsed_count_per_category: dict[str, int] | None = None
    if count_per_category:
        parsed_count_per_category = {}
        for item in count_per_category:
            k, v = _parse_key_int_pair(item)
            parsed_count_per_category[k] = v

    parsed_technique_mix: dict[str, float] | None = None
    if technique_mix:
        parsed_technique_mix = {}
        for pair in technique_mix.split(","):
            pair = pair.strip()
            if not pair:
                continue
            k, v = _parse_key_float_pair(pair)
            parsed_technique_mix[k] = v
        # Validate proportions sum to 1.0
        total_prop = sum(parsed_technique_mix.values())
        if abs(total_prop - 1.0) > 0.01:
            raise click.UsageError(
                f"--technique-mix proportions must sum to 1.0 "
                f"(got {total_prop:.3f})"
            )

    parsed_evasion_per_category: dict[str, float] | None = None
    if evasion_per_category:
        parsed_evasion_per_category = {}
        for item in evasion_per_category:
            k, v = _parse_key_float_pair(item)
            if not 0.0 <= v <= 1.0:
                raise click.UsageError(
                    f"Evasion rate for {k!r} must be 0.0–1.0, got {v}"
                )
            parsed_evasion_per_category[k] = v

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
                "[dim]Tier: banking (default) — use --tier full for all categories[/dim]"
            )
        else:
            err_console.print(f"[dim]Tier: {effective_tier}[/dim]")

    techs = list(techniques) if techniques else None
    tech_groups = list(technique_group) if technique_group else None

    # ── Generate entries once (shared across all formats) ─────────────────────
    display_count = str(total) + " total" if total else str(count)
    err_console.print(
        f"[bold]evadex generate[/bold] — "
        f"format=[cyan]{', '.join(formats)}[/cyan]  "
        f"count=[cyan]{display_count}[/cyan]  evasion-rate=[cyan]{evasion_rate}[/cyan]"
    )
    if seed is not None:
        err_console.print(f"  seed: [dim]{seed}[/dim]")

    # ── Resolve --evasion-mode (load history if needed) ───────────────────────
    technique_history: dict | None = None
    em = evasion_mode.lower()
    if em in ("weighted", "adversarial"):
        from evadex.feedback.technique_history import (
            has_history, load_technique_history,
        )
        if has_history(audit_log):
            stats = load_technique_history(audit_log)
            technique_history = {t: s.average_success for t, s in stats.items()}
        else:
            err_console.print(
                f"[yellow]No technique history found in {audit_log} — "
                f"--evasion-mode {em} falls back to random. "
                f"Run a few scans with --audit-log set to build history.[/yellow]"
            )
            em = "random"

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
        count_per_category=parsed_count_per_category,
        total=total,
        density=density,
        technique_group=tech_groups,
        technique_mix=parsed_technique_mix,
        evasion_per_category=parsed_evasion_per_category,
        template=template,
        noise_level=noise_level,
        evasion_mode=em,
        technique_history=technique_history,
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
    from evadex.generate.writers import get_writer, set_writer_config
    set_writer_config(
        template=template,
        noise_level=noise_level,
        density=density,
        seed=seed,
        barcode_type=barcode_type,
        language=language,
    )

    for write_fmt in formats:
        # Determine output path: stem + extension for --formats, original path for --format
        if batch_formats:
            ext = _FORMAT_EXTENSION.get(write_fmt, write_fmt)
            out_path = str(out.with_suffix(f".{ext}"))
        else:
            out_path = output

        writer = get_writer(write_fmt)
        try:
            writer(entries, out_path)
        except OSError as exc:
            err_console.print(f"[red]Cannot write '{out_path}': {exc.strerror}[/red]")
            sys.exit(1)
        except RuntimeError as exc:
            err_console.print(f"[red]{exc}[/red]")
            sys.exit(1)

        err_console.print(f"[green]✓ Written:[/green] {out_path}")
