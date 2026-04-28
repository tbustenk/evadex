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
    ["generic", "invoice", "statement", "banking-statement", "banking_statement",
     "hr_record", "audit_report",
     "source_code", "config_file", "chat_log", "medical_record",
     "env_file", "secrets_file", "code_with_secrets",
     "lsh_variants", "lsh_corpus",
     "email_thread",
     # Capital markets templates (v3.25.0)
     "trade_confirmation", "swift_mt103", "settlement_instruction",
     "bloomberg_export", "risk_report"],
    case_sensitive=False,
)

# Default similarity ladder when --lsh-variants is used without an
# explicit distortion list. Each rate is chosen so the empirical
# Jaccard vs the base document lands close to the round percentage
# reported in the README / UI. Kept in descending similarity order
# so file N-0 is the least distorted and N-(k-1) is the most.
_LSH_DEFAULT_DISTORTIONS = [0.05, 0.10, 0.20, 0.30, 0.40]

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
    required=False,
    default=None,
    type=click.Path(),
    metavar="PATH",
    help=(
        "Output file path.  With --format, must match the format extension.  "
        "With --formats, treated as a stem — extensions are appended.  "
        "Omit to enter interactive mode."
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
        "Siphon's LSH document-similarity engine — split on '--- VARIANT N ---'). "
        "Capital markets: trade_confirmation (equity trade confirm with ISIN/CUSIP/LEI), "
        "swift_mt103 (SWIFT MT103 payment with IBAN/BIC), "
        "settlement_instruction (CLS/DTCC settlement with ISIN/BIC), "
        "bloomberg_export (Bloomberg terminal CSV export with ISIN/SEDOL/FIGI), "
        "risk_report (counterparty risk summary with LEI/IBAN)."
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
    "--lsh-variants",
    "lsh_variants",
    default=5, show_default=True, type=int,
    help=(
        "Used only with --template lsh_corpus. Produces N near-duplicate "
        "variants per base document at descending similarity levels "
        "(~95%, 90%, 80%, 70%, 60% by default). --output must be a "
        "directory; one file is written per (base, variant) pair. "
        "Each variant keeps the base document's sensitive values "
        "intact so the scanner's LSH engine can be evaluated across "
        "similarity thresholds."
    ),
)
@click.option(
    "--lsh-distortions",
    "lsh_distortions",
    default=None, metavar="FLOAT,FLOAT,...",
    help=(
        "Optional comma-separated list of distortion rates (0.0–1.0) to "
        "override the default LSH ladder. Example: --lsh-distortions "
        "0.02,0.08,0.15,0.25,0.35. Length sets --lsh-variants; the two "
        "flags are mutually exclusive."
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
    output: str | None,
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
    lsh_variants: int,
    lsh_distortions: str | None,
    barcode_type: str,
) -> None:
    """Generate realistic test files containing synthetic sensitive data.

    \b
    Values are embedded in realistic business sentences, tables, and paragraphs.
    Run with no flags for interactive mode.

    \b
    Examples:
      evadex generate                                           # interactive mode
      evadex generate --format xlsx --count 100                 # 100-record spreadsheet
      evadex generate --format docx --template banking-statement # bank statement
      evadex generate --formats xlsx,docx,pdf --tier banking    # all formats at once
      evadex generate --format txt  --random --count 100 --seed 42 --output test.txt
      evadex generate --format json --tier banking --total 1000 --output export.json
      evadex generate --format xlsx --tier banking --evasion-rate 0.5 --technique-group unicode_encoding --output test.xlsx
      evadex generate --format docx --tier banking --template statement --count 100 --output stmt.docx
    """
    # ── Interactive mode when invoked with no format/output ───────────────────
    if not fmt and not batch_formats and output is None:
        err_console.print("[bold]evadex generate[/bold] — interactive mode")
        err_console.print()
        _fmt_raw = click.prompt(
            "  What format? (xlsx/docx/pdf/csv)",
            default="xlsx",
        ).strip().lower()
        fmt = _fmt_raw if _fmt_raw in _ALL_FORMATS else "xlsx"
        _count_raw = click.prompt("  How many records?", default="100")
        try:
            count = int(_count_raw)
        except ValueError:
            count = 100
        _ext = _FORMAT_EXTENSION.get(fmt, fmt)
        _default_out = f"test_data.{_ext}"
        output = click.prompt("  Output file?", default=_default_out).strip()
        err_console.print()

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
    if output is None:
        raise click.UsageError(
            "Provide --output PATH, or run with no flags for interactive mode."
        )
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
    #
    # v3.20.0: cold-start no longer falls back to uniform random. The
    # generator uses the seed knowledge base (evadex.feedback.seed_weights)
    # when history is empty, and blends 70 % history + 30 % seed when it
    # isn't. That keeps --evasion-mode weighted useful on day one.
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
                f"[dim]No technique history in {audit_log} — "
                f"--evasion-mode {em} uses seed weights (cold-start).[/dim]"
            )

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

    # ── lsh_corpus: multi-file output ─────────────────────────────────────────
    # Produce ``count`` base documents × ``lsh_variants`` near-duplicates
    # into an output directory. Each (base, variant) pair is rendered by
    # the requested writer with the variant's distortion spliced onto
    # the base's sensitive-value set so the scanner can be evaluated
    # across similarity thresholds while the payload stays constant.
    if template.lower() == "lsh_corpus":
        from evadex.lsh import BASE_DOCUMENTS, distorted_variant, jaccard_similarity
        import random as _random

        # Writers that honour templates (docx/txt/eml) re-render from the
        # entry's category/variant_value rather than its ``embedded_text``,
        # which would collapse every LSH variant back to the same base text.
        # Switch to the generic template for the LSH loop so the distorted
        # variant_text we splice into ``embedded_text`` is what ends up on
        # disk.
        set_writer_config(
            template="generic",
            noise_level=noise_level,
            density=density,
            seed=seed,
            barcode_type=barcode_type,
            language=language,
        )

        # Resolve the distortion ladder — explicit flag overrides the
        # default. Any parse error is a CLI-level UsageError so the
        # operator sees it immediately.
        if lsh_distortions:
            try:
                distortions = [float(x.strip()) for x in lsh_distortions.split(",")
                               if x.strip()]
            except ValueError as exc:
                raise click.UsageError(
                    f"--lsh-distortions must be a comma list of floats "
                    f"(0.0–1.0): {exc}"
                )
            if not distortions or any(not (0.0 <= d <= 1.0) for d in distortions):
                raise click.UsageError(
                    "--lsh-distortions entries must be in [0.0, 1.0]."
                )
        else:
            distortions = _LSH_DEFAULT_DISTORTIONS[:max(1, lsh_variants)]
            # If caller asked for more variants than the default ladder
            # provides, extrapolate linearly up to 0.5 distortion.
            while len(distortions) < max(1, lsh_variants):
                distortions.append(
                    min(0.5, distortions[-1] + 0.1)
                )

        # Output must be a directory. If the caller passed a file path,
        # treat it as the directory name (create it).
        out_dir = Path(output)
        if out_dir.suffix:
            out_dir = out_dir.with_suffix("")
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as exc:
            err_console.print(
                f"[red]Cannot create output directory '{out_dir}': "
                f"{exc.strerror or exc}.[/red]"
            )
            sys.exit(1)

        base_ids = list(BASE_DOCUMENTS.keys())
        lsh_rng = _random.Random(seed if seed is not None else 0)
        manifest: list[dict] = []

        n_bases = max(1, count)
        for b in range(n_bases):
            base_id = base_ids[b % len(base_ids)]
            base_text = BASE_DOCUMENTS[base_id]
            # Share one sensitive-value sample across this base + all
            # its variants so the scanner sees the same payload.
            sensitive = entries[b % len(entries)].variant_value if entries else ""

            for v_idx, rate in enumerate(distortions):
                if rate == 0.0:
                    variant_text = base_text
                else:
                    variant_text = distorted_variant(base_text, rate, lsh_rng)
                if sensitive:
                    variant_text = (
                        f"{variant_text} Reference identifier: {sensitive}."
                    )
                empirical = jaccard_similarity(base_text, variant_text)

                for write_fmt in formats:
                    ext = _FORMAT_EXTENSION.get(write_fmt, write_fmt)
                    fname = f"{base_id}_base{b:02d}_var{v_idx}.{ext}"
                    out_path = str(out_dir / fname)

                    # Wrap the variant text as a one-entry list so the
                    # generic writer path renders it into the target
                    # format. We reuse a single entry's metadata but
                    # swap its embedded text for the variant prose.
                    import dataclasses
                    variant_entry = dataclasses.replace(
                        entries[b % len(entries)],
                        embedded_text=variant_text,
                    )

                    writer = get_writer(write_fmt)
                    try:
                        writer([variant_entry], out_path)
                    except OSError as exc:
                        err_console.print(
                            f"[red]Cannot write '{out_path}': {exc.strerror}[/red]"
                        )
                        sys.exit(1)
                    except RuntimeError as exc:
                        err_console.print(f"[red]{exc}[/red]")
                        sys.exit(1)

                    manifest.append({
                        "file":        fname,
                        "base":        base_id,
                        "base_index":  b,
                        "variant":     v_idx,
                        "distortion":  round(rate, 4),
                        "jaccard":     round(empirical, 4),
                        "format":      write_fmt,
                    })

        # Manifest makes the corpus self-describing — the scanner
        # can be evaluated against the manifest's jaccard column to
        # compute precision/recall at each similarity threshold.
        import json as _json
        manifest_path = out_dir / "manifest.json"
        manifest_path.write_text(
            _json.dumps({
                "base_documents": base_ids,
                "variants":       len(distortions),
                "distortions":    distortions,
                "entries":        manifest,
            }, indent=2),
            encoding="utf-8",
        )
        err_console.print(
            f"[green]✓ LSH corpus written:[/green] {out_dir}/ "
            f"({len(manifest)} files, {len(distortions)} variants × "
            f"{n_bases} bases × {len(formats)} formats)"
        )
        err_console.print(f"  manifest: {manifest_path}")
        return

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
