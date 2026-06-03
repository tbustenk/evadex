"""evadex validate — verify templates generate correctly without errors.

Generates a small sample document (5 records by default), checks the file
opens without corruption, and reports file size and entry count.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

err_console = Console(stderr=True)

# All templates that can be passed to evadex generate --template
_ALL_TEMPLATES = [
    "generic",
    "invoice",
    "statement",
    "banking-statement",
    "hr_record",
    "audit_report",
    "source_code",
    "config_file",
    "chat_log",
    "medical_record",
    "env_file",
    "secrets_file",
    "code_with_secrets",
    "email_thread",
    "trade_confirmation",
    "swift_mt103",
    "settlement_instruction",
    "bloomberg_export",
    "risk_report",
]

_VALID_FORMATS = ["docx", "csv", "xlsx", "pdf", "txt", "json"]


def _validate_one(
    template: str, fmt: str, count: int, scan: bool, tmp_dir: Path
) -> dict:
    """Run a single validate check. Returns a result dict."""
    out_path = tmp_dir / f"{template}.{fmt}"
    t0 = time.perf_counter()
    error: str | None = None
    file_size: int = 0
    entry_count: int = 0

    try:
        from evadex.core.registry import load_builtins
        from evadex.generate.generator import GenerateConfig, generate_entries
        from evadex.generate.writers import get_writer, set_writer_config
        from evadex.payloads.tiers import get_tier_categories
        from evadex.core.result import PayloadCategory

        load_builtins()

        cats_set = get_tier_categories("northam")
        cats = list(cats_set)[:4] if cats_set else [PayloadCategory.CREDIT_CARD, PayloadCategory.SSN]

        config = GenerateConfig(
            fmt=fmt,
            categories=cats,
            count=count,
            evasion_rate=0.3,
            keyword_rate=0.5,
            seed=42,
            output=str(out_path.with_suffix("")),
            template=template,
        )

        entries = generate_entries(config)
        entry_count = len(entries)

        set_writer_config(
            template=template,
            noise_level="medium",
            density="medium",
            seed=42,
            barcode_type="qr",
            language="en",
        )
        writer = get_writer(fmt)
        writer(entries, str(out_path))

        elapsed = time.perf_counter() - t0

        if out_path.exists():
            file_size = out_path.stat().st_size
            _check_file_integrity(out_path, fmt)
        else:
            error = "file not created after write()"

    except Exception as exc:
        elapsed = time.perf_counter() - t0
        error = str(exc)[:120]

    result = {
        "template": template,
        "format": fmt,
        "ok": error is None,
        "error": error,
        "file_size_kb": round(file_size / 1024, 1) if file_size else 0.0,
        "entry_count": entry_count,
        "elapsed_s": round(elapsed, 2),
    }

    if scan and error is None and out_path.exists():
        result["scan"] = {"attempted": False, "note": "scan requires a live scanner"}

    return result


def _check_file_integrity(path: Path, fmt: str) -> None:
    """Raise if the generated file cannot be parsed/read."""
    if fmt in ("docx", "xlsx"):
        import zipfile
        with zipfile.ZipFile(path) as zf:
            _ = zf.namelist()
    elif fmt == "json":
        with open(path, encoding="utf-8") as f:
            json.load(f)
    elif fmt in ("csv", "txt"):
        with open(path, encoding="utf-8") as f:
            _ = f.read(512)
    elif fmt == "pdf":
        with open(path, "rb") as f:
            header = f.read(5)
        if header[:4] != b"%PDF":
            raise ValueError("Not a valid PDF (missing %PDF header)")


def _render_results(results: list[dict]) -> None:
    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("Template", style="cyan", no_wrap=True)
    table.add_column("Format", style="dim")
    table.add_column("Size", justify="right")
    table.add_column("Entries", justify="right")
    table.add_column("Time", justify="right")
    table.add_column("Status", no_wrap=True)

    for r in results:
        if r["ok"]:
            status = "[green]✓ ok[/green]"
        else:
            status = f"[red]✗ ERROR[/red]"
        table.add_row(
            r["template"],
            r["format"],
            f"{r['file_size_kb']:.0f}KB" if r["ok"] else "—",
            str(r["entry_count"]) if r["ok"] else "—",
            f"{r['elapsed_s']:.1f}s",
            status,
        )

    err_console.print()
    err_console.print("[bold]Validating templates...[/bold]")
    err_console.print(table)
    ok_count = sum(1 for r in results if r["ok"])
    err_console.print(f"  {ok_count}/{len(results)} templates validated successfully.")
    if any(not r["ok"] for r in results):
        for r in results:
            if not r["ok"]:
                err_console.print(f"  [red]✗ {r['template']}:[/red] {r['error']}")


@click.command("validate")
@click.option(
    "--template",
    "templates",
    multiple=True,
    metavar="NAME",
    help="Template name to validate (may be repeated). "
    "Use --all-templates to validate every template.",
)
@click.option(
    "--all-templates",
    "all_templates",
    is_flag=True,
    default=False,
    help="Validate every known template.",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    default="docx",
    type=click.Choice(_VALID_FORMATS, case_sensitive=False),
    show_default=True,
    help="File format to generate for each template.",
)
@click.option(
    "--count",
    default=5,
    show_default=True,
    type=click.IntRange(1, 1000),
    help="Number of records per generated file.",
)
@click.option(
    "--scan",
    "do_scan",
    is_flag=True,
    default=False,
    help="Also submit the generated file to the configured scanner.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Write validation results as JSON to this file.",
)
def validate(
    templates: tuple[str, ...],
    all_templates: bool,
    fmt: str,
    count: int,
    do_scan: bool,
    output: str | None,
) -> None:
    """Validate that templates generate correct files without errors.

    Generates a small sample document per template, checks the file can be
    opened, and reports size, entry count, and generation time.

    \\b
    Examples:
      evadex validate --template trade_confirmation --format docx
      evadex validate --template swift_mt103 --format docx --scan
      evadex validate --all-templates --format csv
      evadex validate --template invoice --template statement --format csv
    """
    if all_templates:
        selected = list(_ALL_TEMPLATES)
    elif templates:
        selected = list(templates)
    else:
        err_console.print(
            "[red]Specify at least one --template NAME or use --all-templates.[/red]"
        )
        sys.exit(1)

    results = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        for tmpl in selected:
            r = _validate_one(tmpl, fmt, count, do_scan, Path(tmp_dir))
            results.append(r)

    _render_results(results)

    if output:
        try:
            Path(output).write_text(
                json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            err_console.print(f"[dim]Results written to {output}[/dim]")
        except OSError as e:
            err_console.print(f"[red]Cannot write output '{output}': {e.strerror}[/red]")
            sys.exit(1)

    had_errors = any(not r["ok"] for r in results)
    sys.exit(1 if had_errors else 0)
