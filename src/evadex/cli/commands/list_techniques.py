"""evadex list-techniques — enumerate evasion generators + techniques.

``--verbose`` expands each generator family with the per-technique
documentation from ``docs/techniques.md`` (description, example,
real-world context, detection fix, seed bypass weight). Those entries
are the canonical source of technique docs; see the README section on
``--evasion-mode`` for the seed-weight rationale.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

import click
from rich.console import Console
from rich.table import Table

from evadex.core.registry import load_builtins, all_generators

console = Console()


@dataclass(frozen=True)
class _TechniqueDoc:
    """Human-readable documentation for one evasion technique."""
    name: str
    description: str
    example: str       # "input → output" format
    context: str
    fix: str


# Per-family prose. Keyed by generator family name.
# This mirrors docs/techniques.md — keep them in sync when either changes.
_FAMILY_DOCS: dict[str, dict[str, str]] = {
    "unicode_whitespace": {
        "context": (
            "Any channel where the renderer collapses whitespace — email, "
            "chat, office documents. Scanners that tokenise on ASCII \\s "
            "alone miss every variant."
        ),
        "fix": (
            "NFKC-normalise and strip all non-ASCII whitespace "
            "characters before pattern matching."
        ),
    },
    "unicode_encoding": {
        "context": (
            "Phishing, pasted secrets, any place the renderer shows the "
            "same glyph regardless of codepoint."
        ),
        "fix": (
            "NFKC-normalise, then apply the Unicode TR39 confusables "
            "map to fold Cyrillic/Greek/fullwidth back to ASCII."
        ),
    },
    "bidirectional": {
        "context": (
            "File names, chat messages, reviewer workflows where a human "
            "approves something that looks benign but stores as something else."
        ),
        "fix": (
            "Flag or reject any input containing U+202A..U+202E or "
            "U+2066..U+2069 regardless of pattern match."
        ),
    },
    "soft_hyphen": {
        "context": (
            "Word/Google Docs exports, HTML forms — channels where "
            "bytes are preserved but the display hides soft hyphens."
        ),
        "fix": (
            "Strip U+00AD before matching; log any strip that removes "
            "more than two characters as an evasion signal."
        ),
    },
    "encoding": {
        "context": (
            "Exfiltration through channels where encoding is expected — "
            "base64 in JSON, hex in config, HTML entities in forms."
        ),
        "fix": (
            "Heuristically detect and decode common encodings (base64, "
            "hex, percent, HTML entities) before pattern matching."
        ),
    },
    "encoding_chains": {
        "context": (
            "Advanced exfiltration — rot13 inside base64 inside JSON. "
            "Single-layer decoders stop one level short."
        ),
        "fix": (
            "Decode iteratively to a bounded depth (3–4 layers); log "
            "any match that required ≥ 2 decodes."
        ),
    },
    "splitting": {
        "context": (
            "Multi-line logs, CSV splits, HTML documents where markup "
            "interrupts the value mid-string."
        ),
        "fix": (
            "Use a sliding window that joins across whitespace / trivial "
            "separators; strip HTML tags before scanning."
        ),
    },
    "structural": {
        "context": (
            "Programmatic exfiltration where the attacker controls the "
            "structure — JSON APIs, config files."
        ),
        "fix": (
            "Allow a broader length range; detect common rotations; scan "
            "structured formats by value, not by raw bytes."
        ),
    },
    "delimiter": {
        "context": (
            "Log lines, URLs, any format where delimiters vary legitimately."
        ),
        "fix": (
            "Accept a broader delimiter character class in patterns, or "
            "normalise delimiters before matching."
        ),
    },
    "leetspeak": {
        "context": (
            "Older phishing, obfuscated hostnames, informal exfil channels."
        ),
        "fix": (
            "Run a leetspeak → ASCII normaliser before pattern matching."
        ),
    },
    "regional_digits": {
        "context": (
            "Locales where non-Latin digits are valid — Arabic-Indic, "
            "Devanagari, Thai, Bengali forms."
        ),
        "fix": (
            "Use \\d in Unicode mode, or normalise digit scripts to "
            "ASCII via unicodedata.decimal() before matching."
        ),
    },
    "morse_code": {
        "context": (
            "Niche exfiltration channels and CTF-style obfuscation; "
            "few DLP products ship a morse signature."
        ),
        "fix": (
            "Detect high concentrations of . and - with consistent group "
            "separators and decode heuristically."
        ),
    },
    "context_injection": {
        "context": (
            "Slipping credentials into long documents where bulk filters "
            "(size, entropy, known-text ratio) are the only defence."
        ),
        "fix": (
            "Apply pattern matchers independently of volume filters; "
            "don't let a low-entropy wrapper cancel a high-confidence match."
        ),
    },
    "entropy_evasion": {
        "context": (
            "Secret-scanner evasion (e.g. GitHub push protection) where "
            "detection is entropy-based rather than regex-based."
        ),
        "fix": (
            "Combine entropy with keyword proximity — a low-entropy "
            "string near the word 'password' is still a finding."
        ),
    },
    "archive_evasion": {
        "context": (
            "Email attachments, file uploads, any channel where archive "
            "extraction is configurable and may be off."
        ),
        "fix": (
            "Enable recursive archive extraction with a depth cap to "
            "avoid zip bombs."
        ),
    },
    "barcode_evasion": {
        "context": (
            "Printed forms, mobile workflows, any scenario where a device "
            "scans an image for human consumption."
        ),
        "fix": (
            "Enable image OCR + barcode decoding for content that may "
            "contain printed forms (statements, invoices, shipping labels)."
        ),
    },
}


def _render_verbose_generator(gen, sample: str) -> None:
    """Print one generator family in full detail — header prose, seed
    weight, then every technique with description + example."""
    from evadex.feedback.seed_weights import SEED_WEIGHTS, SEED_WEIGHT_RATIONALE

    fam = _FAMILY_DOCS.get(gen.name, {})
    weight = SEED_WEIGHTS.get(gen.name)
    rationale = SEED_WEIGHT_RATIONALE.get(gen.name, "")

    header = f"[bold cyan]{gen.name}[/bold cyan]"
    if weight is not None:
        header += f"  [dim](seed bypass: {weight:.2f})[/dim]"
    console.print(header)

    if fam.get("context"):
        console.print(f"  [white]Context:[/white] {fam['context']}")
    if fam.get("fix"):
        console.print(f"  [white]Fix:[/white] {fam['fix']}")
    if rationale:
        console.print(f"  [white]Seed rationale:[/white] [dim]{rationale}[/dim]")

    # Enumerate techniques by running the generator on a sample. The
    # sample is alphanumeric + typical length so every branch triggers.
    try:
        variants = list(gen.generate(sample))
    except Exception as exc:
        console.print(f"  [red]Error enumerating techniques: {exc}[/red]")
        return

    seen: dict[str, tuple[str, str]] = {}
    for v in variants:
        if v.technique not in seen:
            seen[v.technique] = (v.transform_name, v.value)

    if not seen:
        console.print("  [dim](no techniques emitted for this sample)[/dim]\n")
        return

    table = Table(show_header=True, header_style="bold dim", border_style="dim")
    table.add_column("Technique", style="cyan", min_width=28)
    table.add_column("Description", min_width=36)
    table.add_column("Example output", style="green", min_width=24, overflow="fold")

    for technique, (desc, output) in sorted(seen.items()):
        # Trim very long outputs so the terminal stays readable, but
        # keep enough to see the encoding.
        display = output if len(output) <= 48 else output[:45] + "..."
        table.add_row(technique, desc, display)
    console.print(table)
    console.print()


@click.command("list-techniques")
@click.option(
    "--generator", "-g", "filter_gen",
    default=None,
    help="Show only techniques from this generator family.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help=(
        "Show full per-family documentation: description, example, "
        "real-world context, detection fix, and seed bypass weight. "
        "Mirrors docs/techniques.md."
    ),
)
def list_techniques(filter_gen: str | None, verbose: bool) -> None:
    """List all registered evasion generators and their techniques."""
    load_builtins()
    generators = all_generators()

    if filter_gen:
        generators = [g for g in generators if g.name == filter_gen]
        if not generators:
            console.print(f"[red]No generator named {filter_gen!r}[/red]")
            sys.exit(1)

    # Alphanumeric + typical length so every branch of every generator
    # emits at least one variant. Used for both the plain and verbose
    # views so the visible examples stay consistent.
    sample = "4532015112830366"

    if verbose:
        for gen in generators:
            _render_verbose_generator(gen, sample)
        console.print(
            f"[dim]{len(generators)} generator family(ies) — "
            f"see docs/techniques.md for full reference[/dim]"
        )
        return

    total = 0
    for gen in generators:
        try:
            variants = list(gen.generate(sample))
        except Exception as exc:
            console.print(f"[red]Error loading generator {gen.name!r}: {exc}[/red]")
            variants = []

        # Deduplicate by technique name.
        seen: dict[str, str] = {}
        for v in variants:
            if v.technique not in seen:
                seen[v.technique] = v.transform_name

        cats = gen.applicable_categories
        cats_str = ", ".join(sorted(c.value for c in cats)) if cats else "all"

        table = Table(
            title=f"[bold cyan]{gen.name}[/bold cyan]  [dim](applies to: {cats_str})[/dim]",
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
