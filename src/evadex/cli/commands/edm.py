"""evadex edm — test harness for Siphon's Exact Data Match (EDM) engine.

Siphon EDM detects *specific known values* (actual SSNs, account numbers,
etc.) registered with the scanner, rather than pattern-matched formats.
Values are HMAC-SHA256 hashed after normalisation (NFKC + lowercase +
trim + strip ``[\\s\\-./()]+``) and matched against tokenised scan
input. See ``crates/siphon-core/src/edm.rs`` for the upstream
implementation.

This command exercises that pipeline end to end:

1. **Register** — POST ``/v1/edm/register`` with known values pulled
   from evadex's built-in payloads. Test values land under the
   ``evadex_test_*`` category namespace so they never collide with
   production EDM categories.
2. **Verify** — submit each registered value through ``/v1/scan`` and
   confirm the response carries an ``EDM: <category>`` finding.
3. **Evasion** — re-submit the same value after a set of
   transformations (case, delimiters, whitespace, homoglyphs,
   unicode whitespace) and report which ones EDM's normaliser
   absorbs vs which defeat it.
4. **Corpus generation** — ``--generate-corpus`` emits a JSON or CSV
   import file for bulk EDM registration without touching the API.

Cleanup caveat
--------------
Siphon's HTTP API exposes registration and listing endpoints but no
delete. True cleanup requires clearing the server's EDM state file
(or restarting the server). The harness scopes test data to a
dedicated category namespace so any residual hashes remain
clearly-labelled test data.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Optional

import click
import httpx
from rich.console import Console
from rich.table import Table

from evadex.core.registry import load_builtins
from evadex.payloads.builtins import BUILTIN_PAYLOADS, HEURISTIC_CATEGORIES
from evadex.core.result import Payload, PayloadCategory


err_console = Console(stderr=True)


# ── Shared constants ────────────────────────────────────────────────────────

#: Prefix applied to every EDM category evadex registers. Keeps the test
#: harness's hashes isolated from production EDM categories.
EDM_TEST_CATEGORY_PREFIX = "evadex_test_"

#: Siphon's constant-time scan threshold — above this, it logs a warning
#: about degraded performance. We surface the same warning so operators
#: notice before the server does.
SIPHON_EDM_HASH_WARN_THRESHOLD = 50_000

#: Transformations we apply to a registered value to probe EDM's
#: normaliser. Name → lambda; each produces ONE variant text per value.
#: The key insight: Siphon normalises ``[\s\-./()]+`` away before
#: hashing, so delimiter/whitespace/NFKC-absorbing variants should all
#: still match. Homoglyphs (Cyrillic/Greek look-alikes) should NOT
#: match because NFKC keeps distinct Unicode scripts separate.
EVASION_TRANSFORMS: dict[str, "callable"] = {
    "exact":          lambda v: v,
    "uppercase":      lambda v: v.upper(),
    "lowercase":      lambda v: v.lower(),
    "dashes":         lambda v: _insert_every(v, 4, "-"),
    "spaces":         lambda v: _insert_every(v, 4, " "),
    "dots":           lambda v: _insert_every(v, 4, "."),
    "slashes":        lambda v: _insert_every(v, 4, "/"),
    "nbsp_spaces":    lambda v: _insert_every(v, 4, "\u00a0"),  # non-breaking space
    "homoglyph_0":    lambda v: v.replace("0", "\u041e"),  # Cyrillic O
    "homoglyph_o":    lambda v: v.replace("o", "\u043e"),  # Cyrillic small o
    "zero_width":     lambda v: _insert_every(v, 4, "\u200b"),  # zero-width space
}


def _insert_every(value: str, n: int, sep: str) -> str:
    """Insert *sep* every *n* characters into *value*."""
    if len(value) <= n:
        return value + sep + value[:1]  # still produce a different string
    return sep.join(value[i : i + n] for i in range(0, len(value), n))


# ── Siphon EDM HTTP client ──────────────────────────────────────────────────

class SiphonEDMClient:
    """Narrow client for the two EDM endpoints + /v1/scan verification.

    Intentionally synchronous + minimal so tests can mock it with respx
    without fighting async machinery.
    """

    def __init__(self, base_url: str, api_key: Optional[str], timeout: float):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["x-api-key"] = self._api_key
        return h

    def register(self, category: str, values: list[str]) -> dict:
        resp = httpx.post(
            f"{self.base_url}/v1/edm/register",
            json={"category": category, "values": values},
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def categories(self) -> dict:
        resp = httpx.get(
            f"{self.base_url}/v1/edm/categories",
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def scan(self, text: str) -> dict:
        """POST /v1/scan and return the response JSON."""
        resp = httpx.post(
            f"{self.base_url}/v1/scan",
            json={"text": text, "action": "flag"},
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()


def _is_edm_match(scan_response: dict) -> bool:
    """Return True when any finding in *scan_response* is an EDM hit."""
    findings = scan_response.get("findings") or []
    for f in findings:
        cat = f.get("category", "")
        sub = f.get("sub_category", "")
        if cat.startswith("EDM:") or sub == "Exact Data Match":
            return True
    return False


# ── Corpus generation ──────────────────────────────────────────────────────

def _category_allowlist(
    categories: tuple[str, ...],
    include_heuristic: bool,
) -> Optional[set[PayloadCategory]]:
    if not categories:
        return None
    cats: set[PayloadCategory] = set()
    for name in categories:
        try:
            cat = PayloadCategory(name)
        except ValueError as exc:
            raise click.UsageError(f"Unknown category: {name!r}") from exc
        cats.add(cat)
    return cats


def _select_payloads(
    categories: Optional[set[PayloadCategory]],
    include_heuristic: bool,
    limit: Optional[int] = None,
) -> list[Payload]:
    payloads: list[Payload] = []
    for p in BUILTIN_PAYLOADS:
        if not include_heuristic and p.category in HEURISTIC_CATEGORIES:
            continue
        if categories is not None and p.category not in categories:
            continue
        payloads.append(p)
    if limit is not None:
        payloads = payloads[:limit]
    return payloads


def _write_corpus(
    payloads: list[Payload],
    output: str,
    fmt: str,
) -> None:
    """Dump *payloads* to *output* in *fmt* = ``json`` or ``csv``."""
    if fmt == "json":
        body = {
            "values": [
                {
                    "value": p.value,
                    "category": p.category.value,
                    "label": p.label,
                }
                for p in payloads
            ]
        }
        Path(output).write_text(json.dumps(body, indent=2), encoding="utf-8")
    elif fmt == "csv":
        with open(output, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["category", "label", "value"])
            for p in payloads:
                writer.writerow([p.category.value, p.label, p.value])
    else:
        raise click.UsageError(f"Unsupported corpus format: {fmt!r}")


# ── Registration + verification pipeline ────────────────────────────────────

def _register_payloads(
    client: SiphonEDMClient,
    payloads: list[Payload],
    dry_run: bool,
) -> tuple[dict, int]:
    """Register each payload under its evadex-namespaced category.

    Returns ``(per_category_counts, total_registered)``.
    """
    by_cat: dict[str, list[Payload]] = {}
    for p in payloads:
        by_cat.setdefault(p.category.value, []).append(p)

    counts: dict = {}
    total = 0
    for cat_name, cat_payloads in sorted(by_cat.items()):
        edm_cat = f"{EDM_TEST_CATEGORY_PREFIX}{cat_name}"
        values = [p.value for p in cat_payloads]
        total += len(values)
        if dry_run:
            counts[edm_cat] = {"registered": len(values), "total_hashes": None}
            continue
        resp = client.register(edm_cat, values)
        counts[edm_cat] = {
            "registered": resp.get("registered", len(values)),
            "total_hashes": resp.get("total_hashes"),
        }

    if total > SIPHON_EDM_HASH_WARN_THRESHOLD:
        err_console.print(
            f"[yellow]Warning: registering {total} values exceeds Siphon's recommended "
            f"constant-time threshold of {SIPHON_EDM_HASH_WARN_THRESHOLD} hashes — "
            f"EDM scan performance will degrade on the server.[/yellow]"
        )
    return counts, total


def _verify_payloads(
    client: SiphonEDMClient,
    payloads: list[Payload],
) -> list[dict]:
    """Submit each payload verbatim and record whether EDM caught it."""
    results = []
    for p in payloads:
        try:
            resp = client.scan(p.value)
            detected = _is_edm_match(resp)
            results.append({
                "category": p.category.value,
                "label": p.label,
                "value": p.value,
                "edm_detected": detected,
            })
        except httpx.HTTPError as exc:
            results.append({
                "category": p.category.value,
                "label": p.label,
                "value": p.value,
                "edm_detected": False,
                "error": str(exc),
            })
    return results


def _run_evasion(
    client: SiphonEDMClient,
    payloads: list[Payload],
    transforms: dict,
) -> dict:
    """For each transform, submit every payload's transformed value.

    Returns a mapping ``transform_name → stats`` with per-transform hit
    counts so the final table shows which normalisations EDM absorbs.
    """
    stats: dict = {
        name: {"tested": 0, "detected": 0, "failures": []}
        for name in transforms
    }
    for p in payloads:
        for name, fn in transforms.items():
            try:
                text = fn(p.value)
            except Exception:
                continue
            try:
                resp = client.scan(text)
                hit = _is_edm_match(resp)
            except httpx.HTTPError:
                hit = False
            stats[name]["tested"] += 1
            if hit:
                stats[name]["detected"] += 1
            else:
                stats[name]["failures"].append({
                    "category": p.category.value,
                    "value": text,
                })
    return stats


# ── Tabular rendering ───────────────────────────────────────────────────────

def _render_verification_table(verification: list[dict]) -> Table:
    table = Table(title="EDM exact-value detection")
    table.add_column("Category", style="cyan")
    table.add_column("Label")
    table.add_column("Detected", justify="right")
    for r in verification:
        mark = "[green]✓[/green]" if r["edm_detected"] else "[red]✗[/red]"
        table.add_row(r["category"], r["label"], mark)
    return table


def _render_evasion_table(stats: dict) -> Table:
    table = Table(title="EDM evasion probe (detection rate per transform)")
    table.add_column("Transform", style="cyan")
    table.add_column("Detected / Tested", justify="right")
    table.add_column("Normalisation absorbs it?")
    for name in EVASION_TRANSFORMS:
        s = stats.get(name)
        if not s or s["tested"] == 0:
            continue
        total = s["tested"]
        hit = s["detected"]
        pct = 100.0 * hit / total if total else 0.0
        note = (
            "[green]yes[/green]" if pct >= 99 else
            "[yellow]partial[/yellow]" if pct >= 20 else
            "[red]no[/red]"
        )
        table.add_row(name, f"{hit}/{total} ({pct:.0f}%)", note)
    return table


# ── Click command ──────────────────────────────────────────────────────────

@click.command("edm")
@click.option("--tool", "-t", default="siphon", show_default=True,
              help="DLP adapter to probe (siphon is the only one with an EDM engine).")
@click.option("--url", default="http://localhost:8000", show_default=True,
              help="Base URL for the Siphon HTTP API.")
@click.option("--api-key", default=None, envvar="EVADEX_API_KEY",
              help="Siphon API key (sent as x-api-key). Registration requires Admin role.")
@click.option("--timeout", default=30.0, show_default=True, type=float,
              help="HTTP timeout in seconds.")
@click.option("--category", "categories", multiple=True, metavar="CATEGORY",
              help="Restrict registration to these payload categories. Repeat for multiple.")
@click.option("--include-heuristic", is_flag=True, default=False,
              help="Include heuristic categories (AWS key, JWT, etc.).")
@click.option("--limit", type=int, default=None, metavar="N",
              help="Register at most N values. Useful for quick smoke tests.")
@click.option("--test-evasion/--no-test-evasion", default=True, show_default=True,
              help="After verification, probe EDM's normalisation with a set of "
                   "transforms (case, delimiters, whitespace, homoglyphs).")
@click.option("--generate-corpus", is_flag=True, default=False,
              help="Skip the server entirely. Just write an EDM import file "
                   "(--corpus-format) to --output.")
@click.option("--corpus-format", default="json", show_default=True,
              type=click.Choice(["json", "csv"]),
              help="Format for --generate-corpus output.")
@click.option("--count", type=int, default=None,
              help="Alias for --limit when using --generate-corpus.")
@click.option("--output", "-o", default=None, metavar="PATH",
              help="Output path. With --generate-corpus: corpus file. "
                   "Otherwise: JSON report of the test run.")
@click.option("--c2-url", "c2_url", default=None, envvar="EVADEX_C2_URL",
              help="Siphon-C2 URL. Pushes the EDM test results to "
                   "POST /v1/evadex/edm. Failures log a warning; never fail the run.")
@click.option("--c2-key", "c2_key", default=None, envvar="EVADEX_C2_KEY",
              help="API key sent as 'x-api-key' to Siphon-C2.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Do not contact the Siphon server — print the plan only.")
def edm(
    tool: str,
    url: str,
    api_key: Optional[str],
    timeout: float,
    categories: tuple[str, ...],
    include_heuristic: bool,
    limit: Optional[int],
    test_evasion: bool,
    generate_corpus: bool,
    corpus_format: str,
    count: Optional[int],
    output: Optional[str],
    c2_url: Optional[str],
    c2_key: Optional[str],
    dry_run: bool,
) -> None:
    """Register known values with Siphon's EDM engine and verify detection.

    Siphon-specific. Tests that registered values are caught, then probes
    evasion variants (case, delimiters, homoglyphs) against the EDM index.

    \b
    Examples:
      evadex edm --url http://localhost:8000 --api-key $SIPHON_KEY
      evadex edm --category credit_card --category sin
      evadex edm --generate-corpus --output edm_corpus.json
      evadex edm --generate-corpus --corpus-format csv --count 1000 \\
        --output edm_corpus.csv
    """
    load_builtins()

    cats = _category_allowlist(categories, include_heuristic)
    n = limit if limit is not None else count
    payloads = _select_payloads(cats, include_heuristic, limit=n)

    if not payloads:
        err_console.print(
            "[red]No payloads match the selected categories. "
            "Use --include-heuristic or broaden --category.[/red]"
        )
        sys.exit(1)

    # ── Corpus-only path ────────────────────────────────────────────────
    if generate_corpus:
        if not output:
            raise click.UsageError("--generate-corpus requires --output.")
        _write_corpus(payloads, output, corpus_format)
        err_console.print(
            f"[dim]Wrote {len(payloads)} entries to {output} ({corpus_format})[/dim]"
        )
        return

    # ── Live test path ──────────────────────────────────────────────────
    client = SiphonEDMClient(url, api_key, timeout)

    if dry_run:
        err_console.print(
            f"[dim]DRY RUN — would register {len(payloads)} values "
            f"into {len({p.category.value for p in payloads})} categories "
            f"on {url}[/dim]"
        )
        counts, total = _register_payloads(client, payloads, dry_run=True)
        for c, info in counts.items():
            err_console.print(f"  {c}: {info['registered']} values")
        return

    if len(payloads) > SIPHON_EDM_HASH_WARN_THRESHOLD:
        err_console.print(
            f"[yellow]Warning: about to register {len(payloads)} values, "
            f"which exceeds Siphon's recommended constant-time threshold of "
            f"{SIPHON_EDM_HASH_WARN_THRESHOLD}. EDM scan performance will "
            f"degrade on the server. Press Ctrl-C to abort.[/yellow]"
        )

    err_console.print(
        f"[dim]Registering {len(payloads)} values with Siphon EDM at {url}[/dim]"
    )
    try:
        counts, total = _register_payloads(client, payloads, dry_run=False)
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 403:
            err_console.print(
                "[red]Registration refused (403) — the API key must have the "
                "Admin role (POST /v1/edm/register requires AdminAction).[/red]"
            )
        elif status == 404:
            err_console.print(
                f"[red]Siphon's EDM API is not available at {url} (HTTP 404). "
                f"Check that EDM is enabled in Siphon's config "
                f"(edm.enabled = true).[/red]"
            )
        else:
            err_console.print(f"[red]EDM registration failed: HTTP {status}[/red]")
        sys.exit(1)
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        err_console.print(
            f"[red]Could not reach Siphon at {url}. Is the scanner running? "
            f"({exc.__class__.__name__})[/red]"
        )
        sys.exit(1)
    except httpx.HTTPError as exc:
        err_console.print(f"[red]EDM registration failed: {exc}[/red]")
        sys.exit(1)

    verification = _verify_payloads(client, payloads)
    err_console.print(_render_verification_table(verification))

    stats: dict = {}
    if test_evasion:
        err_console.print(
            f"[dim]Probing EDM normalisation with {len(EVASION_TRANSFORMS)} "
            f"transforms × {len(payloads)} values[/dim]"
        )
        stats = _run_evasion(client, payloads, EVASION_TRANSFORMS)
        err_console.print(_render_evasion_table(stats))

    detected = sum(1 for v in verification if v["edm_detected"])
    exact_rate = round(100.0 * detected / len(verification), 1) if verification else 0.0
    err_console.print(
        f"\n[bold]EDM exact-match rate: {detected}/{len(verification)} "
        f"({exact_rate}%)[/bold]  [dim]"
        f"{total} hashes registered across {len(counts)} categories[/dim]"
    )

    report = {
        "tool": tool,
        "url": url,
        "registered_total": total,
        "categories": counts,
        "verification": verification,
        "exact_match_rate_pct": exact_rate,
        "evasion_stats": {
            name: {"tested": s["tested"], "detected": s["detected"]}
            for name, s in stats.items()
        },
    }

    if output:
        Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        err_console.print(f"[dim]EDM report written to {output}[/dim]")

    # ── Siphon-C2 push ────────────────────────────────────────────────────
    from evadex.reporters.c2_reporter import (
        push_history_batch,  # re-use batch endpoint for EDM payload
        resolve_c2_config,
    )
    _c2_url, _c2_key = resolve_c2_config(c2_url, c2_key)
    if _c2_url:
        # Wrap the EDM report as a single-entry history batch tagged type=edm.
        # Keeps C2's ingestion surface small — no new endpoint needed.
        report_for_c2 = dict(report)
        report_for_c2["type"] = "edm"
        push_history_batch(_c2_url, _c2_key, entries=[report_for_c2])
