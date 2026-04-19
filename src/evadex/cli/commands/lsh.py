"""evadex lsh — exercise Siphon's document-similarity (LSH) engine.

Generates a base document, registers it with Siphon, then submits
near-duplicate variants at decreasing similarity levels. For each
variant the command reports:

  * The *empirical* Jaccard similarity (computed locally with the
    same shingle-3 algorithm Siphon uses — the ground-truth value
    Siphon's MinHash should asymptotically estimate).
  * Whether Siphon flagged the variant at the requested threshold.
  * What similarity score Siphon reported when it did flag.

Two transports are supported:

  ``--transport http`` (default when ``--url`` is set) — talks to
  ``POST /v1/lsh/register`` and ``POST /v1/lsh/query`` on a running
  Siphon API server. Requires the ``siphon serve`` subcommand which
  is not yet wired in current builds.

  ``--transport cli`` (default otherwise) — shells out to
  ``siphon lsh register`` and ``siphon lsh query`` against a local
  state file. Works against any Siphon binary built today.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import click
import httpx
from rich.console import Console
from rich.table import Table

from evadex.lsh import BASE_DOCUMENTS, distorted_variant, jaccard_similarity


err_console = Console(stderr=True)


DEFAULT_DISTORTION_RATES = (0.05, 0.10, 0.15, 0.20, 0.30, 0.50)


# ── Transports ─────────────────────────────────────────────────────────────

class _HttpTransport:
    """LSH register/query against a live Siphon HTTP API."""

    def __init__(self, url: str, api_key: Optional[str], timeout: float):
        self.base_url = url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["x-api-key"] = self.api_key
        return h

    def health(self) -> None:
        resp = httpx.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()

    def register(self, doc_id: str, text: str) -> None:
        resp = httpx.post(
            f"{self.base_url}/v1/lsh/register",
            json={"doc_id": doc_id, "text": text, "sensitivity": "sensitive"},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()

    def query(self, text: str, threshold: float) -> list[dict]:
        resp = httpx.post(
            f"{self.base_url}/v1/lsh/query",
            json={"text": text, "threshold": threshold},
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("matches", [])


class _CliTransport:
    """LSH register/query via ``siphon lsh ...`` against a state file."""

    def __init__(self, exe: str, state_path: str):
        self.exe = exe
        self.state_path = state_path

    def health(self) -> None:
        if not Path(self.exe).exists():
            raise FileNotFoundError(f"Siphon binary not found at {self.exe}")

    def register(self, doc_id: str, text: str) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fp:
            fp.write(text)
            doc_path = fp.name
        try:
            subprocess.run(
                [self.exe, "lsh", "register", doc_id, doc_path,
                 "--state", self.state_path],
                check=True, capture_output=True, text=True,
            )
        finally:
            Path(doc_path).unlink(missing_ok=True)

    def query(self, text: str, threshold: float) -> list[dict]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fp:
            fp.write(text)
            doc_path = fp.name
        try:
            result = subprocess.run(
                [self.exe, "lsh", "query", doc_path,
                 "--threshold", f"{threshold:.4f}",
                 "--state", self.state_path],
                check=True, capture_output=True, text=True,
            )
        finally:
            Path(doc_path).unlink(missing_ok=True)
        return _parse_cli_query(result.stdout)


def _parse_cli_query(stdout: str) -> list[dict]:
    """Parse the human-readable output of ``siphon lsh query``.

    Two output shapes:

        No similar documents found (threshold: 80%).

        2 similar documents found:
          [97%] doc_id_a (sensitivity: sensitive)
          [82%] doc_id_b (sensitivity: confidential)
    """
    matches: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            pct_str, rest = line.split("]", 1)
            pct = float(pct_str.lstrip("[").rstrip("%"))
            doc_part = rest.strip()
            doc_id = doc_part.split(" (sensitivity:")[0].strip()
            matches.append({"doc_id": doc_id, "similarity": pct / 100.0})
        except (ValueError, IndexError):
            continue
    return matches


# ── Command ────────────────────────────────────────────────────────────────

@click.command(name="lsh")
@click.option("--transport", type=click.Choice(["http", "cli"]), default=None,
              help="LSH transport. Defaults to 'http' when --url is set, "
                   "else 'cli'.")
@click.option("--url", default=None,
              help="Siphon HTTP API URL for --transport http.")
@click.option("--api-key", default=None,
              help="Siphon API key for HTTP transport (or EVADEX_API_KEY).")
@click.option("--exe", default=None,
              help="Path to siphon binary for --transport cli "
                   "(default: 'siphon' on PATH).")
@click.option("--state", "state_path", default=None,
              help="LSH state file path for --transport cli "
                   "(default: a temp file, cleaned up at exit).")
@click.option("--similarity", "query_threshold", type=float, default=0.5,
              help="Similarity threshold passed to Siphon's query "
                   "(0.0–1.0). Variants with empirical Jaccard above "
                   "this value are expected to be flagged.  [default: 0.5]")
@click.option("--document", "doc_choice",
              type=click.Choice(sorted(BASE_DOCUMENTS.keys())),
              default="loan_decision",
              help="Which built-in base document to test against.")
@click.option("--seed", type=int, default=0,
              help="RNG seed for deterministic variant generation.")
@click.option("--timeout", type=float, default=30.0,
              help="HTTP timeout in seconds (HTTP transport only).")
@click.option("-o", "--output", "output", type=click.Path(), default=None,
              help="Write a JSON report to this path.")
def lsh(
    transport: Optional[str],
    url: Optional[str],
    api_key: Optional[str],
    exe: Optional[str],
    state_path: Optional[str],
    query_threshold: float,
    doc_choice: str,
    seed: int,
    timeout: float,
    output: Optional[str],
) -> None:
    """Test Siphon's LSH document-similarity detection.

    Generates a base document, registers it with Siphon, and submits
    six near-duplicate variants at decreasing similarity levels
    (~95%, 90%, 85%, 80%, 70%, 50% Jaccard). Reports the minimum
    similarity Siphon can reliably detect.

    \b
    Examples:
      # Quick check against a Siphon binary (no API server required)
      evadex lsh --exe ./siphon --similarity 0.5

      # Against a running Siphon API server
      evadex lsh --url http://localhost:8080 --api-key $SIPHON_KEY

      # Test against a different built-in document
      evadex lsh --document incident_report --similarity 0.7
    """
    if transport is None:
        transport = "http" if url else "cli"

    base_text = BASE_DOCUMENTS[doc_choice]

    if transport == "cli":
        chosen_exe = exe or shutil.which("siphon") or shutil.which("dlpscan")
        if not chosen_exe:
            err_console.print(
                "[red]CLI transport requires --exe pointing at a siphon "
                "binary, or 'siphon'/'dlpscan' on PATH.[/red]"
            )
            sys.exit(1)
        # Use a fresh temp state file so the test does not interact with
        # any production LSH vault sitting next to the binary.
        with tempfile.TemporaryDirectory(prefix="evadex-lsh-") as tmp:
            sp = state_path or str(Path(tmp) / "lsh-state.json")
            txp = _CliTransport(chosen_exe, sp)
            try:
                txp.health()
            except FileNotFoundError as exc:
                err_console.print(f"[red]{exc}[/red]")
                sys.exit(1)
            _run_test(txp, base_text, doc_choice, query_threshold, seed, output)
    else:
        if not url:
            err_console.print("[red]HTTP transport requires --url.[/red]")
            sys.exit(1)
        txp = _HttpTransport(url, api_key, timeout)
        try:
            txp.health()
        except (httpx.ConnectError, httpx.ConnectTimeout):
            err_console.print(
                f"[red]Could not reach Siphon at {url}. Is the server "
                f"running ('siphon serve')?[/red]"
            )
            sys.exit(1)
        except httpx.HTTPStatusError as exc:
            err_console.print(
                f"[red]Health check failed: HTTP {exc.response.status_code}[/red]"
            )
            sys.exit(1)
        _run_test(txp, base_text, doc_choice, query_threshold, seed, output)


def _run_test(
    transport,
    base_text: str,
    doc_id: str,
    threshold: float,
    seed: int,
    output: Optional[str],
) -> None:
    err_console.print(
        f"[dim]Registering base document '{doc_id}' "
        f"({len(base_text)} chars, "
        f"{len(base_text.split())} words)[/dim]"
    )
    transport.register(doc_id, base_text)

    # Always include the exact base as a sanity row — Siphon should
    # report similarity ~= 1.0 for it. Any drift here means the
    # MinHash estimator or hash seed is mis-configured.
    rows: list[dict] = []
    sanity_matches = transport.query(base_text, threshold)
    sanity_sim = next(
        (m["similarity"] for m in sanity_matches if m["doc_id"] == doc_id),
        0.0,
    )
    rows.append({
        "label": "exact (sanity)",
        "distortion_rate": 0.0,
        "empirical_jaccard": 1.0,
        "siphon_detected": bool(sanity_matches),
        "siphon_reported_similarity": sanity_sim,
    })

    import random
    rng = random.Random(seed)
    for rate in DEFAULT_DISTORTION_RATES:
        variant = distorted_variant(base_text, rate, rng)
        empirical = jaccard_similarity(base_text, variant)
        matches = transport.query(variant, threshold)
        reported = next(
            (m["similarity"] for m in matches if m["doc_id"] == doc_id), 0.0
        )
        rows.append({
            "label": f"distort {rate:.0%}",
            "distortion_rate": rate,
            "empirical_jaccard": round(empirical, 4),
            "siphon_detected": bool(matches),
            "siphon_reported_similarity": round(reported, 4),
        })

    _render_table(rows, threshold, doc_id)
    min_detected = _minimum_detected(rows)
    if min_detected is not None:
        err_console.print(
            f"\n[bold]Minimum reliably detected similarity:[/bold] "
            f"{min_detected:.0%}"
        )
    else:
        err_console.print(
            "\n[yellow]No variants were flagged. Threshold may be too "
            "high, or LSH is not active in this build.[/yellow]"
        )

    if output:
        report = {
            "base_document": doc_id,
            "query_threshold": threshold,
            "rng_seed": seed,
            "rows": rows,
            "minimum_detected_similarity": min_detected,
        }
        Path(output).write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        err_console.print(f"[dim]Report written to {output}[/dim]")


def _render_table(rows: list[dict], threshold: float, doc_id: str) -> None:
    table = Table(
        title=f"LSH near-duplicate detection vs. '{doc_id}'  "
              f"(threshold={threshold:.0%})"
    )
    table.add_column("Variant", style="cyan")
    table.add_column("Empirical Jaccard", justify="right")
    table.add_column("Siphon Reported", justify="right")
    table.add_column("Detected?", justify="center")
    for r in rows:
        det = "[green]yes[/green]" if r["siphon_detected"] else "[red]no[/red]"
        reported = (f"{r['siphon_reported_similarity']:.0%}"
                    if r["siphon_detected"] else "—")
        table.add_row(
            r["label"],
            f"{r['empirical_jaccard']:.0%}",
            reported,
            det,
        )
    console = Console()
    console.print(table)


def _minimum_detected(rows: list[dict]) -> Optional[float]:
    """Lowest empirical Jaccard at which Siphon still flagged a match."""
    detected = [r["empirical_jaccard"] for r in rows if r["siphon_detected"]]
    if not detected:
        return None
    return min(detected)
