"""evadex ci — CI/CD quality gate for DLP scanner detection thresholds.

Runs a scan against the configured scanner and exits 0 when all thresholds
are met, 1 when any threshold is violated.  Designed for use in GitHub
Actions, GitLab CI, Jenkins, etc.:

    - name: DLP quality gate
      run: evadex ci --min-detection 30 --max-fp 20

Output is one line per check, suitable for CI log scanning:

    evadex ci -- northam tier
    Detection rate: 34.5% (threshold: 30%) ✓
    Exit: 0

Exit codes
----------
0   All thresholds met.
1   One or more thresholds violated.
2   Inconclusive: the scan failed to run, more than --max-error-rate of the
    submissions errored instead of returning a verdict, or the false-positive
    measurement could not be taken. Not a verdict on the scanner.

The detection rate is measured over submissions that got a verdict. An
errored submission (timeout, unreachable scanner) is not a bypass; it is
reported and gated separately, so a flaky transport cannot read as a scanner
regression and cannot hide one either.
"""

from __future__ import annotations

import json
import subprocess
import sys

import click
from rich.console import Console

from evadex.payloads.tiers import VALID_TIERS

console = Console(stderr=True)

_TIER_CHOICES = click.Choice(sorted(VALID_TIERS), case_sensitive=False)
_TRANSPORT_CHOICES = click.Choice(["cli", "http", "auto"], case_sensitive=False)

_CHECK = "✓"  # ✓
_CROSS = "✗"  # ✗


@click.command("ci")
@click.option(
    "--min-detection",
    "min_detection",
    default=30.0,
    show_default=True,
    type=float,
    help="Minimum required detection rate (0–100). Fails if scanner detects less.",
)
@click.option(
    "--max-fp",
    "max_fp",
    default=None,
    type=float,
    help="Maximum allowed false-positive rate (0–100). Checked only when set.",
)
@click.option(
    "--max-error-rate",
    type=float,
    default=5.0,
    show_default=True,
    help="Exit 2 (inconclusive) when more than this percentage of submissions "
    "errored instead of returning a verdict. Errored submissions are not "
    "bypasses and are excluded from the detection rate.",
)
@click.option(
    "--seed",
    type=int,
    default=None,
    help="Seed forwarded to `evadex scan --seed` and `evadex falsepos --seed` so "
    "the gate is reproducible run to run.",
)
@click.option(
    "--fp-count",
    type=int,
    default=100,
    show_default=True,
    help="Invalid values per category submitted for the --max-fp check.",
)
@click.option(
    "--tier",
    "tier",
    default="northam",
    show_default=True,
    type=_TIER_CHOICES,
    help="Payload tier to scan.",
)
@click.option(
    "--fast",
    is_flag=True,
    default=False,
    help="Use fast mode — high-bypass techniques only.",
)
@click.option(
    "--scanner-label",
    "scanner_label",
    default=None,
    help="Label for the scanner in CI output.",
)
@click.option(
    "--transport",
    "transport",
    default=None,
    type=_TRANSPORT_CHOICES,
    help="Transport mode: cli, http, or auto.",
)
@click.option(
    "--url",
    "url",
    default=None,
    help="Scanner HTTP URL (for --transport http/auto).",
)
@click.option(
    "--api-key",
    "api_key",
    default=None,
    envvar="EVADEX_API_KEY",
    help="API key for the scanner HTTP endpoint.",
)
@click.option(
    "--concurrency",
    "concurrency",
    default=None,
    type=int,
    help="Override concurrency for the underlying scan.",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to evadex.yaml config file.",
)
def ci(
    min_detection: float,
    max_fp: float | None,
    max_error_rate: float,
    seed: int | None,
    fp_count: int,
    tier: str,
    fast: bool,
    scanner_label: str | None,
    transport: str | None,
    url: str | None,
    api_key: str | None,
    concurrency: int | None,
    config_path: str | None,
) -> None:
    """Run a scan and exit non-zero if detection thresholds are not met.

    Useful in CI/CD pipelines as a quality gate.

    \b
    Examples:
      evadex ci --min-detection 30                        # default northam tier
      evadex ci --min-detection 30 --max-fp 20 --fast     # fast mode + FP gate
      evadex ci --transport http --url http://localhost:8080 --min-detection 40
    """
    tier_label = scanner_label or tier
    console.print(f"[bold]evadex ci[/bold] — {tier_label} tier")
    console.print("─" * 50)

    # ── Build the evadex scan subprocess command ─────────────────────────
    cmd: list[str] = [
        sys.executable,
        "-m",
        "evadex",
        "scan",
        "--tier",
        tier,
        "--format",
        "json",
        "--no-stream",  # batch mode so stdout contains complete JSON
    ]
    if fast:
        cmd.append("--fast")
    if scanner_label:
        cmd.extend(["--scanner-label", scanner_label])
    if transport:
        cmd.extend(["--transport", transport])
    if url:
        cmd.extend(["--url", url])
    if api_key:
        cmd.extend(["--api-key", api_key])
    if concurrency:
        cmd.extend(["--concurrency", str(concurrency)])
    if config_path:
        cmd.extend(["--config", config_path])
    if seed is not None:
        cmd.extend(["--seed", str(seed)])

    console.print(f"[dim]Running: {' '.join(cmd[:6])} ...[/dim]")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except Exception as exc:
        console.print(f"[red]Scan failed to start: {exc}[/red]")
        sys.exit(2)

    if proc.returncode not in (0, 1):
        # evadex scan exits 0 on success, 1 on adapter/engine errors
        stderr_preview = (
            proc.stderr.decode("utf-8", "replace")[:500] if proc.stderr else ""
        )
        console.print(f"[red]Scan process exited with code {proc.returncode}[/red]")
        if stderr_preview:
            console.print(f"[dim]{stderr_preview}[/dim]")
        sys.exit(2)

    raw_stdout = proc.stdout.decode("utf-8", "replace").strip() if proc.stdout else ""
    if not raw_stdout:
        console.print("[red]Scan produced no output.[/red]")
        if proc.stderr:
            console.print(f"[dim]{proc.stderr.decode('utf-8', 'replace')[:500]}[/dim]")
        sys.exit(2)

    # evadex scan --format json may emit progress lines to stderr and JSON to
    # stdout.  Find the last line that parses as JSON.
    scan_data: dict | None = None
    for line in reversed(raw_stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                scan_data = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    if scan_data is None:
        # Try the whole stdout as a single JSON blob
        try:
            scan_data = json.loads(raw_stdout)
        except json.JSONDecodeError:
            console.print("[red]Could not parse scan output as JSON.[/red]")
            console.print(f"[dim]{raw_stdout[:300]}[/dim]")
            sys.exit(2)

    meta = scan_data.get("meta", {})
    total = int(meta.get("total") or 0)
    errors = int(meta.get("error") or 0)
    if "error_rate" in meta:
        error_rate = float(meta["error_rate"])
    else:
        error_rate = round(errors / total * 100, 1) if total else 0.0
    # `detection_rate` (v3.41.0) excludes errored submissions. Older scan
    # output has only `pass_rate`, which counted them as misses.
    detection_rate = float(meta.get("detection_rate", meta.get("pass_rate", 0.0)))
    if meta.get("seed") is not None:
        console.print(
            f"[dim]Seed: {meta['seed']} (pass --seed {meta['seed']} to repeat)[/dim]"
        )

    # ── Error gate: inconclusive before it is a verdict ──────────────────
    err_ok = error_rate <= max_error_rate
    err_sym = _CHECK if err_ok else _CROSS
    err_color = "green" if err_ok else "red"
    console.print(
        f"[{err_color}]{err_sym}[/{err_color}] Errored submissions: "
        f"[bold]{errors}/{total}[/bold] ({error_rate:.1f}%, max {max_error_rate:.0f}%)"
    )
    if not err_ok:
        console.print()
        console.print(
            "[bold red]Inconclusive: too many submissions errored; "
            "this run says nothing about detection.[/bold red]"
        )
        sys.exit(2)

    # ── Threshold checks ─────────────────────────────────────────────────
    checks_passed = True

    # Detection rate check
    det_ok = detection_rate >= min_detection
    if not det_ok:
        checks_passed = False
    det_sym = _CHECK if det_ok else _CROSS
    det_color = "green" if det_ok else "red"
    console.print(
        f"[{det_color}]{det_sym}[/{det_color}] Detection rate: "
        f"[bold]{detection_rate:.1f}%[/bold] "
        f"(threshold: {min_detection:.0f}%)"
    )

    # False-positive rate check (optional): a second measurement, not a
    # field of the scan output. `evadex scan` submits only true positives and
    # has never written a false-positive rate; reading one from its meta
    # defaulted to 0.0 and passed every gate before v3.41.0.
    if max_fp is not None:
        fp_rate = _measure_false_positive_rate(
            config_path=config_path,
            url=url,
            concurrency=concurrency,
            count=fp_count,
            seed=seed,
        )
        fp_ok = fp_rate <= max_fp
        if not fp_ok:
            checks_passed = False
        fp_sym = _CHECK if fp_ok else _CROSS
        fp_color = "green" if fp_ok else "red"
        console.print(
            f"[{fp_color}]{fp_sym}[/{fp_color}] False positive rate: "
            f"[bold]{fp_rate:.1f}%[/bold] "
            f"(threshold: {max_fp:.0f}%)"
        )

    console.print()
    if checks_passed:
        console.print("[bold green]All thresholds met.[/bold green]")
        sys.exit(0)
    else:
        console.print("[bold red]One or more thresholds violated.[/bold red]")
        sys.exit(1)


def _measure_false_positive_rate(
    *,
    config_path: str | None,
    url: str | None,
    concurrency: int | None,
    count: int,
    seed: int | None,
) -> float:
    """Run ``evadex falsepos`` under the same config and return its rate.

    Values are wrapped in keyword sentences (``--wrap-context``) so the
    measurement matches the conditions ``evadex scan`` grades detection
    under. Exits 2 when the measurement cannot be taken: a gate that cannot
    measure must not report a pass.
    """
    cmd: list[str] = [
        sys.executable,
        "-m",
        "evadex",
        "falsepos",
        "--format",
        "json",
        "--count",
        str(count),
        "--wrap-context",
    ]
    if config_path:
        cmd.extend(["--config", config_path])
    if url:
        cmd.extend(["--url", url])
    if concurrency:
        cmd.extend(["--concurrency", str(concurrency)])
    if seed is not None:
        cmd.extend(["--seed", str(seed)])

    console.print(f"[dim]Running: {' '.join(cmd[:6])} ...[/dim]")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except Exception as exc:
        console.print(f"[red]False-positive check failed to start: {exc}[/red]")
        sys.exit(2)

    raw = proc.stdout.decode("utf-8", "replace").strip() if proc.stdout else ""
    report = None
    if raw:
        try:
            report = json.loads(raw)
        except json.JSONDecodeError:
            report = None
    if (
        proc.returncode != 0
        or not isinstance(report, dict)
        or "overall_false_positive_rate" not in report
    ):
        console.print(
            f"[red]False-positive check failed (falsepos exit {proc.returncode}); "
            "the gate cannot report a pass without it.[/red]"
        )
        if proc.stderr:
            console.print(f"[dim]{proc.stderr.decode('utf-8', 'replace')[:500]}[/dim]")
        sys.exit(2)
    return float(report["overall_false_positive_rate"])
