"""evadex watch — monitor Siphon for detection-rate regressions.

Runs an initial baseline scan then re-scans at a fixed interval.  If the
detection rate drops by more than ``--threshold`` percentage points compared
to the baseline, a regression alert is printed (and optionally POSTed to a
webhook URL).  The command runs indefinitely until interrupted.

Exit codes:
  0  Interrupted cleanly (Ctrl-C)
  1  Any scan or subprocess error before the baseline was established
"""

from __future__ import annotations

import asyncio
import json as _json
import sys
from typing import Optional

import click
from rich.console import Console

_console = Console()


@click.command("watch")
@click.option(
    "--scanner-label",
    default="siphon-cli",
    show_default=True,
    help="evadex tool / adapter label to use for each scan run.",
)
@click.option(
    "--threshold",
    default=5.0,
    type=float,
    show_default=True,
    help="Percentage-point drop that triggers a regression alert.",
)
@click.option(
    "--interval",
    default=300,
    type=int,
    show_default=True,
    help="Seconds between scan runs.",
)
@click.option(
    "--webhook",
    default=None,
    help="URL to POST a JSON regression alert to (optional).",
)
@click.option(
    "--tier",
    default="northam",
    show_default=True,
    type=click.Choice(
        ["northam", "banking", "core", "regional", "full"], case_sensitive=False
    ),
    help="evadex payload tier to scan against.",
)
@click.option(
    "--baseline",
    "baseline_mode",
    type=click.Choice(["fixed", "sliding"], case_sensitive=False),
    default="fixed",
    show_default=True,
    help="Baseline mode: 'fixed' uses the first run (default); 'sliding' uses "
    "a rolling average of the last --window runs.",
)
@click.option(
    "--window",
    "window",
    default=5,
    type=int,
    show_default=True,
    help="Number of recent runs to average for the sliding baseline (used with --baseline sliding).",
)
def watch(
    scanner_label: str,
    threshold: float,
    interval: int,
    webhook: Optional[str],
    tier: str,
    baseline_mode: str,
    window: int,
) -> None:
    """Watch Siphon for detection-rate regressions.

    Establishes a baseline detection rate then re-scans at --interval seconds.
    Prints an alert and optionally POSTs to --webhook when the rate drops by
    more than --threshold percentage points.

    \b
    Examples:
      evadex watch                                    # defaults: siphon-cli, northam, 5pp, 300s
      evadex watch --tier banking --threshold 3       # stricter threshold on banking payloads
      evadex watch --interval 60 --webhook https://hooks.example.com/evadex
    """
    try:
        asyncio.run(
            _watch_loop(
                scanner_label=scanner_label,
                threshold=threshold,
                interval=interval,
                webhook=webhook,
                tier=tier,
                baseline_mode=baseline_mode,
                window=window,
            )
        )
    except KeyboardInterrupt:
        _console.print("\n[dim]watch interrupted[/dim]")
        sys.exit(0)


async def _watch_loop(
    scanner_label: str,
    threshold: float,
    interval: int,
    webhook: Optional[str],
    tier: str,
    baseline_mode: str = "fixed",
    window: int = 5,
) -> None:
    _console.print(
        f"[bold]evadex watch[/bold] · tool=[cyan]{scanner_label}[/cyan] "
        f"tier=[cyan]{tier}[/cyan] threshold=[yellow]{threshold}pp[/yellow] "
        f"interval=[yellow]{interval}s[/yellow]"
    )

    baseline_rate: Optional[float] = None
    recent_rates: list[float] = []  # for sliding mode
    run_count = 0

    while True:
        run_count += 1
        _console.print(f"[dim]run #{run_count} — scanning…[/dim]")
        rate = await _run_scan(scanner_label, tier)

        if rate is None:
            _console.print(
                f"[yellow]⚠[/yellow] run #{run_count}: scan failed — skipping"
            )
            if baseline_rate is None and not recent_rates:
                sys.exit(1)
        else:
            recent_rates.append(rate)
            # Compute effective baseline
            if baseline_mode == "sliding":
                window_rates = recent_rates[-window:]
                current_baseline = sum(window_rates) / len(window_rates)
                baseline_label = f"sliding({len(window_rates)}/{window})"
            else:
                if baseline_rate is None:
                    baseline_rate = rate
                current_baseline = baseline_rate
                baseline_label = "baseline"

            if (baseline_mode == "fixed" and len(recent_rates) == 1) or (
                baseline_mode == "sliding" and len(recent_rates) <= window
            ):
                _console.print(
                    f"[green]✓[/green] run #{run_count}: {baseline_label} "
                    f"[green]{rate:.1f}%[/green] detection rate"
                )
            else:
                # For sliding, compare current run vs sliding baseline of PREVIOUS window
                if baseline_mode == "sliding":
                    prev_window = (
                        recent_rates[-(window + 1) : -1]
                        if len(recent_rates) > window
                        else recent_rates[:-1]
                    )
                    compare_baseline = (
                        sum(prev_window) / len(prev_window)
                        if prev_window
                        else current_baseline
                    )
                else:
                    compare_baseline = current_baseline
                drop = compare_baseline - rate
                if drop >= threshold:
                    _console.print(
                        f"[red]✗[/red] run #{run_count}: REGRESSION — "
                        f"{baseline_label} [cyan]{compare_baseline:.1f}%[/cyan] → "
                        f"current [red]{rate:.1f}%[/red] (−{drop:.1f}pp)"
                    )
                    await _send_webhook(
                        webhook, scanner_label, tier, compare_baseline, rate, drop
                    )
                else:
                    _console.print(
                        f"[green]✓[/green] run #{run_count}: OK — "
                        f"{rate:.1f}% ({baseline_label} {compare_baseline:.1f}%, Δ{drop:+.1f}pp)"
                    )

        await asyncio.sleep(interval)


async def _run_scan(scanner_label: str, tier: str) -> Optional[float]:
    """Invoke ``evadex scan`` and return the detection rate (0–100) or None."""
    argv = [
        sys.executable,
        "-m",
        "evadex",
        "scan",
        "--tool",
        scanner_label,
        "--tier",
        tier,
        "--progress-json",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        return None

    last_tick: dict = {}
    assert proc.stderr is not None
    async for raw in proc.stderr:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            tick = _json.loads(line)
            if "tested" in tick or "total" in tick:
                last_tick = tick
        except ValueError:
            pass

    await proc.wait()
    if proc.returncode != 0 and not last_tick:
        return None

    total = int(last_tick.get("total", 0))
    detected = int(last_tick.get("detected", 0))
    if total == 0:
        return None
    return detected / total * 100.0


async def _send_webhook(
    webhook: Optional[str],
    scanner_label: str,
    tier: str,
    baseline: float,
    current: float,
    drop: float,
) -> None:
    if not webhook:
        return
    payload = {
        "event": "evadex_regression",
        "scanner": scanner_label,
        "tier": tier,
        "baseline_rate": round(baseline, 2),
        "current_rate": round(current, 2),
        "drop_pp": round(drop, 2),
    }
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(webhook, json=payload)
    except Exception as exc:
        _console.print(f"[yellow]⚠[/yellow] webhook POST failed: {exc}")
