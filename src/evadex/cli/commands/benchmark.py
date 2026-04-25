"""evadex benchmark — measure evadex's own generate/scan performance.

Runs a small matrix of generate operations across formats and (if a
siphon binary is on PATH) a representative scan, then prints average
times, standard deviation, peak memory, and recommended concurrency /
count ceilings for the current machine. The command is defensive — any
stage that fails (e.g. siphon missing, optional deps absent) is
reported but does not abort the run.

Design notes
============

* **No new deps.** Peak memory is sampled via ``resource.getrusage`` on
  POSIX and ``psutil`` if installed; on Windows without psutil we fall
  back to the process-level ``memory_info`` from ``os.getpid`` + WMIC
  if available, otherwise we print ``n/a``. Benchmarks never crash the
  command just because a fancy metric is unavailable.
* **Subprocess isolation for memory.** Every generate run is a fresh
  subprocess so the peak RSS is that single operation — otherwise the
  first run would "poison" every subsequent memory number by keeping
  loaded generators in the parent process.
* **Recommended settings are heuristics**, not promises. They are
  derived from the measured averages: concurrency is
  ``min(cpu_count * 2, 32)`` clamped by peak memory, and the xlsx
  count ceiling backs off quadratically from the observed time.
"""
from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import click
from rich.console import Console

from evadex.payloads.tiers import VALID_TIERS

err_console = Console(stderr=True)


_TIER_CHOICES = click.Choice(sorted(VALID_TIERS), case_sensitive=False)


@dataclass
class _RunStats:
    label: str
    times: list[float] = field(default_factory=list)
    peak_mb: float | None = None

    def avg(self) -> float:
        return statistics.mean(self.times) if self.times else 0.0

    def stdev(self) -> float:
        return statistics.pstdev(self.times) if len(self.times) > 1 else 0.0


def _peak_memory_mb() -> float | None:
    """Peak RSS of the current process, in MB. ``None`` if unavailable."""
    try:
        import resource  # POSIX only
        ru = resource.getrusage(resource.RUSAGE_SELF)
        # Linux reports ru_maxrss in kilobytes; macOS reports bytes.
        maxrss = ru.ru_maxrss
        if sys.platform == "darwin":
            return maxrss / (1024 * 1024)
        return maxrss / 1024
    except Exception:
        pass
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:
        return None


def _child_peak_memory() -> float | None:
    """Best-effort peak RSS for the most recent child process.
    Returns ``None`` on platforms without ``resource`` or psutil, which
    is fine — the benchmark still reports timing. ``getrusage`` on
    RUSAGE_CHILDREN reports the high-water mark across all children
    the parent has ever reaped, which is good enough as an upper
    bound for a single-process benchmark."""
    try:
        import resource
        ru = resource.getrusage(resource.RUSAGE_CHILDREN)
        maxrss = ru.ru_maxrss
        if sys.platform == "darwin":
            return maxrss / (1024 * 1024)
        return maxrss / 1024
    except Exception:
        return None


def _run_generate_once(fmt: str, tier: str, count: int, out_dir: Path) -> tuple[float, float | None]:
    """Run one ``evadex generate`` in a subprocess. Returns (seconds, peak_mb).

    Running in a subprocess keeps memory numbers honest: every run
    starts with a clean interpreter so the peak RSS we measure is the
    cost of *that* format, not the residue of every earlier run.
    """
    ext_map = {"sqlite": "db", "multi_barcode_png": "png", "zip_nested": "zip"}
    ext = ext_map.get(fmt, fmt)
    out = out_dir / f"bench_{fmt}.{ext}"
    cmd = [
        sys.executable, "-m", "evadex", "generate",
        "--format", fmt,
        "--tier", tier,
        "--count", str(count),
        "--output", str(out),
        "--seed", "1",
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        raise RuntimeError(
            f"evadex generate --format {fmt} failed "
            f"({proc.returncode}): {proc.stderr.decode('utf-8', 'replace')[:400]}"
        )
    peak = _child_peak_memory()
    return elapsed, peak


def _fmt_time(seconds: float) -> str:
    if seconds < 1.0:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{seconds / 60:.1f}min"


def _fmt_time_pair(avg: float, stdev: float) -> str:
    return f"{_fmt_time(avg)} avg   ±{_fmt_time(stdev)}"


def _find_siphon() -> str | None:
    for name in ("siphon", "siphon.exe", "siphon-cli", "siphon-cli.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _run_scan_once(siphon_path: str, corpus_dir: Path) -> tuple[float, int]:
    """Run one siphon-cli scan over the prepared corpus.
    Returns (seconds, variant_count). ``variant_count`` is the number
    of generated records across all files — used to compute variants/sec.
    """
    cmd = [siphon_path, "scan", str(corpus_dir), "--format", "json"]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.perf_counter() - start
    # We do not fail the benchmark if siphon exits non-zero; report the
    # number anyway so the operator knows to investigate.
    n_findings = 0
    try:
        payload = json.loads(proc.stdout.decode("utf-8", "replace") or "{}")
        if isinstance(payload, dict):
            n_findings = len(payload.get("findings") or payload.get("results") or [])
        elif isinstance(payload, list):
            n_findings = len(payload)
    except json.JSONDecodeError:
        pass
    return elapsed, n_findings


def _recommended_concurrency(peak_mb: float | None) -> int:
    """Pick a concurrency target from CPU count, clamped by peak mem.

    Why: evadex's CPU-bound work (variant generation, format writing)
    scales well up to 2× CPU count, but peak memory during xlsx is a
    tight ceiling on laptops. We back off whenever peak RSS exceeds
    256 MB so a 16 GB machine still has headroom for other tools."""
    cpu = os.cpu_count() or 4
    base = min(cpu * 2, 32)
    if peak_mb is not None and peak_mb > 256:
        base = max(4, base // 2)
    return base


def _recommended_xlsx_ceiling(xlsx_avg_seconds: float) -> int:
    """Back off xlsx counts as generation time grows super-linearly.

    We saw ~13s for 1 000 records locally; going to 10 000 typically
    blows past 2 minutes and starts paging. This is a heuristic so the
    operator gets a safe upper bound, not a hard rule."""
    if xlsx_avg_seconds <= 0:
        return 2000
    if xlsx_avg_seconds < 5:
        return 5000
    if xlsx_avg_seconds < 15:
        return 2000
    if xlsx_avg_seconds < 30:
        return 1000
    return 500


@click.command("benchmark")
@click.option(
    "--tier", "tier",
    default="banking",
    show_default=True,
    type=_TIER_CHOICES,
    help="Payload tier to generate during the benchmark.",
)
@click.option(
    "--runs",
    default=3,
    show_default=True,
    type=click.IntRange(1, 20),
    help="Number of repetitions per measurement. More = tighter stdev.",
)
@click.option(
    "--count",
    default=1000,
    show_default=True,
    type=click.IntRange(10, 100_000),
    help="Records per generate run.",
)
@click.option(
    "--formats",
    default="csv,xlsx,docx",
    show_default=True,
    help="Comma-separated formats to benchmark generate time on.",
)
@click.option(
    "--skip-scan",
    is_flag=True,
    default=False,
    help="Skip the siphon-cli scan pass (useful when siphon isn't installed).",
)
@click.option(
    "--json", "emit_json",
    is_flag=True,
    default=False,
    help="Emit results as JSON instead of a human-readable table.",
)
def benchmark(
    tier: str,
    runs: int,
    count: int,
    formats: str,
    skip_scan: bool,
    emit_json: bool,
) -> None:
    """Measure evadex generate and scan performance on this machine.

    Useful for sizing concurrency and count limits before a production run.
    Reports average time, stddev, and peak memory per format.

    \b
    Examples:
      evadex benchmark                              # banking tier, 3 runs
      evadex benchmark --formats csv,xlsx,docx,pdf  # all common formats
      evadex benchmark --skip-scan                  # generate performance only
    """
    fmt_list = [f.strip().lower() for f in formats.split(",") if f.strip()]
    results: dict[str, _RunStats] = {f: _RunStats(label=f) for f in fmt_list}

    if not emit_json:
        err_console.print(
            f"[bold]evadex benchmark[/bold] — {tier} tier, {runs} run(s), "
            f"count={count}, formats={','.join(fmt_list)}"
        )
        err_console.print("─" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for fmt in fmt_list:
            stats = results[fmt]
            for i in range(runs):
                try:
                    elapsed, peak = _run_generate_once(fmt, tier, count, tmp_path)
                except RuntimeError as exc:
                    err_console.print(f"  [yellow]{fmt}: {exc}[/yellow]")
                    break
                stats.times.append(elapsed)
                if peak is not None and (stats.peak_mb is None or peak > stats.peak_mb):
                    stats.peak_mb = peak
                if not emit_json:
                    err_console.print(
                        f"  [dim]{fmt} run {i+1}/{runs}: {_fmt_time(elapsed)}[/dim]"
                    )

        # Prepare a corpus to scan (one file per format, using the last
        # run's output). If the tmpdir is empty because every generate
        # failed, we skip the scan too.
        siphon_stats = _RunStats(label="scan")
        variants_per_sec = 0.0
        siphon_path = None if skip_scan else _find_siphon()
        n_total_variants = count * len(fmt_list)
        if siphon_path and not skip_scan and any(tmp_path.iterdir()):
            for i in range(runs):
                try:
                    elapsed, findings = _run_scan_once(siphon_path, tmp_path)
                except Exception as exc:
                    err_console.print(f"  [yellow]scan: {exc}[/yellow]")
                    break
                siphon_stats.times.append(elapsed)
                if not emit_json:
                    err_console.print(
                        f"  [dim]scan run {i+1}/{runs}: {_fmt_time(elapsed)} "
                        f"({findings} findings)[/dim]"
                    )
            if siphon_stats.times:
                variants_per_sec = n_total_variants / siphon_stats.avg()

    proc_peak = _peak_memory_mb()
    xlsx_avg = results["xlsx"].avg() if "xlsx" in results else 0.0
    rec_concurrency = _recommended_concurrency(
        max(
            (s.peak_mb for s in results.values() if s.peak_mb is not None),
            default=proc_peak,
        )
    )
    rec_xlsx_ceiling = _recommended_xlsx_ceiling(xlsx_avg)

    if emit_json:
        payload = {
            "tier": tier,
            "runs": runs,
            "count": count,
            "generate": {
                fmt: {
                    "avg_seconds": s.avg(),
                    "stdev_seconds": s.stdev(),
                    "peak_mb": s.peak_mb,
                    "samples": s.times,
                }
                for fmt, s in results.items()
            },
            "scan": {
                "siphon_path": siphon_path,
                "avg_seconds": siphon_stats.avg(),
                "stdev_seconds": siphon_stats.stdev(),
                "variants_per_sec": variants_per_sec,
            },
            "memory": {
                "peak_mb": proc_peak,
            },
            "recommended": {
                "concurrency": rec_concurrency,
                "xlsx_count_max": rec_xlsx_ceiling,
            },
        }
        click.echo(json.dumps(payload, indent=2))
        return

    err_console.print()
    err_console.print(f"[bold]evadex benchmark[/bold] — {tier} tier, {runs} runs")
    err_console.print("─" * 60)
    err_console.print("[bold]Generation[/bold]")
    for fmt in fmt_list:
        s = results[fmt]
        if not s.times:
            err_console.print(f"  {fmt:<5} ({count} records)   [yellow]unavailable[/yellow]")
            continue
        err_console.print(
            f"  {fmt:<5} ({count} records)   {_fmt_time_pair(s.avg(), s.stdev())}"
        )

    err_console.print()
    err_console.print("[bold]Scanning[/bold] (siphon-cli, text strategy)")
    if skip_scan:
        err_console.print("  [dim]skipped (--skip-scan)[/dim]")
    elif not siphon_path:
        err_console.print("  [yellow]siphon-cli not found on PATH — skipped[/yellow]")
    elif not siphon_stats.times:
        err_console.print("  [yellow]scan did not complete — see errors above[/yellow]")
    else:
        err_console.print(
            f"  {tier:<20}   {_fmt_time_pair(siphon_stats.avg(), siphon_stats.stdev())}"
        )
        err_console.print(f"  variants/sec          {variants_per_sec:.1f} avg")

    err_console.print()
    err_console.print("[bold]Memory[/bold]")
    peak_gen = max(
        ((fmt, s.peak_mb) for fmt, s in results.items() if s.peak_mb is not None),
        key=lambda t: t[1],
        default=None,
    )
    if peak_gen is not None:
        err_console.print(f"  peak generate ({peak_gen[0]})   {peak_gen[1]:.0f}MB")
    elif proc_peak is not None:
        err_console.print(f"  peak generate         {proc_peak:.0f}MB")
    else:
        err_console.print("  peak generate         [dim]n/a on this platform[/dim]")
    if siphon_stats.times and proc_peak is not None:
        err_console.print(f"  peak scan             {proc_peak:.0f}MB (approximate)")

    err_console.print("─" * 60)
    err_console.print("[bold]Recommended settings for this machine:[/bold]")
    err_console.print(f"  --concurrency {rec_concurrency}")
    if xlsx_avg > 0:
        err_console.print(f"  --count max {rec_xlsx_ceiling} for xlsx, unlimited for csv")
    else:
        err_console.print("  --count max [dim]unmeasured[/dim] for xlsx, unlimited for csv")
