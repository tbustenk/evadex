"""evadex status — show current state at a glance.

Reads from:
  - evadex.yaml for scanner config
  - audit.jsonl for last scan/falsepos
  - ~/.evadex/profiles/ for scheduled runs
  - ~/.evadex/cache/ for cache stats
  - Bridge /health for bridge status
"""

from __future__ import annotations

import importlib.metadata as im
import os
import socket
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen

import click
from rich.console import Console

err_console = Console(stderr=True)

_OK = "[green]✓[/green]"
_BAD = "[red]✗[/red]"
_WARN = "[yellow]⚠[/yellow]"
_DIM = "[dim]—[/dim]"


def _evadex_version() -> str:
    try:
        return im.version("evadex")
    except im.PackageNotFoundError:
        return "unknown"


def _load_config() -> tuple[Optional[str], Optional[str]]:
    """Return (scanner_label, exe_path) from evadex.yaml if present."""
    try:
        from evadex.config import find_config, load_config

        cfg_path = find_config()
        if cfg_path is None:
            return None, None
        cfg = load_config(cfg_path)
        return cfg.scanner_label, cfg.exe
    except Exception:
        return None, None


def _audit_log_path() -> Path:
    override = os.environ.get("EVADEX_AUDIT_LOG")
    if override:
        return Path(override)
    # Check evadex.yaml for an explicit audit_log path.
    try:
        from evadex.config import find_config, load_config

        cfg_path = find_config()
        if cfg_path is not None:
            cfg = load_config(cfg_path)
            if cfg.audit_log:
                return Path(cfg.audit_log)
    except Exception:
        pass
    # Fall back to the same default as `evadex scan` and `evadex techniques`.
    return Path("results/audit.jsonl")


def _read_last_entries(audit_path: Path, n: int = 5) -> list[dict]:
    """Return last N audit log entries, oldest first."""
    try:
        from evadex.audit import read_audit_entries

        entries = read_audit_entries(audit_path)
        return entries[-n:] if entries else []
    except Exception:
        return []


def _human_age(ts_str: str) -> str:
    """Turn an ISO timestamp into a human-readable age (e.g. '2h ago')."""
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = now - dt
        secs = int(delta.total_seconds())
        if secs < 60:
            return f"{secs}s ago"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"
    except Exception:
        return "unknown"


def _bridge_status() -> tuple[bool, str]:
    """Return (reachable, url)."""
    url = os.environ.get("EVADEX_BRIDGE_URL", "http://localhost:8081")
    for endpoint in ("/healthz", "/health", "/docs"):
        try:
            with urlopen(url.rstrip("/") + endpoint, timeout=1.5) as resp:
                if 200 <= resp.status < 300:
                    return True, url
        except (URLError, socket.timeout, ConnectionError, OSError, Exception):
            pass
    return False, url


def _cache_stats() -> tuple[int, float]:
    """Return (total_entries, hit_rate)."""
    try:
        from evadex.cache.scan_cache import ScanCache

        c = ScanCache()
        s = c.stats()
        return s.total_entries, s.hit_rate
    except Exception:
        return 0, 0.0


def _profile_count() -> tuple[int, int]:
    """Return (user_profiles, builtin_profiles)."""
    try:
        from evadex.profiles.storage import profiles_dir, _BUILTINS_PACKAGE

        pdir = profiles_dir()
        user = len(list(pdir.glob("*.yaml")))
        builtins = len(list(_BUILTINS_PACKAGE.glob("*.yaml")))
        return user, builtins
    except Exception:
        return 0, 0


def _next_cron_run(expr: str, after: datetime) -> Optional[datetime]:
    """Return the next UTC datetime matching *expr* that is strictly after *after*.

    Scans forward up to 366 days. Returns None if the expression cannot be
    parsed or no match is found within that window.
    """
    try:
        from evadex.profiles.schedule import parse_cron

        spec = parse_cron(expr)
    except Exception:
        return None

    base = after.astimezone(timezone.utc).replace(second=0, microsecond=0) + timedelta(minutes=1)
    base_date = base.date()
    for day_offset in range(366):
        candidate_date = base_date + timedelta(days=day_offset)
        for h in sorted(spec["hour"]):
            for m in sorted(spec["minute"]):
                try:
                    candidate = datetime(
                        candidate_date.year,
                        candidate_date.month,
                        candidate_date.day,
                        h,
                        m,
                        0,
                        tzinfo=timezone.utc,
                    )
                except ValueError:
                    continue
                if candidate < base:
                    continue
                if (
                    candidate.day in spec["day"]
                    and candidate.month in spec["month"]
                    and candidate.weekday() in spec["weekday"]
                ):
                    return candidate
    return None


def _scheduled_profiles() -> list[tuple[str, datetime]]:
    """Return list of (profile_name, next_run_utc) for profiles with schedule.cron."""
    results = []
    try:
        from evadex.profiles.storage import profiles_dir, load_profile

        pdir = profiles_dir()
        now = datetime.now(timezone.utc)
        for yaml_path in sorted(pdir.glob("*.yaml")):
            try:
                profile = load_profile(yaml_path.stem)
                cron = (profile.schedule or {}).get("cron")
                if cron:
                    next_run = _next_cron_run(cron, now)
                    if next_run is not None:
                        results.append((profile.name, next_run))
            except Exception:
                continue
    except Exception:
        pass
    results.sort(key=lambda x: x[1])
    return results


def _detect_scanner_exe(cfg_exe: Optional[str]) -> tuple[str, bool]:
    """Return (display_path, found)."""
    import shutil

    if cfg_exe and Path(cfg_exe).is_file():
        return cfg_exe, True
    for name in ("siphon", "siphon.exe", "siphon-cli", "siphon-cli.exe"):
        found = shutil.which(name)
        if found:
            return found, True
    return "not found", False


@click.command("status")
@click.option(
    "--json",
    "emit_json",
    is_flag=True,
    default=False,
    help="Emit status as JSON.",
)
def status(emit_json: bool) -> None:
    """Show current evadex state at a glance.

    Reads scanner config, last scan/falsepos results, cache stats, bridge
    reachability, and profile counts.

    \\b
    Examples:
      evadex status
      evadex status --json
    """
    import json as _json

    version = _evadex_version()
    scanner_label, cfg_exe = _load_config()
    audit_path = _audit_log_path()
    entries = _read_last_entries(audit_path, n=10)

    # Last scan entry (has pass_rate)
    scan_entries = [e for e in entries if e.get("pass_rate") is not None]
    last_scan: Optional[dict] = scan_entries[-1] if scan_entries else None

    # Last falsepos entry — identified by a falsepos_rate field (or fall back
    # to the same scan entries for now since they share the log)
    fp_entries = [e for e in entries if e.get("fail_rate") is not None or "falsepos" in e.get("tool", "")]
    last_fp: Optional[dict] = fp_entries[-1] if fp_entries else None

    # Detection rate trend (last 3 scans)
    recent_rates = [round(e["pass_rate"], 1) for e in scan_entries[-3:] if "pass_rate" in e]

    # Cache
    cache_entries, cache_hit_rate = _cache_stats()

    # Bridge
    bridge_ok, bridge_url = _bridge_status()

    # Profiles
    user_profiles, builtin_profiles = _profile_count()

    # Scheduled profiles
    scheduled = _scheduled_profiles()

    # Scanner exe
    exe_display, exe_found = _detect_scanner_exe(cfg_exe)

    if emit_json:
        payload = {
            "version": version,
            "scanner_label": scanner_label,
            "scanner_exe": exe_display,
            "scanner_found": exe_found,
            "last_scan": {
                "age": _human_age(last_scan["timestamp"]) if last_scan else None,
                "tier": last_scan.get("tier") if last_scan else None,
                "pass_rate": last_scan.get("pass_rate") if last_scan else None,
            },
            "cache_entries": cache_entries,
            "cache_hit_rate": round(cache_hit_rate * 100, 1),
            "bridge_reachable": bridge_ok,
            "bridge_url": bridge_url,
            "user_profiles": user_profiles,
            "builtin_profiles": builtin_profiles,
            "recent_rates": recent_rates,
            "next_scheduled": [
                {"profile": name, "next_run_utc": dt.isoformat()}
                for name, dt in scheduled
            ],
        }
        click.echo(_json.dumps(payload, indent=2))
        return

    err_console.print()
    err_console.print(f"[bold]evadex v{version}[/bold] — status")
    err_console.print("─" * 52)

    # Scanner
    label_str = f"[cyan]{scanner_label}[/cyan]" if scanner_label else "[dim]not configured[/dim]"
    exe_str = f"[dim]{exe_display}[/dim]"
    scanner_ok = _OK if exe_found else _BAD
    err_console.print(f"  Scanner        {label_str} · {exe_str} {scanner_ok}")

    # Last scan
    if last_scan:
        age = _human_age(last_scan["timestamp"])
        tier = (
            last_scan.get("tier")
            or (last_scan.get("categories") or None)
            and last_scan["categories"][0]
            or last_scan.get("scanner_label")
            or "?"
        )
        rate = round(last_scan.get("pass_rate", 0.0), 1)
        err_console.print(f"  Last scan      [dim]{age}[/dim] · [dim]{tier}[/dim] · [cyan]{rate}%[/cyan] detection")
    else:
        err_console.print(f"  Last scan      {_DIM}  [dim]no scan history found[/dim]")

    # Last falsepos
    if last_fp:
        age = _human_age(last_fp["timestamp"])
        fp_rate = round(last_fp.get("fail_rate", 0.0), 1)
        err_console.print(f"  Last falsepos  [dim]{age}[/dim] · [cyan]{fp_rate}%[/cyan] FP rate")
    else:
        err_console.print(f"  Last falsepos  {_DIM}  [dim]no falsepos history found[/dim]")

    # Cache
    hit_pct = round(cache_hit_rate * 100, 1)
    err_console.print(
        f"  Cache          [cyan]{cache_entries:,}[/cyan] entries · [cyan]{hit_pct}%[/cyan] hit rate"
    )

    # Bridge
    bridge_symbol = _OK if bridge_ok else _WARN
    bridge_state = "online" if bridge_ok else "offline"
    err_console.print(
        f"  Bridge         [dim]{bridge_url}[/dim] · {bridge_state} {bridge_symbol}"
    )

    # Profiles
    err_console.print(
        f"  Profiles       [cyan]{user_profiles}[/cyan] user · [cyan]{builtin_profiles}[/cyan] builtin"
    )

    # Next scheduled
    if scheduled:
        now = datetime.now(timezone.utc)
        next_name, next_dt = scheduled[0]
        delta = next_dt - now
        hours = int(delta.total_seconds() // 3600)
        mins = int((delta.total_seconds() % 3600) // 60)
        if hours >= 24:
            when_str = f"in {hours // 24}d {hours % 24}h"
        elif hours > 0:
            when_str = f"in {hours}h {mins}m"
        else:
            when_str = f"in {mins}m"
        extra = f" [dim](+{len(scheduled) - 1} more)[/dim]" if len(scheduled) > 1 else ""
        err_console.print(
            f"  Next scheduled [dim]{next_name}[/dim] · [cyan]{when_str}[/cyan]{extra}"
        )
    else:
        err_console.print(f"  Next scheduled {_DIM}  [dim]no profiles with schedule.cron[/dim]")

    # Trend
    if len(recent_rates) >= 2:
        arrow = " → "
        trend_str = arrow.join(f"[cyan]{r}%[/cyan]" for r in recent_rates)
        if recent_rates[-1] > recent_rates[-2]:
            trend_note = "[green](→ improving)[/green]"
        elif recent_rates[-1] < recent_rates[-2]:
            trend_note = "[red](→ regressing)[/red]"
        else:
            trend_note = "[dim](→ stable)[/dim]"
        err_console.print(f"  Recent trend   {trend_str}  {trend_note}")
    elif len(recent_rates) == 1:
        err_console.print(f"  Recent trend   [cyan]{recent_rates[0]}%[/cyan]  [dim](only 1 run)[/dim]")

    err_console.print()
