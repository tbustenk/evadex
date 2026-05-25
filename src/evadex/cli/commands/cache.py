"""evadex cache — manage the scan result cache.

Sub-commands:
  evadex cache stats   — show cache hit rate and entry count
  evadex cache clear   — delete all cached scan results
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

err_console = Console(stderr=True)


@click.group("cache")
def cache() -> None:
    """Manage the evadex scan result cache."""
    pass


@cache.command("stats")
def cache_stats() -> None:
    """Show cache statistics (entry count, hit rate).

    \\b
    Examples:
      evadex cache stats
    """
    from evadex.cache.scan_cache import ScanCache

    c = ScanCache()
    s = c.stats()
    err_console.print("[bold]evadex cache stats[/bold]")
    err_console.print("─" * 34)
    err_console.print(f"  Entries:   [cyan]{s.total_entries:,}[/cyan]")
    err_console.print(
        f"  Hit rate:  [cyan]{s.hit_rate * 100:.1f}%[/cyan]"
        f"  ([dim]{s.hit_count:,} hits / {s.miss_count:,} misses[/dim])"
    )
    db_path = c._db_path
    err_console.print(f"  Store:     [dim]{db_path}[/dim]")


@cache.command("clear")
@click.option("--yes", is_flag=True, default=False, help="Skip confirmation prompt.")
def cache_clear(yes: bool) -> None:
    """Delete all entries from the scan result cache.

    \\b
    Examples:
      evadex cache clear
      evadex cache clear --yes
    """
    from evadex.cache.scan_cache import ScanCache

    if not yes:
        click.confirm("Delete all cached scan results?", abort=True)

    c = ScanCache()
    deleted = c.clear()
    err_console.print(f"[green]Deleted {deleted:,} cache entries.[/green]")
