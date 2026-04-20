"""``evadex schedule`` — manage the ``schedule:`` section of profiles and emit
ready-to-use cron lines or Windows Task Scheduler XML.

evadex does not install schedules into the system scheduler itself — that
touches privileged state (crontab, schtasks) and is platform-specific.
Instead ``schedule add`` records a cron expression inside the profile and
``schedule export`` prints the line or XML you'd hand to your scheduler of
choice. ``schedule run-due`` walks all profiles and runs any whose cron is
firing right now, which is the hook you'd wire into a single system-level
cron entry that polls every minute.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.profiles import (
    ProfileError,
    list_builtin_profiles,
    list_profiles,
    load_profile,
    profile_path,
    save_profile,
)
from evadex.profiles.schedule import (
    export_cron,
    export_windows_task,
    is_due,
    parse_cron,
    write_schedule_to_profile,
)
from evadex.profiles.storage import update_last_run


err_console = Console(stderr=True)
out_console = Console()


@click.group("schedule")
def schedule() -> None:
    """Manage cron-style schedules attached to profiles."""


# ── add ────────────────────────────────────────────────────────────────────


@schedule.command("add")
@click.argument("name")
@click.option("--cron", "cron_expr", required=True,
              help="5-field cron expression, e.g. '0 6 * * *' for 06:00 UTC daily.")
def schedule_add(name: str, cron_expr: str) -> None:
    """Attach a cron expression to profile *name*.

    This writes ``schedule.cron`` into the user profile. It does NOT install
    anything into system cron — use ``evadex schedule export`` to get a line
    you can add to crontab or a Windows task.
    """
    try:
        parse_cron(cron_expr)
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)

    try:
        profile = load_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)

    if profile.builtin:
        # Copy built-in to user dir before editing its schedule.
        err_console.print(
            f"[yellow]'{name}' is a built-in profile — copying to user profiles dir "
            "so the schedule persists.[/yellow]"
        )
        profile.builtin = False
        profile.source_path = None
        save_profile(profile)
        profile = load_profile(name)

    updated = write_schedule_to_profile(profile, cron_expr)
    save_profile(updated, overwrite=True)
    out_console.print(
        f"[green]schedule.cron set to[/green] {cron_expr!r} on profile '{name}'"
    )


# ── list ───────────────────────────────────────────────────────────────────


@schedule.command("list")
def schedule_list() -> None:
    """List all profiles that have a schedule."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("Profile")
    table.add_column("Cron")
    table.add_column("Last run", no_wrap=True)
    table.add_column("Source")

    names = list(dict.fromkeys(list_profiles() + list_builtin_profiles()))
    for name in sorted(names):
        try:
            p = load_profile(name)
        except ProfileError:
            continue
        cron = (p.schedule or {}).get("cron")
        if not cron:
            continue
        table.add_row(
            name, cron, p.last_run or "-",
            "built-in" if p.builtin else "user",
        )

    if table.row_count == 0:
        err_console.print(
            "[dim]No scheduled profiles. Use 'evadex schedule add <name> --cron \"0 6 * * *\"'.[/dim]"
        )
        return
    out_console.print(table)


# ── remove ─────────────────────────────────────────────────────────────────


@schedule.command("remove")
@click.argument("name")
def schedule_remove(name: str) -> None:
    """Clear the schedule from a profile."""
    try:
        profile = load_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if profile.builtin:
        err_console.print(
            f"[red]'{name}' is a built-in profile; built-in schedules can't be removed. "
            "Save your own copy first.[/red]"
        )
        sys.exit(1)
    if not (profile.schedule or {}).get("cron"):
        err_console.print(f"[dim]Profile '{name}' had no schedule; nothing to do.[/dim]")
        return
    profile.schedule = {
        k: v for k, v in (profile.schedule or {}).items() if k != "cron"
    }
    save_profile(profile, overwrite=True)
    out_console.print(f"[green]Cleared schedule.cron from[/green] '{name}'")


# ── export ─────────────────────────────────────────────────────────────────


@schedule.command("export")
@click.argument("name")
@click.option("--format", "fmt", type=click.Choice(["cron", "windows-task"]),
              default="cron", show_default=True,
              help="Output format.")
@click.option("--output", "-o", default=None,
              help="Write to this path instead of stdout (Task Scheduler XML is usually saved to a file).")
def schedule_export(name: str, fmt: str, output: Optional[str]) -> None:
    """Emit a cron line or Task Scheduler XML for the profile's schedule."""
    try:
        p = load_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)

    try:
        if fmt == "cron":
            content = export_cron(p)
        else:
            content = export_windows_task(p)
    except ValueError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        out_console.print(f"[green]Wrote[/green] {fmt} schedule to {output}")
    else:
        sys.stdout.write(content if content.endswith("\n") else content + "\n")


# ── run-due ────────────────────────────────────────────────────────────────


@schedule.command("run-due")
@click.option("--window-minutes", default=5, show_default=True,
              help="Treat schedules firing within the last N minutes as still due.")
@click.option("--dry-run", is_flag=True, default=False)
def schedule_run_due(window_minutes: int, dry_run: bool) -> None:
    """Run every profile whose schedule fires right now.

    Intended to be called from a single system-level cron entry that polls
    every minute (e.g. ``* * * * * evadex schedule run-due``). The
    ``window_minutes`` tolerance catches schedules whose polling interval
    drifts by a few seconds.
    """
    now = datetime.now(timezone.utc)
    due: list[str] = []
    names = list(dict.fromkeys(list_profiles() + list_builtin_profiles()))
    for name in sorted(names):
        try:
            p = load_profile(name)
        except ProfileError:
            continue
        if is_due(p, now=now, window_minutes=window_minutes):
            due.append(name)

    if not due:
        err_console.print(f"[dim]No profiles due at {now.isoformat()}.[/dim]")
        return

    err_console.print(
        f"[bold cyan]Due now:[/bold cyan] {', '.join(due)}"
    )
    if dry_run:
        return

    # Invoke ``evadex profile run <names>`` via subprocess so the actual
    # run lives in a child process and this command can exit quickly.
    import subprocess
    cmd = [sys.executable, "-m", "evadex", "profile", "run"] + due
    err_console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    rc = subprocess.call(cmd)
    # Stamp last_run on each user profile so we don't re-fire within the same window.
    for name in due:
        try:
            update_last_run(name)
        except ProfileError:
            pass
    sys.exit(rc)
