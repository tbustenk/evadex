"""``evadex profile`` — manage named, saved scan configurations.

Subcommands:

* ``create``  — interactive (``-q`` for scriptable) wizard that writes a new profile
* ``list``    — user + built-in profiles
* ``show``    — dump a profile as YAML
* ``run``     — execute one or more profiles
* ``edit``    — open a profile in ``$EDITOR`` (falls back to the OS default)
* ``delete``  — remove a user profile
* ``export``  — write a profile to an arbitrary path (for sharing)
* ``import``  — copy a YAML file into the user profiles directory
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from evadex.profiles import (
    Profile,
    ProfileError,
    delete_profile,
    list_builtin_profiles,
    list_profiles,
    load_builtin_profile,
    load_profile,
    profile_path,
    profile_to_falsepos_argv,
    profile_to_scan_argv,
    profiles_dir,
    save_profile,
)
from evadex.profiles.schema import parse_profile
from evadex.profiles.storage import update_last_run


err_console = Console(stderr=True)
out_console = Console()


@click.group("profile")
def profile() -> None:
    """Manage named, saved evadex scan configurations.

    \b
    Save a scan setup once, re-run it any time with a short name.
    Profiles are stored in ~/.evadex/profiles/.

    \b
    Examples:
      evadex profile create banking-weekly   # interactive wizard
      evadex profile list                    # show all profiles
      evadex profile run banking-weekly      # execute a saved profile
      evadex profile show banking-weekly     # inspect a profile's settings
    """


# ── create ─────────────────────────────────────────────────────────────────


@profile.command("create")
@click.argument("name")
@click.option("--description", default=None, help="Short description of what this profile is for.")
@click.option("--tool", default="siphon-cli", show_default=True,
              help="Adapter the profile will use.")
@click.option("--tier", default="banking", show_default=True,
              help="Payload tier: banking, core, regional, full.")
@click.option("--strategy", "strategies", multiple=True,
              help="Strategy (text / docx / pdf / xlsx). Repeat for multiple.")
@click.option("--exe", default=None, help="Path to scanner binary.")
@click.option("--cmd-style", default=None, help="cmd-style: python / rust / binary / cargo.")
@click.option("--scanner-label", default=None)
@click.option("--evasion-mode", default="exhaustive", show_default=True)
@click.option("--min-detection-rate", type=float, default=None)
@click.option("--require-context", is_flag=True, default=False)
@click.option("--wrap-context", is_flag=True, default=False)
@click.option("--falsepos/--no-falsepos", default=False,
              help="Include a false-positive run in this profile.")
@click.option("--falsepos-count", type=int, default=100, show_default=True)
@click.option("--c2-url", default=None,
              help="Push results to this Siphon-C2 URL. Supports ${ENV_VAR}.")
@click.option("--c2-key", default=None,
              help="API key for C2 push. Supports ${ENV_VAR}.")
@click.option("--cron", default=None,
              help="Cron expression (5 fields). Stored under schedule.cron.")
def profile_create(
    name: str,
    description: Optional[str],
    tool: str,
    tier: Optional[str],
    strategies: tuple,
    exe: Optional[str],
    cmd_style: Optional[str],
    scanner_label: Optional[str],
    evasion_mode: str,
    min_detection_rate: Optional[float],
    require_context: bool,
    wrap_context: bool,
    falsepos: bool,
    falsepos_count: int,
    c2_url: Optional[str],
    c2_key: Optional[str],
    cron: Optional[str],
) -> None:
    """Create a new profile from flags and save it to ~/.evadex/profiles."""
    scan: dict = {
        "tool": tool,
        "tier": tier,
        "evasion_mode": evasion_mode,
    }
    if strategies:
        scan["strategy"] = list(strategies)
    else:
        scan["strategy"] = "text"
    if exe:
        scan["exe"] = exe
    if cmd_style:
        scan["cmd_style"] = cmd_style
    if scanner_label:
        scan["scanner_label"] = scanner_label
    if min_detection_rate is not None:
        scan["min_detection_rate"] = min_detection_rate
    if require_context:
        scan["require_context"] = True
    if wrap_context:
        scan["wrap_context"] = True

    fp_section: dict = {"enabled": bool(falsepos)}
    if falsepos:
        fp_section["count"] = falsepos_count
        fp_section["wrap_context"] = bool(wrap_context)

    c2_section: dict = {}
    if c2_url:
        c2_section["url"] = c2_url
    if c2_key:
        c2_section["key"] = c2_key

    schedule_section: dict = {}
    if cron:
        schedule_section["cron"] = cron

    p = Profile(
        name=name,
        description=description,
        scan=scan,
        falsepos=fp_section,
        c2=c2_section,
        schedule=schedule_section,
    )
    try:
        # Validate by round-tripping through parse_profile.
        parse_profile(p.to_dict())
        path = save_profile(p)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    out_console.print(f"[green]Created profile[/green] '{name}' at [dim]{path}[/dim]")


# ── list ───────────────────────────────────────────────────────────────────


@profile.command("list")
@click.option("--builtins-only", "builtins_only", is_flag=True, default=False,
              help="Show only built-in profiles.")
@click.option("--user-only", "user_only", is_flag=True, default=False,
              help="Show only user profiles.")
def profile_list(builtins_only: bool, user_only: bool) -> None:
    """List profiles (user profiles first, built-ins after)."""
    user_names = [] if builtins_only else list_profiles()
    builtin_names = [] if user_only else list_builtin_profiles()
    # A user profile shadows a built-in of the same name; mark that.
    user_set = set(user_names)
    builtin_set = set(builtin_names)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Source")
    table.add_column("Description")
    table.add_column("Last run", no_wrap=True)

    for name in user_names:
        try:
            p = load_profile(name)
        except ProfileError as e:
            table.add_row(name, "user (invalid)", f"[red]{e}[/red]", "-")
            continue
        source = "user (shadows built-in)" if name in builtin_set else "user"
        table.add_row(name, source, p.description or "-", p.last_run or "-")

    for name in builtin_names:
        if name in user_set:
            continue  # shown above
        p = load_builtin_profile(name)
        table.add_row(name, "built-in", p.description or "-", "-")

    if table.row_count == 0:
        err_console.print(
            "[dim]No profiles. Run 'evadex profile create <name>' or use a built-in.[/dim]"
        )
        return
    out_console.print(table)
    err_console.print(f"[dim]User profiles dir: {profiles_dir()}[/dim]")


# ── show ───────────────────────────────────────────────────────────────────


@profile.command("show")
@click.argument("name")
@click.option("--expand-env", is_flag=True, default=False,
              help="Substitute ${ENV_VAR} placeholders in the output.")
def profile_show(name: str, expand_env: bool) -> None:
    """Dump a profile as YAML to stdout."""
    try:
        p = load_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if expand_env:
        from evadex.profiles.schema import expand_profile
        p = expand_profile(p)
    import yaml
    sys.stdout.write(yaml.safe_dump(p.to_dict(), sort_keys=False))


# ── run ────────────────────────────────────────────────────────────────────


@profile.command("run")
@click.argument("names", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, default=False,
              help="Print the argv that would be invoked and exit. No scan is run.")
@click.option("--skip-falsepos", is_flag=True, default=False,
              help="Skip the profile's falsepos run even if it is enabled.")
def profile_run(names: tuple, dry_run: bool, skip_falsepos: bool) -> None:
    """Run one or more profiles end-to-end.

    Each profile is translated into an ``evadex scan`` (and optionally
    ``evadex falsepos``) subprocess invocation. Profiles run sequentially so
    output archives and audit logs remain clear.
    """
    exit_code = 0
    for name in names:
        try:
            p = load_profile(name)
        except ProfileError as e:
            err_console.print(f"[red]{e}[/red]")
            exit_code = 1
            continue

        scan_argv = profile_to_scan_argv(p)
        fp_argv = None if skip_falsepos else profile_to_falsepos_argv(p)

        if dry_run:
            err_console.print(f"[bold]{name}[/bold] — dry-run:")
            out_console.print("  scan:     evadex scan " + " ".join(_shq(a) for a in scan_argv))
            if fp_argv is not None:
                out_console.print("  falsepos: evadex falsepos " + " ".join(_shq(a) for a in fp_argv))
            continue

        err_console.print(f"[bold cyan]Running profile '{name}'[/bold cyan]")
        rc = _invoke(["scan"] + scan_argv)
        if rc != 0:
            err_console.print(f"[yellow]scan exited {rc}[/yellow]")
            exit_code = rc
        if fp_argv is not None:
            rc = _invoke(["falsepos"] + fp_argv)
            if rc != 0:
                err_console.print(f"[yellow]falsepos exited {rc}[/yellow]")
                exit_code = rc

        # Stamp last_run on user-saved profiles only (built-ins are read-only).
        try:
            update_last_run(name)
        except ProfileError:
            pass

    sys.exit(exit_code)


def _invoke(argv: list) -> int:
    """Invoke ``python -m evadex <argv>`` and stream stdio back."""
    cmd = [sys.executable, "-m", "evadex"] + argv
    err_console.print(f"[dim]$ {' '.join(_shq(a) for a in cmd)}[/dim]")
    return subprocess.call(cmd)


def _shq(s: str) -> str:
    if os.name == "nt":
        # Windows subprocess handles quoting; for display just wrap anything with spaces.
        return f'"{s}"' if " " in s or "\t" in s else s
    return shlex.quote(s)


# ── edit ───────────────────────────────────────────────────────────────────


@profile.command("edit")
@click.argument("name")
def profile_edit(name: str) -> None:
    """Open the profile in ``$EDITOR`` (or the OS default for .yaml)."""
    try:
        p = load_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if p.builtin:
        err_console.print(
            f"[yellow]'{name}' is a built-in profile — copying to user profiles dir "
            f"so your edits persist.[/yellow]"
        )
        p.builtin = False
        p.source_path = None
        save_profile(p)
    path = profile_path(name)
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL")
    if editor:
        rc = subprocess.call([editor, str(path)])
        sys.exit(rc)
    # Fall back to OS default.
    if sys.platform == "win32":
        os.startfile(str(path))  # noqa: S606 — user-requested editor
    elif sys.platform == "darwin":
        subprocess.call(["open", str(path)])
    else:
        subprocess.call(["xdg-open", str(path)])


# ── delete ─────────────────────────────────────────────────────────────────


@profile.command("delete")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation.")
def profile_delete(name: str, yes: bool) -> None:
    """Remove a user profile. Built-in profiles cannot be deleted."""
    if not yes:
        if not click.confirm(f"Delete profile '{name}'?", default=False):
            err_console.print("[dim]Cancelled.[/dim]")
            return
    try:
        path = delete_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    out_console.print(f"[green]Deleted[/green] {path}")


# ── export / import ────────────────────────────────────────────────────────


@profile.command("export")
@click.argument("name")
@click.option("--output", "-o", default=None,
              help="Path to write to. Defaults to <name>.yaml in the cwd.")
def profile_export(name: str, output: Optional[str]) -> None:
    """Write a profile to an arbitrary path for sharing."""
    try:
        p = load_profile(name)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    out_path = Path(output) if output else Path.cwd() / f"{name}.yaml"
    import yaml
    out_path.write_text(yaml.safe_dump(p.to_dict(), sort_keys=False), encoding="utf-8")
    out_console.print(f"[green]Exported[/green] {name} → {out_path}")


@profile.command("import")
@click.argument("path")
@click.option("--name", default=None, help="Override the profile's name (default: file's 'name' field).")
@click.option("--overwrite", is_flag=True, default=False)
def profile_import(path: str, name: Optional[str], overwrite: bool) -> None:
    """Copy a profile YAML into the user profiles directory."""
    src = Path(path)
    if not src.is_file():
        err_console.print(f"[red]File not found: {src}[/red]")
        sys.exit(1)
    import yaml
    try:
        raw = yaml.safe_load(src.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        err_console.print(f"[red]Invalid YAML: {e}[/red]")
        sys.exit(1)
    if name:
        raw["name"] = name
    try:
        p = parse_profile(raw)
        saved = save_profile(p, overwrite=overwrite)
    except ProfileError as e:
        err_console.print(f"[red]{e}[/red]")
        sys.exit(1)
    out_console.print(f"[green]Imported[/green] {src} → {saved}")
