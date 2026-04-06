import sys
import click
from pathlib import Path
from rich.console import Console
from evadex.config import DEFAULT_CONFIG_YAML, CONFIG_FILENAME

err_console = Console(stderr=True)


@click.command(name="init")
def init_cmd():
    """Generate a default evadex.yaml config file in the current directory."""
    target = Path.cwd() / CONFIG_FILENAME
    if target.exists():
        err_console.print(
            f"[red]Error: {CONFIG_FILENAME} already exists. "
            f"Delete it first or edit it directly.[/red]"
        )
        sys.exit(1)
    target.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
    click.echo(f"Created {target}")
    click.echo(f"Edit {CONFIG_FILENAME} then run: evadex scan --config {CONFIG_FILENAME}")
