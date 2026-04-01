import click
from rich.console import Console
from evadex.cli.commands.scan import scan

console = Console()


@click.group()
@click.version_option(package_name="evadex")
def main():
    """evadex — DLP evasion test suite."""
    pass


main.add_command(scan)
