import click
from rich.console import Console
from evadex.cli.commands.scan import scan
from evadex.cli.commands.compare import compare
from evadex.cli.commands.list_payloads import list_payloads
from evadex.cli.commands.list_techniques import list_techniques

console = Console()


@click.group()
@click.version_option(package_name="evadex")
def main():
    """evadex — DLP evasion test suite."""
    pass


main.add_command(scan)
main.add_command(compare)
main.add_command(list_payloads)
main.add_command(list_techniques)
