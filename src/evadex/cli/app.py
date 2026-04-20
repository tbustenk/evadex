import sys
import io
import click
from evadex.cli.commands.scan import scan
from evadex.cli.commands.compare import compare
from evadex.cli.commands.generate import generate
from evadex.cli.commands.list_payloads import list_payloads
from evadex.cli.commands.list_techniques import list_techniques
from evadex.cli.commands.init import init_cmd
from evadex.cli.commands.falsepos import falsepos
from evadex.cli.commands.history import history
from evadex.cli.commands.trend import trend
from evadex.cli.commands.entropy import entropy
from evadex.cli.commands.edm import edm
from evadex.cli.commands.lsh import lsh
from evadex.cli.commands.techniques import techniques
from evadex.cli.commands.profile import profile as profile_cmd
from evadex.cli.commands.schedule import schedule as schedule_cmd

# Ensure stdout/stderr use UTF-8 on Windows so that Rich tables with Unicode
# box-drawing characters and special symbols render without codec errors.
if sys.stdout and hasattr(sys.stdout, "buffer") and sys.stdout.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "buffer") and sys.stderr.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


@click.group()
@click.version_option(package_name="evadex")
def main():
    """evadex — DLP evasion test suite."""
    pass


main.add_command(scan)
main.add_command(compare)
main.add_command(generate)
main.add_command(list_payloads)
main.add_command(list_techniques)
main.add_command(init_cmd)
main.add_command(falsepos)
main.add_command(history)
main.add_command(trend)
main.add_command(entropy)
main.add_command(edm)
main.add_command(lsh)
main.add_command(techniques)
main.add_command(profile_cmd)
main.add_command(schedule_cmd)
