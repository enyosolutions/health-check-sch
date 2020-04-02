"""
SmartCronHelper - A shell wrapper for Healthchecks monitored cron jobs
"""

import sys

import click

from sch import sch


@click.command()
@click.version_option()
@click.option('-c', '--command', required=True)
def main(command):
    """
    SmartCronHellper - A shell wrapper for Healthchecks monitored cron jobs
    """
    sch.shell(command)
    return 0


if __name__ == "__main__":
    sys.exit(main(''))  # pragma: no cover
