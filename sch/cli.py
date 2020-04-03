"""
SmartCronHelper - A shell wrapper for Healthchecks monitored cron jobs
"""

import sys

import click

from sch import sch


@click.group(invoke_without_command=True, no_args_is_help=True)
@click.version_option()
@click.option('-c', '--shell_command', help='command to execute')
def main(shell_command=None):
    """
    sch - A cron shell wrapper for registering and updating cron jobs
    automatically in healthchecks
    """
    if shell_command:
        sch.shell(shell_command)


@main.command('list')
@click.option('-a', '--all', 'host_filter', flag_value='all')
@click.option('-l', '--local', 'host_filter', flag_value='local',
              default=True)
@click.option('-s', '--status', 'status_filter',
              type=click.Choice(['up', 'down', 'grace', 'pause', 'new']))
def listchecks(host_filter, status_filter):
    """
    list Healthchecks checks
    """
    healthchecks = sch.get_hc_api()
    healthchecks.print_status(host_filter, status_filter)


if __name__ == "__main__":
    sys.exit(main(''))  # pragma: no cover
