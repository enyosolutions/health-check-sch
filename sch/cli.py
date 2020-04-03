"""
SmartCronHelper - A shell wrapper for Healthchecks monitored cron jobs
"""

import sys

import click

from sch import sch


@click.group(invoke_without_command=True, no_args_is_help=True)
@click.version_option()
@click.option('-c', '--shell_command',
              help='Command to execute. This how Cron'
                   ' executes \'sch\' when it is set as SHELL.')
def main(shell_command=None):
    """
    sch - A cron shell wrapper for registering and updating cron jobs
    automatically in Healthchecks. The Healthchecks project api_url and
    api_key should be configured in /etc/sch.conf.
    """
    if shell_command:
        sch.shell(shell_command)


@main.command('list')
@click.option('--localhost/--all', '-l/-a', 'list_local', default=True,
              help='List checks that originate from this host (default) or '
              'list all checks.')
@click.option('-s', '--status', 'status_filter',
              type=click.Choice(['up', 'down', 'grace',
                                 'started', 'pause', 'new']),
              help='Show only checks that have the specified status.')
def listchecks(list_local, status_filter):
    """
    List checks for the configured Healthchecks project.
    """
    healthchecks = sch.get_hc_api()
    healthchecks.print_status(list_local, status_filter)


if __name__ == "__main__":
    sys.exit(main(''))  # pragma: no cover
