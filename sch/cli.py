"""
SmartCronHelper - A shell wrapper for Healthchecks monitored cron jobs
"""

import sys

import click
import os

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
    api_key should be configured in ~/.sch.conf.
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


@main.command('init')
@click.option('--api-url', '-u', 'api_url', default='https://checks.google.com/api/v1/',
              help='get the api URL '
              'to connect to. EX: https://checks.google.com/api/v1/ ')
@click.option('--api-key', '-k', 'api_key', required=True,
              help='get the api KEY '
              'to connect to. ')
def init(api_url, api_key):
    """
    Inits the config for the configured Healthchecks project.
    """
    f = open(os.path.expanduser("~/.sch.conf"), "w+")
    f.write('[hc]\nhealthchecks_api_url = ' + api_url +
            '\nhealthchecks_api_key = ' + api_key + '\n')
    f.close()


if __name__ == "__main__":
    sys.exit(main())
