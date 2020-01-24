"""
sch: Smart Cron Helper Shell
"""

import configparser
import os
import sys

from crontabs import CronTabs

from hc import HealthcheckCredentials, Healthchecks

CONFIG = configparser.ConfigParser()

try:
    CONFIG.read(['sch.conf', '/etc/sch.conf'])

    URL = CONFIG.get('hc', 'healthchecks_api_url')
    KEY = CONFIG.get('hc', 'healthchecks_api_key')
except configparser.Error:
    sys.exit(
        'ERROR: Could not find/read/parse config'
        'file sch.conf or /etc/sch.conf'
        )


CRED = HealthcheckCredentials(
    api_url=URL,
    api_key=KEY
    )


def execute_shell_command(command):
    """
    runs the specified command in the system shell and
    returns the exit code

    what to do with stdout and stderr?
    """
    exit_code = os.system(command)

    return exit_code


def run():
    """
    sch:run is a cron shell that registers, updates and pings cron jobs in
    healthchecks.io

    a cronfile should have the SHELL variable pointing to the sch executable.
    Each cron line in it should have an environment variable 'JOB_ID' with a
    unique value for that host

    The check description is taken from the inline comment or the comment just
    a line the cron line.

    If you want to set additional tags for your check, you should do that with
    an environment variable JOB_TAGS. Seperate multiple tags with a comma.


    """
    # we should have excactly two arguments
    if len(sys.argv) != 3:
        sys.exit("Error: Expected two arguments")

    # first argument should be '-c'
    if sys.argv[1] != '-c':
        sys.exit("Error: the first argument should be '-c'")

    # cron command (including env variable JOB_ID) is the 2nd argument
    command = sys.argv[2]

    # only handle the command when JOB_ID is in there
    if not Healthchecks.extract_job_id(command):
        execute_shell_command(command)
        sys.exit()

    health_checks = Healthchecks(CRED)

    # find system cron job that executes this command
    check = None
    jobs = CronTabs().all.find_command(command)
    for job in jobs:
        check = health_checks.find_check(job)
        if check:
            health_checks.update_check(check, job)
        else:
            print("creating new check")
            check = health_checks.new_check(job)

    if not check:
        sys.exit("Error: could not find or register check for given command")

    # execute command

    # ping start
    health_checks.ping(check, '/start')

    exit_code = execute_shell_command(command)

    # ping end
    if exit_code == 0:
        # ping success
        health_checks.ping(check)

    else:
        # ping failure
        health_checks.ping(check, '/fail')


if __name__ == "__main__":
    run()
