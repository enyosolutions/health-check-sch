"""
sch: Smart Cron Helper Shell
"""

import configparser
import logging
import logging.handlers
import os
import re
import sys

from ttictoc import TicToc

from hc import Cron, HealthcheckCredentials, Healthchecks

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

HANDLER = logging.handlers.SysLogHandler('/dev/log')
FORMATTER = logging.Formatter(
    '{name}/%(module)s.%(funcName)s: %(message)s'.format(name=__name__)
    )
HANDLER.setFormatter(FORMATTER)
ROOT = logging.getLogger()
ROOT.setLevel(logging.DEBUG)
ROOT.addHandler(HANDLER)

logging.info("started with arguments %s", sys.argv)


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
        # cron runs sch with two arguments
        sys.exit("Error: Expected two arguments")

    # first argument should be '-c'
    if sys.argv[1] != '-c':
        # cron runs the shell with the -c flag
        sys.exit("Error: the first argument should be '-c'")

    # cron command (including env variable JOB_ID) is the 2nd argument
    command = sys.argv[2]

    # determine JOB_ID
    regex = r".*JOB_ID=([\w,-]*)"
    match = re.match(regex, command)
    if not match:
        logging.debug(
            "running a job without a JOB_ID, so no "
            "associated check, command: %s",
            command
            )
        execute_shell_command(command)
        sys.exit()

    # find system cron job that executes this command
    job_id = match.group(1)
    jobs = Cron(job_id).jobs()

    if len(jobs) != 1:
        # oops
        sys.exit()

    job = jobs[0]

    check = None
    is_new_check = False

    health_checks = Healthchecks(CRED)
    check = health_checks.find_check(job)
    if check:
        logging.debug(
            "found check for cron job (job.id=%s)",
            job.id,
            )
        health_checks.update_check(check, job)
    else:
        logging.debug(
            "found new cron job (job.id=%s)",
            job.id,
            )
        is_new_check = True
        check = health_checks.new_check(job)

    if not check:
        logging.error(
            "could not find or register check for given command (job.id=%s)",
            job.id,
            )

    # ping start
    health_checks.ping(check, '/start')

    timer = TicToc()
    timer.tic()

    # execute command
    logging.debug(
        "About to run command: %s (job.id=%s)",
        command,
        job.id,
        )
    exit_code = execute_shell_command(command)

    timer.toc()
    logging.debug(
        "Command completed in %s seconds (job.id=%s)",
        timer.elapsed,
        job.id,
        )

    # ping end
    if exit_code == 0:
        # ping success
        health_checks.ping(check)

        # set grace time from measurement if the check is
        # - new
        # - there's no JOB_GRACE set in the job command
        if is_new_check and not job.grace:
            health_checks.set_grace(check, round(1.2 * timer.elapsed + 30))
    else:
        logging.error(
            "Command returned with exit code %s (job.id=%s)",
            exit_code,
            job.id,
            )
        # ping failure
        health_checks.ping(check, '/fail')


if __name__ == "__main__":
    run()
