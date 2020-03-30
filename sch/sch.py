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

from sch import Cron, HealthchecksCredentials, Healthchecks

HANDLER = logging.handlers.SysLogHandler('/dev/log')
FORMATTER = logging.Formatter(
    '{name}/%(module)s.%(funcName)s:'
    '%(levelname)s %(message)s'.format(name=__name__)
    )
HANDLER.setFormatter(FORMATTER)
ROOT = logging.getLogger()
# log level DEBUG
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


def get_job_id(command):
    """
    returns the value of the JOB_ID environment variable in specified
    command string
    returns None if not found
    """
    regex = r".*JOB_ID=([\w,-]*)"
    match = re.match(regex, command)
    if match:
        return match.group(1)

    logging.debug("Could not find JOB_ID in command %s", command)

    return None


def shell(command):
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
    # pylint:disable=too-many-statements
    # pylint:disable=too-many-branches

    # cron command (including env variable JOB_ID) is the 2nd argument
    # command = sys.argv[2]
    job_id = get_job_id(command)

    # find system cron job that executes this command
    try:
        job = Cron(job_id).job()
    except TypeError:
        logging.error("Could not find matching cron job")

    # try loading Healthchecks API url and key
    try:
        config = configparser.ConfigParser()
        config.read(['sch.conf', '/etc/sch.conf'])

        url = config.get('hc', 'healthchecks_api_url')
        key = config.get('hc', 'healthchecks_api_key')

        cred = HealthchecksCredentials(
            api_url=url,
            api_key=key
        )

        health_checks = Healthchecks(cred)
    except configparser.Error:
        logging.error(
            'Could not find/read/parse config'
            'file sch.conf or /etc/sch.conf'
            )

    check = None
    interfere = False
    # pylint:disable=broad-except
    try:
        check = health_checks.find_check(job)
    except Exception:
        # do not update or create checks because of communication problems
        logging.error('Ooops! Could not communicate with the healthchecks API')
        interfere = False
    else:
        if check:
            # existing check found
            logging.debug(
                "found check for cron job (job.id=%s)",
                job.id,
                )
            is_new_check = False
            health_checks.update_check(check, job)
            interfere = True
        else:
            # new check to be created
            logging.debug(
                "no check found for cron job (job.id=%s)",
                job.id,
                )
            is_new_check = True
            check = health_checks.new_check(job)

            if check:
                interfere = True
            else:
                logging.error(
                    "Could not find or register check for given command. "
                    "Using read-only API keys? (job.id=%s)",
                    job.id,
                    )

    # pylint:enable=broad-except

    if not interfere or not job_id or not job:
        # for some reason, we can't do much with Healthchecks
        # at this point. So, we run the job without too much SCH
        # interference
        logging.debug(
            "Running a job without SCH interference, command: %s",
            command
            )
        execute_shell_command(command)
        sys.exit()

    # at this point, we're setup to do some smart stuff ;-)
    # we know the exact cron configration for the job
    # and are able to communicate with healthchecks

    # ping start
    health_checks.ping(check, '/start')

    # start timer
    timer = TicToc()
    timer.tic()

    # execute command
    logging.debug(
        "Executing shell commmand: %s (job.id=%s)",
        command,
        job.id,
        )
    exit_code = execute_shell_command(command)

    # stop timer
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


# if __name__ == "__main__":
#    shell()
