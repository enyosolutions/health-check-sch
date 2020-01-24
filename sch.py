"""
sch: Smart Cron Helper Shell
"""

import configparser
import sys

from crontabs import CronTabs

from hc import HealthcheckCredentials, Healthchecks

CONFIG = configparser.ConfigParser()
CONFIG.read('sch.conf')

CRED = HealthcheckCredentials(
    api_url=CONFIG.get('hc', 'healthchecks_api_url'),
    api_key=CONFIG.get('hc', 'healthchecks_api_key')
    )


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
        print("Error: Expected two arguments")
        sys.exit(1)

    health_checks = Healthchecks(CRED)

    # first argument should be '-c'
    if sys.argv[1] != '-c':
        sys.exit("Error: the first argument should be '-c'")

    # cron command (including env variable JOB_ID) is the 2nd argument
    command = sys.argv[2]

    # find system cron job that executes this command
    jobs = CronTabs().all.find_command(command)
    for job in jobs:
        check = health_checks.find_check(job)
        if check:
            health_checks.update_check(check, job)
        else:
            print("creating new check")
            check = health_checks.new_check(job)

    print("check:", check)


if __name__ == "__main__":
    run()
