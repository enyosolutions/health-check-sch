"""
sch: Smart Cron Helper Shell
"""

import configparser
import sys

from crontabs import CronTabs

from hc import HealthcheckCredentials, Healthchecks

config = configparser.ConfigParser()
config.read('sch.conf')

CRED = HealthcheckCredentials(
    api_url=config.get('hc', 'healthchecks_api_url'),
    api_key=config.get('hc', 'healthchecks_api_key')
    )

def run():
    # we should have excactly two arguments
    if len(sys.argv) != 3 :
        print("Error: Expected two arguments")
        sys.exit (1)


    H = Healthchecks(CRED)
    
    # cron command (including env variable JOB_ID) is the 2nd argument
    command = sys.argv[2]

    # find system cron job that executes this command
    JOBS = CronTabs().all.find_command(command)
    for job in JOBS:
        check = H.find_check(job)
        if check:
            H.update_check(check, job)
        else:
            print("creating new check")
            check = H.new_check(job)

    print("check:", check)

if __name__== "__main__":
    run()
