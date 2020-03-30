"""
Wrapper around CronTabs
"""
import logging

from crontabs import CronTabs
from sch import Job


class Cron():
    """
    Cron searches for cron jobs with the environment variable
    "JOB_ID={job_id}" for given job_id
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, job_id):
        self._jobs = []
        self._job_id = job_id

        command_filter = "JOB_ID={} ".format(job_id)
        crontabs = CronTabs().all.find_command(command_filter)
        for crontab in crontabs:
            if crontab.enabled:
                self._jobs.append(Job(crontab))

    def job(self):
        """
        returns the matching cron job
        or None if there are no or multiple matches or
        if given job_id was None to start with
        """

        if not self._job_id:
            return None

        if len(self._jobs) == 1:
            return self._jobs[0]

        logging.error(
            'found %s matching cron jobs for given job id'
            '. 1 expected (job.id=%s)',
            len(self._jobs),
            self._job_id
            )
        return None
