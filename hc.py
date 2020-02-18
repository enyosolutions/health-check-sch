"""
module for interfacing a healthchecks.io compatible service
"""
import collections
import hashlib
import logging
import os
import re
import socket
from urllib.parse import quote_plus

import arrow
import click
import requests
import tzlocal
from crontabs import CronTabs

HealthcheckCredentials = collections.namedtuple(
    'HealthcheckCredentials',
    'api_url api_key'
    )

INTERVAL_DICT = collections.OrderedDict([
    ("Y", 365*86400),  # 1 year
    ("M", 30*86400),   # 1 month
    ("W", 7*86400),    # 1 week
    ("D", 86400),      # 1 day
    ("h", 3600),       # 1 hour
    ("m", 60),         # 1 minute
    ("s", 1)])         # 1 second


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


class Job():
    """
    Wrapper to create a self aware cron job object
    """
    # pylint does not like the number of attributes and
    # public methods, but i do ;-)

    # pylint: disable=too-many-instance-attributes
    # pylint: disable=too-few-public-methods

    def __init__(self, job):
        # wrab the job
        self._job = job
        self.id = self._get_id()  # pylint: disable=invalid-name
        self.command = self._job.command
        self.comment = self._job.comment
        self.tags = self._get_tags()
        self.schedule = self._get_schedule()
        self.grace = self._get_grace()
        # finally, determine hash
        self.hash = self._get_hash()

    def _get_env_var(self, env_var):
        """
        Returns the value of an environment variable
        """
        regex = r".*{env_var}=([\w,-]*)".format(env_var=env_var)
        match = re.match(regex, self._job.command)
        if match:
            return match.group(1)

        return None

    def _get_id(self):
        """
        Returns the value of environment variable JOB_ID if specified
        in the cron job
        """
        return self._get_env_var('JOB_ID')

    def _get_tags(self):
        """
        Returns the tags specified in the environment variable
        JOB_TAGS in the cron job
        """
        tags = self._get_env_var('JOB_TAGS')
        if tags:
            return tags.replace(',', ' ')
        return ""

    def _get_schedule(self):
        """
        extract the schedule in 5 column notation from the given job
        """
        # correct schedule aliases back to fields
        schedule = self._job.slices.render()
        if schedule == '@hourly':
            schedule = '0 * * * *'
        if schedule == '@daily':
            schedule = '0 0 * * *'
        if schedule == '@weekly':
            schedule = '0 0 * * 0'
        if schedule == '@monthly':
            schedule = '0 0 1 * *'
        if schedule == '@yearly':
            schedule = '0 0 1 1 *'

        return schedule

    def _get_hash(self):
        """Returns the unique hash for given cron job"""
        md5 = hashlib.md5()

        # job schedule
        md5.update(self.schedule.encode('utf-8'))
        # the command itself
        md5.update(self.command.encode('utf-8'))
        # the comment
        md5.update(self.comment.encode('utf-8'))
        # host fqdn
        md5.update(socket.getfqdn().encode('utf-8'))
        # job user
        md5.update(os.environ['LOGNAME'].encode('utf-8'))
        # the timezone (not so likely to change)
        md5.update(tzlocal.get_localzone().zone.encode('utf-8'))

        return md5.hexdigest()

    def _get_grace(self):
        """
        Returns the jobs grace time in seconds as specified by the
        commands' environment variable JOB_GRACE
        """
        grace = self._get_env_var('JOB_GRACE')
        if grace:
            grace = self._human_to_seconds(grace)
            return grace

        return None

    @staticmethod
    def _human_to_seconds(string):
        """Convert internal string like 1M, 1Y3M, 3W to seconds.

        :type string: str
        :param string: Interval string like 1M, 1W, 1M3W4h2s...
            (s => seconds, m => minutes, h => hours, D => days,
             W => weeks, M => months, Y => Years).

        :rtype: int
        :return: The conversion in seconds of string.
        """
        interval_exc = "Bad interval format for {0}".format(string)

        interval_regex = re.compile(
            "^(?P<value>[0-9]+)(?P<unit>[{0}])".format(
                "".join(INTERVAL_DICT.keys())))

        if string.isdigit():
            seconds = int(string)
            return seconds

        seconds = 0

        while string:
            match = interval_regex.match(string)
            if match:
                value, unit = int(match.group("value")), match.group("unit")
                if int(value) and unit in INTERVAL_DICT:
                    seconds += value * INTERVAL_DICT[unit]
                    string = string[match.end():]
                else:
                    raise Exception(interval_exc)
            else:
                raise Exception(interval_exc)
        return seconds


class Healthchecks:
    """
    Interfaces with e healthckecks.io compatible API to register
    cron jobs found on the system.
    """
    def __init__(self, cred):
        self.cred = cred
        self.auth_headers = {'X-Api-Key': self.cred.api_key}

    def get_checks(self, query=''):
        """Returns a list of checks from the HC API"""
        url = "{api_url}checks/{query}".format(
            api_url=self.cred.api_url,
            query=query
            )

        try:
            response = requests.get(url, headers=self.auth_headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.error("bad response %s", err)
            return None

        if response:
            return response.json()['checks']

        logging.error('fetching cron checks failed')
        raise Exception('fetching cron checks failed')

    def find_check(self, job):
        """
        Find a check in Healthchecks for the host and given job
        """
        tag_for_job_id = 'job_id={job_id}'.format(job_id=job.id)
        tag_for_host = 'host={hostname}'.format(hostname=socket.getfqdn())

        query = "?&tag={tag1}&tag={tag2}".format(
            tag1=quote_plus(tag_for_job_id),
            tag2=quote_plus(tag_for_host)
            )

        checks = self.get_checks(query)

        # we are only interrested if we found exactly one match
        if checks and len(checks) == 1:
            return checks[0]

        # no result found
        return None

    def ping(self, check, ping_type=''):
        """
        ping a healthchecks check

        ping_type can be '', '/start' or '/fail'
        """
        try:
            response = requests.get(
                check['ping_url'] + ping_type,
                headers=self.auth_headers
                )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.error('could not ping, error: %s', err)

    @staticmethod
    def get_check_hash(check):
        """
        returns the hash stored in a tag of a healthchecks check
        the tags lookes like:

            hash=fdec0d88e53cc57ef666c8ec548c88bb

        returns None if the tag is not found
        """
        regex = r"hash=(\w*)"
        hash_search = re.search(regex, check['tags'])

        if hash_search:
            return hash_search.group(1)

        return None

    def update_check(self, check, job):
        """
        update check metadata for given cron job
        """
        check_hash = self.get_check_hash(check)

        if check_hash:
            if job.hash == check_hash:
                # hash did not change: no need to update checks' details
                logging.debug(
                    "Hash did not change (job.id=%s)",
                    job.id
                    )
                return True

        logging.debug(
            "Hash changed: "
            "about to update the check (job.id=%s)",
            job.id
            )

        # gather all the jobs' metadata
        data = {
            'schedule': job.schedule,
            'desc': job.comment,
            'tz': tzlocal.get_localzone().zone,
            'tags': 'sch host={host} job_id={job_id} user={user} '
                    'hash={hash} {job_tags}'.format(
                        host=socket.getfqdn(),
                        job_id=job.id,
                        user=os.environ['LOGNAME'],
                        hash=job.hash,
                        job_tags=job.tags
                        )
        }

        # grace time
        if job.grace:
            data['grace'] = job.grace

        # post the data
        try:
            response = requests.post(
                url=check['update_url'],
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError:
            logging.error(
                "An error occurred while updating check (job.id=%s)",
                job.id,
                exc_info=True
                )
            return False

        logging.debug(
            "Sucessfully updated check (job.id=%s)",
            job.id
            )
        return True

    def new_check(self, job):
        """
        creates a new check for given job
        """
        logging.debug(
            "Creating a new check (job.id=%s)",
            job.id
            )

        # gather all the jobs' metadata
        data = {
            'name': job.id,
            'schedule': job.schedule,
            'grace': 3600,
            'desc': job.comment,
            'channels': '*',  # all available notification channels
            'tz': tzlocal.get_localzone().zone,
            'tags': 'sch host={host} job_id={job_id} user={user} '
                    'hash={hash} {job_tags}'.format(
                        host=socket.getfqdn(),
                        job_id=job.id,
                        user=os.environ['LOGNAME'],
                        hash=job.hash,
                        job_tags=job.tags
                        )
        }

        # grace time
        if job.grace:
            data['grace'] = self._coerce_grace(job.grace)

        # post the data
        try:
            response = requests.post(
                url='{}/checks/'.format(self.cred.api_url),
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError:
            logging.error(
                "An error occurred while creating a check (job.id=%s)",
                job.id,
                exc_info=True
                )
            return None

        logging.debug(
            "Successfully created a new check (job.id=%s)",
            job.id
            )

        # return check
        return response.json()

    @staticmethod
    def _coerce_grace(grace):
        """
        returns a grace time that respects the hc api
        """
        grace = max(60, grace)
        grace = min(grace, 2592000)

        return grace

    def set_grace(self, check, grace):
        """
        set the grace time for a check
        """
        data = {'grace': self._coerce_grace(grace)}

        # post the data
        try:
            response = requests.post(
                url=check['update_url'],
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError:
            logging.error(
                "An error occurred while updating the grace time",
                exc_info=True
                )
            return False

        logging.debug("Successfully set grace_time to %s seconds", grace)
        return True

    def print_status(self, status_filter=""):
        """Show status of monitored cron jobs"""
        click.secho("{status:<6} {last_ping:<15} {name:<40}".format(
            status="Status",
            name="Name",
            last_ping="Last ping"
        ))
        click.secho("{status:-<6} {last_ping:-<15} {name:-<40}".format(
            status="",
            name="",
            last_ping=""
        ))

        checks = self.get_checks()

        for i in checks:
            if status_filter and i['status'] != status_filter:
                continue

            # determine color based on status
            color = 'white'
            bold = False

            if i['status'] == 'up':
                bold = True

            if i['status'] == 'down':
                color = 'red'

            if i['status'] == 'grace':
                color = 'yellow'

            if i['status'] == 'paused':
                color = 'blue'

            # determine last ping
            last_ping = arrow.get(i['last_ping']).humanize()
            if i['status'] == 'new':
                last_ping = ''

            click.secho(
                "{status:<6} {last_ping:<15} {name:<40}".format(
                    status=i['status'],
                    name=i['name'],
                    last_ping=last_ping
                ),
                fg=color,
                bold=bold
            )
