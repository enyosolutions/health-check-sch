"""
module for interfacing a healthchecks.io compatible service
"""
import collections
import hashlib
import os
import re
import socket
import sys

import arrow
import click
import requests
import tzlocal

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


class Healthchecks:
    """
    Interfaces with e healthckecks.io compatible API to register
    cron jobs found on the system.
    """
    def __init__(self, cred):
        self.cred = cred
        self.auth_headers = {'X-Api-Key': self.cred.api_key}
        self.checks = self.get_checks()

    def get_checks(self):
        """Returns a list of checks from the HC API"""
        url = "{}checks/".format(self.cred.api_url)

        try:
            response = requests.get(url, headers=self.auth_headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        if response:
            return response.json()['checks']

        raise Exception('fetching cron checks failed')

    def find_check(self, job):
        """
        Find a check in Healthchecks for the host and given job
        """
        job_id = self.get_job_id(job)

        tag_for_job_id = 'job_id={job_id}'.format(job_id=job_id)
        tag_for_host = 'host={hostname}'.format(hostname=socket.getfqdn())

        # see if there's a check with tags matching both this host
        # and the job_id
        for check in self.checks:
            found_job_id = False
            found_host = False
            for tag in check['tags'].split(' '):
                if tag == tag_for_job_id:
                    found_job_id = True
                elif tag == tag_for_host:
                    found_host = True
            if found_job_id and found_host:
                return check

        return None

    def ping(self, check, ping_type=''):
        """
        ping a healthchecks check

        ping_type can be empty, '/start' or '/fail'
        """
        try:
            response = requests.get(
                check['ping_url'] + ping_type,
                headers=self.auth_headers
                )
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)

    @staticmethod
    def human_to_seconds(string):
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

    @staticmethod
    def get_job_tags(job):
        """
        Returns the tags specified in the environment variable
        JOB_TAGS in the cron job
        """
        tags = Healthchecks.extract_env_var(job.command, 'JOB_TAGS')
        if tags:
            return tags.replace(',', ' ')
        return ""

    @staticmethod
    def get_job_id(job):
        """
        Returns the value of environment variable JOB_ID if specified
        in the cron job
        """
        return Healthchecks.extract_env_var(job.command, 'JOB_ID')

    @staticmethod
    def get_job_grace(job):
        """
        Returns the value of environment variable JOB_ID if specified
        in the cron job
        """
        grace_time = Healthchecks.extract_env_var(job.command, 'JOB_GRACE')
        if grace_time:
            grace_time = Healthchecks.human_to_seconds(grace_time)
            grace_time = Healthchecks.coerce_grace_time(grace_time)
            return grace_time

        return None

    @staticmethod
    def extract_env_var(command, env_var):
        """
        Returns the value of environment variable JOB_ID if specified
        in the command
        """
        regex = r".*{env_var}=([\w,]*)".format(env_var=env_var)
        match = re.match(regex, command)
        if match:
            return match.group(1)

        return None

    @staticmethod
    def generate_job_hash(job):
        """Returns the unique hash for given cron job"""
        md5 = hashlib.md5()
        # host fqdn
        md5.update(socket.getfqdn().encode('utf-8'))
        # job schedule
        md5.update(Healthchecks.get_job_schedule(job).encode('utf-8'))
        # the timezone (not so likely to change)
        md5.update(tzlocal.get_localzone().zone.encode('utf-8'))
        # job user
        md5.update(os.environ['LOGNAME'].encode('utf-8'))
        # the command itself
        md5.update(job.command.encode('utf-8'))
        # the comment
        md5.update(job.comment.encode('utf-8'))

        return md5.hexdigest()

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
        job_hash = self.generate_job_hash(job)
        check_hash = self.get_check_hash(check)

        if check_hash:
            if job_hash == check_hash:
                # hash did not change: no need to update checks' details
                return True

        print("updating check")
        # gather all the jobs' metadata

        data = {
            'schedule': Healthchecks.get_job_schedule(job),
            'desc': job.comment,
            'tz': tzlocal.get_localzone().zone,
            'tags': 'sch host={host} job_id={job_id} user={user} '
                    'hash={hash} {job_tags}'.format(
                        host=socket.getfqdn(),
                        job_id=self.get_job_id(job),
                        user=os.environ['LOGNAME'],
                        hash=job_hash,
                        job_tags=self.get_job_tags(job)
                        )
        }

        # grace time
        grace = Healthchecks.get_job_grace(job)
        if grace:
            data['grace'] = grace

        # post the data
        try:
            response = requests.post(
                url=check['update_url'],
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("ERROR")
            print(err)
            return False

        return True

    @staticmethod
    def get_job_schedule(job):
        """
        extract the schedule in 5 column notation from the given job
        """

        # correct schedule aliases back to fields
        schedule = job.slices.render()
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

    def new_check(self, job):
        """
        creates a new check for given job
        """
        job_hash = self.generate_job_hash(job)

        # gather all the jobs' metadata
        data = {
            'name': self.get_job_id(job),
            'schedule': Healthchecks.get_job_schedule(job),
            'grace': 3600,
            'desc': job.comment,
            'channels': '*',  # all available notification channels
            'tz': tzlocal.get_localzone().zone,
            'tags': 'sch host={host} job_id={job_id} user={user} '
                    'hash={hash} {job_tags}'.format(
                        host=socket.getfqdn(),
                        job_id=self.get_job_id(job),
                        user=os.environ['LOGNAME'],
                        hash=job_hash,
                        job_tags=self.get_job_tags(job)
                        )
        }

        # grace time
        grace = Healthchecks.get_job_grace(job)
        if grace:
            data['grace'] = grace

        print("data for new check", data)

        # post the data
        try:
            response = requests.post(
                url='{}/checks/'.format(self.cred.api_url),
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("ERROR")
            print(err)
            return None

        # return check
        return response.json()

    @staticmethod
    def coerce_grace_time(grace_time):
        """
        returns the adjusted grace_time so it is in spec with the grace time
        expected by the Healthchecks API
        """
        # make sure the grace time respects the hc api
        grace_time = max(60, grace_time)
        grace_time = min(grace_time, 2592000)

        return grace_time

    def set_grace_time(self, check, grace_time):
        """
        set the grace time for a check
        """
        data = {'grace': Healthchecks.coerce_grace_time(grace_time)}

        # post the data
        try:
            response = requests.post(
                url=check['update_url'],
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("ERROR")
            print(err)
            return False

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

        for i in self.checks:
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
