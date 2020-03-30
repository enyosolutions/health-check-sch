"""
module for interfacing a healthchecks.io compatible service
"""
import collections
import hashlib
import os
import re
import socket

import tzlocal

INTERVAL_DICT = collections.OrderedDict([
    ("Y", 365*86400),  # 1 year
    ("M", 30*86400),   # 1 month
    ("W", 7*86400),    # 1 week
    ("D", 86400),      # 1 day
    ("h", 3600),       # 1 hour
    ("m", 60),         # 1 minute
    ("s", 1)])         # 1 second


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
