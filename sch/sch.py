"""
sch: Smart Cron Helper Shell
"""
import collections
import configparser
import hashlib
import json
import subprocess
import logging
import logging.handlers
import os
import re
import socket
import sys
from urllib.parse import quote_plus

import arrow
import click
import requests
import tzlocal
from crontabs import CronTabs
from ttictoc import TicToc
from . import __version__

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


def execute_shell_command(command):
    """
    runs the specified command in the system shell and
    returns the exit code, stderr and stdout
    """
    exit_code = 0
    out = ''
    err = ''
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True, close_fds=True
            )
        (out, err) = process.communicate()
        exit_code = process.returncode

    except OSError as error:
        logging.error(
            "Error running shell command: %s", error
            )

    return exit_code, out.decode('utf-8'), err.decode('utf-8')


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


def get_hc_api():
    """
    try loading Healthchecks API url and key
    and return an instance of Healthchecks or None if it failed
    """
    try:
        config = configparser.ConfigParser()
        config.read(['sch.conf', '/etc/sch.conf'])

        url = config.get('hc', 'healthchecks_api_url')
        key = config.get('hc', 'healthchecks_api_key')

        cred = HealthchecksCredentials(
            api_url=url,
            api_key=key
        )

        healthchecks = Healthchecks(cred)
    except configparser.Error:
        logging.error(
            'Could not find/read/parse config'
            'file sch.conf or /etc/sch.conf'
            )
        healthchecks = None

    return healthchecks


def shell(command):
    """
    sch:shell is a cron shell that registers, updates and pings cron jobs in
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

    health_checks = get_hc_api()

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
        exit_code = os.system(command)
        sys.exit(exit_code)

    # at this point, we're setup to do some smart stuff ;-)
    # we know the exact cron configration for the job
    # and are able to communicate with healthchecks

    # ping start
    health_checks.ping(check, ping_type='/start')

    # start timer
    timer = TicToc()
    timer.tic()

    # execute command
    logging.debug(
        "Executing shell commmand: %s (job.id=%s)",
        command,
        job.id,
        )

    (exit_code, stdout, stderr) = execute_shell_command(command)

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
        health_checks.ping(check,
                           ping_type='/fail',
                           data="command: {}\n"
                                "exit code: {}\n"
                                "stdout: {}\n"
                                "stderr: {}".format(command,
                                                    exit_code,
                                                    stdout,
                                                    stderr)
                           )


HealthchecksCredentials = collections.namedtuple(
    'HealthchecksCredentials',
    'api_url api_key'
    )


class Healthchecks:
    """
    Interfaces with e healthckecks.io compatible API to register
    cron jobs found on the system.
    """
    def __init__(self, cred):
        self.cred = cred
        self.auth_headers = {
            'X-Api-Key': self.cred.api_key,
            'User-Agent': 'sch/{version}'.format(version=__version__)
            }

    def get_checks(self, query=''):
        """
        Returns a list of checks from the HC API
        reference: https://healthchecks.io/docs/api/#list-checks
        """

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

    def ping(self, check, ping_type='', data=''):
        """
        ping a healthchecks check

        ping_type can be '', '/start' or '/fail'
        """
        try:
            response = requests.post(
                check['ping_url'] + ping_type,
                headers=self.auth_headers,
                data=data
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
                data=json.dumps(data)
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

    def print_status(self, list_local, status_filter):
        """
        Show status of monitored cron jobs
        """
        line_template = "{status:7.7} {last_ping:15.15} {name:40.40}"
        click.secho(line_template.format(
            status="Status",
            name="Name",
            last_ping="Last ping"
        ))
        dashes = '----------------------------------------'
        click.secho(line_template.format(
            status=dashes,
            name=dashes,
            last_ping=dashes
        ))

        query = ''
        if list_local:
            tag_for_host = 'host={hostname}'.format(hostname=socket.getfqdn())
            query = "?&tag={tag}".format(tag=quote_plus(tag_for_host))

        checks = self.get_checks(query)

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
                line_template.format(
                    status=i['status'],
                    name=i['name'],
                    last_ping=last_ping
                ),
                fg=color,
                bold=bold
            )


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
