"""
module for interfacing a healthchecks.io compatible service
"""
import collections
import hashlib
import platform
import re
import sys

import arrow
import click
import requests
import tzlocal

HealthcheckCredentials = collections.namedtuple('HealthcheckCredentials', 'api_url api_key')

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

        tag_for_job = 'job_id={job_id}'.format(job_id=job_id)
        tag_for_host = 'host={hostname}'.format(hostname=platform.node())

        # see if there's a check with tags matching both this host
        # and the job_id
        for check in self.checks:
            found_job = False
            found_host = False
            for tag in check['tags'].split(' '):
                if tag == tag_for_job:
                    found_job = True
                elif tag == tag_for_host:
                    found_host = True
            if found_job and found_host:
                return check

        return None

    @staticmethod
    def get_job_tags(job):
        """
        Returns the tags specified in the environment variable
        JOB_TAGS in the cron job
        """
        regex = r'.*JOB_TAGS=([\w,]*)'
        match = re.match(regex, job.command)
        if match:
            return match.group(1).replace(',', ' ')
        return ""

    @staticmethod
    def get_job_id(job):
        """
        Returns the value of environment variable JOB_ID if specified
        in the cron job
        """
        regex = r".*JOB_ID=(\w*)"
        match = re.match(regex, job.command)
        if match:
            return match.group(1)

        return None

    @staticmethod
    def generate_job_hash(job):
        """Returns the unique hash for given cron job"""
        md5 = hashlib.md5()
        md5.update(platform.node().encode('utf-8'))
        md5.update(str(job.slices).encode('utf-8'))
        md5.update(job.command.encode('utf-8'))
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

        # let's really update the check
        print("about to update check:", check)

        url = check['update_url']

        # gather all the jobs' metadata
        data = {
            'schedule': job.slices.render(),
            'desc': job.comment,
            'grace': 3600,
            'tz': tzlocal.get_localzone().zone,
            'tags': 'sch host={host} job_id={job_id} '
                    'hash={hash} {tags}'.format(
                        host=platform.node(),
                        job_id=self.get_job_id(job),
                        hash=job_hash,
                        tags=self.get_job_tags(job)
                        )
        }

        # post the data
        try:
            response = requests.post(
                url=url,
                headers=self.auth_headers,
                json=data
                )

            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("ERROR")
            print(err)
            return False

        return True

    def new_check(self, job):
        """
        creates a new check for given job
        """
        job_hash = self.generate_job_hash(job)

        # gather all the jobs' metadata
        data = {
            'name': 'new check',
            'schedule': job.slices.render(),
            'desc': job.comment,
            'grace': 3600,
            'channels': '*',  # all available notification channels
            'tz': tzlocal.get_localzone().zone,
            'tags': 'sch host={host} job_id={job_id} '
                    'hash={hash} {tags}'.format(
                        host=platform.node(),
                        job_id=self.get_job_id(job),
                        hash=job_hash,
                        tags=self.get_job_tags(job)
                        )
        }

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
            return False

        print('check created')
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
