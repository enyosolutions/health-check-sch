"""
module for interfacing a healthchecks.io compatible service
"""
import sys
import click
import arrow
import hashlib
import platform
import re
import requests
import tzlocal


class hcCred:
    """
    Object to store the healthchecks api url and key
    """
    def __init__(self, url, api_key):
        self.url = url
        self.api_key = api_key

    def __repr__(self):
        return """healthchecks api access credentials
        to {url}""".format(url=self.url)


class Healthchecks:
    def __init__(self, cred):
        self.cred = cred
        self.auth_headers = {'X-Api-Key': self.cred.api_key}
        self.checks = self.get_checks()

    def get_checks(self):
        """Returns a list of checks from the HC API"""
        url = "{}checks/".format(self.cred.url)

        try:
            response = requests.get(url, headers=self.auth_headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        if response:
            return response.json()['checks']

        raise Exception('fetching cron checks failed')

    def FindCheck(self, job):
        """
        Find a check in Healthchecks for the host and given job
        """
        job_id = self.GetJobId(job)

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

    def GetJobTags(self, job):
        """
        Returns the tags specified in the environment variable
        JOB_TAGS in the cron job
        """
        regex = r'.*JOB_TAGS=([\w,]*)'
        m = re.match(regex, job.command)
        if m:
            return m.group(1).replace(',', ' ')
        return ""

    def GetJobId(self, job):
        """
        Returns the value of environment variable JOB_ID if specified
        in the cron job
        """
        regex = r".*JOB_ID=(\w*)"
        match = re.match(regex, job.command)
        if match:
            return match.group(1)

        return None

    def GenerateJobHash(self, job):
        """Returns the unique hash for given cron job"""
        md5 = hashlib.md5()
        md5.update(platform.node().encode('utf-8'))
        md5.update(str(job.slices).encode('utf-8'))
        md5.update(job.command.encode('utf-8'))
        return md5.hexdigest()

    def GetCheckHash(self, check):
        regex = r"hash=(\w*)"
        hash_search = re.search(regex, check['tags'])

        if hash_search:
            return hash_search.group(1)

        return None

    def UpdateCheck(self, check, job):
        job_hash = self.GenerateJobHash(job)
        check_hash = self.GetCheckHash(check)

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
                job_id=self.GetJobId(job),
                hash=job_hash,
                tags=self.GetJobTags(job)
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

    def NewCheck(self, job):
        job_hash = self.GenerateJobHash(job)

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
                job_id=self.GetJobId(job),
                hash=job_hash,
                tags=self.GetJobTags(job)
                )
        }

        # post the data
        try:
            response = requests.post(
                url='{}/checks/'.format(self.cred.url),
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

    def PrintStatus(self, status_filter=""):
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
