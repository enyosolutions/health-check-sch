import sys
import requests
import click
import arrow
import json
import hashlib
import platform
import re
import tzlocal


class hcCred:
    def __init__(self, url, api_key):
        self.url = url
        self.api_key = api_key

    def __repr__(self):
        return """healthchecks api access credentials
        to {url}""".format(url=self.url)


class hcRegistry:
    def __init__(self, cred, registry):
        self.registry = registry
        self.hc = hc(cred)
        # read file
        try:
            with open(self.registry, 'r') as myfile:
                data = myfile.read()

            # parse file
            self.data = json.loads(data)
        except Exception:
            print("could not load registry")

    def get_hash(self, job):
        """Returns the unique hash for given cron job"""
        md5 = hashlib.md5()
        md5.update(platform.node().encode('utf-8'))
        md5.update(str(job.slices).encode('utf-8'))
        md5.update(job.command.encode('utf-8'))
        return md5.hexdigest()

    def get_jobid(self, job):
        """Returns the value of environment variable JOB_ID if specified in the cron job"""
        regex = r".*JOB_ID=(\w*)"
        match = re.match(regex, job.command)
        if match:
            return match.group(1)

    def get_tags(self, job):
        """Returns the tags specified in the environment variable JOB_TAGS in the cron job"""
        regex = r'.*JOB_TAGS=([\w,]*)'
        m = re.match(regex, job.command)
        if m:
            return m.group(1).replace(',', ' ')
        return ""

    def find_by_hash(self, job):
        """Find a job in the registry by hash"""
        h = self.get_hash(job)
        return next((elem for elem in self.data if elem['hash'] == h), False)

    def find_by_jobid(self, job):
        """Find a job in the registry by job_id"""
        j = self.get_jobid(job)
        return next((elem for elem in self.data if elem['JOB_ID'] == j), False)

    def get_id(self, job):
        """Get the HC id for the given cron job"""
        r = self.find_by_hash(job)
        if r:
            return r['HC_ID']

        r = self.find_by_jobid(job)
        if r:
            # hash has changed, let's update the details
            self.hc.update_check(r, job, self.get_tags(job))
            return r['HC_ID']

        return False

    def register(self, id):
        pass


class hc:
    def __init__(self, cred):
        self.cred = cred
        self.auth_headers = { 'X-Api-Key': self.cred.api_key }

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


    def update_check(self, registration, job, tags):
        url = "{apiurl}checks/{code}".format(
                apiurl=self.cred.url,
                code=registration['HC_ID']
                )
        data = {
                'schedule': job.slices.render(),
                'desc': job.comment,
                'grace': 3600,
                'tz': tzlocal.get_localzone().zone,
                'tags': 'sch host_{} {}'.format(platform.node(), tags)
                }

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

        print(response)


    def print_status(self, status_filter=""):
        """Show status of monitored cron jobs"""
        checks = self.get_checks()
        click.secho("{status:<6} {last_ping:<15} {name:<40}".format(
            status="Status",
            name="Name",
            last_ping="Last ping"
        ))
        click.secho("{status:-<6} {last_ping:-<15} {name:-<40}".format(
            status=   "",
            name=     "",
            last_ping=""
        ))

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
