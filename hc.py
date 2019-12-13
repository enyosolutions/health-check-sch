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
        md5 = hashlib.md5()
        md5.update(platform.node().encode('utf-8'))
        md5.update(str(job.slices).encode('utf-8'))
        md5.update(job.command.encode('utf-8'))
        return md5.hexdigest()

    def get_jobid(self, job):
        regex = r"JOB_ID=(\w*)"
        match = re.match(regex, job.command)
        if match:
            return match.group(1)

    def find_by_hash(self, job):
        h = self.get_hash(job)
        return next((elem for elem in self.data if elem['hash'] == h), False)

    def find_by_jobid(self, job):
        j = self.get_jobid(job)
        return next((elem for elem in self.data if elem['JOB_ID'] == j), False)

    def get_id(self, job):
        r = self.find_by_hash(job)
        if r:
            print("lookup match by hash!")
            return r['HC_ID']

        r = self.find_by_jobid(job)
        if r:
            print("lookup match by JOB_ID")
            # hash has changed, let's update the schedule
            self.hc.update_check(r, job)
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

    def update_check(self, registration, job):
        url = "{apiurl}checks/{code}".format(
                apiurl=self.cred.url,
                code=registration['HC_ID']
                )

        data = {
                'schedule': '* * * * *',
                'tz': tzlocal.get_localzone().zone,
                'tags': 'sch host_{}'.format(platform.node())
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
        click.echo("Status Last ping       Check name")
        click.echo("---------------------------------")

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
                "{status:<6} {last_ping:<15} {name}".format(
                    status=i['status'],
                    name=i['name'],
                    last_ping=last_ping
                ),
                fg=color,
                bold=bold
            )
