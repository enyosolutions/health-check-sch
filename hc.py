import sys
import requests
import click
import arrow
import json

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
                data=myfile.read()
    
            # parse file
            self.data = json.loads(data)
        except Exception as e:
            print ("could not load registry")

        

    def register(self, id):
        pass


class hc:
    def __init__(self, cred):
        self.cred = cred

    def get_checks(self):
        """Returns a list of checks from the HC API"""
        url = "{}checks/".format(self.cred.url)
        headers = {'X-Api-Key': self.cred.api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        if response:
            return response.json()['checks']

        raise Exception('fetching cron checks failed')

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
