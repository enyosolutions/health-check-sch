"""
module for interfacing a healthchecks.io compatible service
"""
import logging
import json
import os
import re
import socket
from urllib.parse import quote_plus

import arrow
import click
import requests
import tzlocal


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
