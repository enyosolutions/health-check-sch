# sch

SmartCronHelper

## Install
``` console
$ python -m venv venv
$ . venv/bin/activate
$ pip install .
```

## Test
For now, create a file `test.py`
``` python
"""
Testing hc.py
"""

from crontabs import CronTabs

from hc import HealthcheckCredentials, Healthchecks

cred = HealthcheckCredentials(
    api_url='https://hc.example.com/api/v1/',
    api_key='mysecretapikey'
    )

CRED = HealthcheckCredentials(
    api_url='https://cronmon.science.ru.nl/api/v1/',
    api_key='AbuQXRDCqBk_Q9SiPRfmJA2KtvbNWKx4'
    )

H = Healthchecks(CRED)
H.print_status()

JOBS = CronTabs().all.find_command('JOB_ID')
for job in JOBS:
    check = H.find_check(job)
    if check:
        H.update_check(check, job)
    else:
        H.new_check(job)
```

And run it within the virtual environment

## Syntax check
In the virtual environment:
``` console
$ pip install flake8
$ flake8 *py
```

## Documentation
* python-crontab <https://pypi.org/project/python-crontab/>
