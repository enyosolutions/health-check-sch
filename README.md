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
from crontabs import CronTabs
from hc import HealthcheckCredentials, Healthchecks

cred = HealthcheckCredentials(
           api_url='https://hc.example.com/api/v1/',
           api_key='mysecretapikey'
        )

h = Healthchecks(cred)
h.PrintStatus()

jobs = CronTabs().all.find_command('JOB_ID')
for job in jobs:
    check = h.find_check(job)
    if check:
        h.update_check(check, job)
    else:
        h.new_check(job)
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
