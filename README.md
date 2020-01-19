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
from hc import hcCred, Healthchecks

cred = hcCred('https://hc.example.com/api/v1/', 'mysecretapikey')
h = Healthchecks(cred)
h.PrintStatus()

# scan jobs that want to use SCH
jobs = CronTabs().all.find_command('JOB_ID')
for job in jobs:
    check = h.FindCheck(job)
    if check:
        h.UpdateCheck(check, job)
    else:
        h.NewCheck(job)
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
