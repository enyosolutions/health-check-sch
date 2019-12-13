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
from hc import hc, hcCred, hcRegistry

cred = hcCred('https://hc.example.com/api/v1/', 'mysecretapikey')

registry = hcRegistry(cred, 'doc/hcregistry.json')

h = hc(cred)
h.print_status()

# scan jobs that want to use SCH
jobs = CronTabs().all.find_command('JOB_ID')
for job in jobs:
    print("job:")
    print(job)
    hc_id = registry.get_id(job)
    print(hc_id)
    print("--------------")
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
