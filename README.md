# sch

SmartCronHelper

## Install
``` console
$ python -m venv venv
$ . venv/bin/activate
$ python install .
```

## Test
For now, create a file `test.py`
``` python
from hc import hc, hcCred, hcRegistry

cred = hcCred('https://hc.example.com/api/v1/', 'mysecretapikey')

registry = hcRegistry(cred, '/var/lib/hcregistry.json')

h = hc(cred)
h.print_status()
```

And run it within the virtual environment

## Syntax check
In the virtual environment:
``` console
$ pip install flake8
$ flake8 *py
```

