# sch

SmartCronHelper

``` python
from hc import hc, hcCred, hcRegistry

cred = hcCred('https://hc.example.com/api/v1/', 'mysecretapikey')

registry = hcRegistry(cred, '/var/lib/hcregistry.json')

h = hc(cred)
h.print_status()
```
