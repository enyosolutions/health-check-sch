# SmartCronHelper
A cron shell wrapper for registering and updating cron jobs automatically in
[healthchecks](https://healthchecks.io) or your [own hosted copy of Healthchecks](https://github.com/healthchecks/healthchecks).

> warning: this software package should be considered "alpha"


## Installation
Install the `sch` shell and it's dependencies by running pip in the cloned
repository:
``` console
$ cd sch
$ sudo pip install .
```

Create a configuration file:
``` console
sudo cp sch.conf.example /etc/sch.conf
```
And fill in the API URL and the key obtained from the Healthchecks project
settings block labeled "API Access".

### Monitoring cron jobs
Just decorate your existing cron tabs by specifying the alternative `sch`:
```
SHELL=/usr/local/bin/sch
```
This line should be above the cron lines you want to have monitored by Healthchecks.

Only jobs with the environment variable `JOB_ID`, ie:
```
*/5 * * * * root JOB_ID=some_id /path/to/some_command
```
The value of `JOB_ID` should be unique for the host.

The combination of the `JOB_ID` environment variable and the `sch` shell is enough
to have the job checked in Healthchecks.

At each run of the job, `sch` will take care that the schedule, description and 
other metadata is synchronized whenever there's a change in the cron job. Just
makes sure to not change the `JOB_ID` (or it will create a new check).
 
### Other meta data
The following data is used to configure a corresponding Healthchecks check:
- `JOB_ID`: the environment variable is used for the name of the check and a tag named `job_id={value of JOB_ID}`
- the cron lines' comment is used for the description of the check. The comment line just above a cron line or the inline comment is used
- `JOB_TAGS`: use this environment variable in a job to specify tag names separated by a comma to specify additional tags
- `$USER`: the current user running the cron command is used to create a tag named `user=$USER`
- the jobs schedule and the hosts timezone is used to set the checks schedule
- when registering a new check, the execution time of the command is used to set an initial grace time. The grace time will be set to 1.2 times the execution time + 30 seconds. As per the Healthchecks API, the minimal grace time is 1 minute and the maximum grace time is 30 days.

An example of a cron file that touches most of the functionality would look like:
```
SHELL=/usr/local/bin/sch
# if this check fails, the host is probably offline
* * * * * root JOB_ID=true /bin/true
```
Although above cron job is useful, a more realistic could look like:
```
SHELL=/usr/loca/bin/sch
# super important backup, if this one fails: fix with top priority!
10 8-20/2 * mon-fri  backup  JOB_ID=db-backups JOB_TAGS=db,backup,my_project /usr/local/bin/run-db-backups
``

### Job execution
`sch` takes over the role of the shell. Jobs not containing the `JOB_ID` environment variable are directly executed with `os.system`.
For `sch` managed jobs:
- `sch` will start with pinging `/start` endpoint of the check
- os.sytem executes the command
- depending on the exit code, it will ping for success or ping the `/fail` end point on failure

## Development environment
### Setup environment
``` console
$ python -m venv venv
$ . venv/bin/activate
$ pip install --editable .
```

### Testing
Create a file named `sch.conf` and edit the Healthchecks API URL and key:
``` console
cp sch.conf.example sch.conf
```
The configuration file looks like:
``` console
 $ cat sch.conf.example 
[hc]
healthchecks_api_url = https://hc.example.com/api/v1/
healthchecks_api_key = xxmysecretkeyxx
```
Create a test cron job:
``` console
$ sudo cp doc/testcrontab /etc/cron.d/test
$ ./testshell.sh
```

### Syntax check
Style Guide Enforcement:
``` console
$ pip install flake8
$ flake8 *py
```

### References
* python-crontab <https://pypi.org/project/python-crontab/>
* crab <https://github.com/grahambell/crab>
