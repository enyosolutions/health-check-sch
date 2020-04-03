# SmartCronHelper
A cron shell wrapper for registering and updating cron jobs automatically in
[healthchecks](https://healthchecks.io) or your [own hosted copy of Healthchecks](https://github.com/healthchecks/healthchecks).

> warning: this software package should be considered "alpha"


## Installation
Install sch system wide with pip
``` console
$ sudo pip3 install sch
```

A `sch` cli should now be availble:
``` console
$ which sch
/usr/local/bin/sch
```

`sch --version` should return something like:
``` console
sch, version 0.2.1
```
## Command line usage
See the `--help` option for usage:
``` console
Usage: sch [OPTIONS] COMMAND [ARGS]...

  sch - A cron shell wrapper for registering and updating cron jobs
  automatically in Healthchecks. The Healthchecks project api_url and
  api_key should be configured in /etc/sch.conf.

Options:
  --version                 Show the version and exit.
  -c, --shell_command TEXT  Command to execute. This how Cron executes 'sch'
                            when it is set as SHELL.
  --help                    Show this message and exit.

Commands:
  list  List checks for the configured Healthchecks project.
```

### `list` command
``` console
Usage: sch list [OPTIONS]

  List checks for the configured Healthchecks project.

Options:
  -l, --localhost / -a, --all     List checks that originate from this host
                                  (default) or list all checks.
  -s, --status [up|down|grace|started|pause|new]
                                  Show only checks that have the specified
                                  status.
  --help                          Show this message and exit.
```

## Configuration
Create a configuration file `/etc/sch.conf` that looks like:
``` ini
[hc]
healthchecks_api_url = https://hc.example.com/api/v1/
healthchecks_api_key = xxmysecretkeyxx
```

And fill in the API URL and the key obtained from the Healthchecks project
settings block labeled "API Access".

## Monitoring cron jobs
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
- the cron lines' **comment** is used for the description of the check. The comment line just above a cron line or the inline comment is used
- `JOB_TAGS`: use this environment variable in a job to specify tag names separated by a comma to specify additional tags
- `$USER`: the current user running the cron command is used to create a tag named `user=$USER`
- the jobs **schedule** and the hosts **timezone** is used to set the checks schedule
- `JOB_GRACE`: the value of this environment variable is used to set the grace time in seconds for the check. See JOB_GRACE for valid interval formats.
- when registering a new check and JOB_GRACE is not set, the **execution time** of the command is used to set an initial grace time. The grace time will be set to 1.2 times the execution time + 30 seconds. As per the Healthchecks API, the minimal grace time is 1 minute and the maximum grace time is 30 days.

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
10 8-20/2 * mon-fri  backup  JOB_ID=db-backups JOB_TAGS=db,backup,my_project JOB_GRACE=5m /usr/local/bin/run-db-backups
```

#### JOB_GRACE interval format
If no suffixes are used, seconds are assumed.
You can make use of the following suffixes to specify an interval:

| Suffix | Interval |
|--------|----------|
| s      | seconds  |
| m      | minutes  |
| h      | hours    |
| D      | days     |
| W      | weeks    |
| M      | months   |
| Y      | years    |

Although days and weeks are accepted, you might want to limit the interval to several hours ;-)

Examples:

| environment variable | grace time |
|----------------------|------------|
| `JOB_GRACE=5m`       | 300s       |
| `JOB_GRACE=120`      | 120s       |
| `JOB_GRACE=1h30m`    | 5400s      |


### Job execution
`sch` takes over the role of the shell. Jobs not containing the `JOB_ID` environment variable are directly executed with `os.system`.
For `sch` managed jobs:
- `sch` will start with pinging `/start` endpoint of the check
- os.sytem executes the command
- depending on the exit code, it will ping for success or ping the `/fail` end point on failure

### References
* python-crontab <https://pypi.org/project/python-crontab/>
* crab <https://github.com/grahambell/crab>

## Notes
### fully qualified domain name
`sch` uses the FQDN to identify the hosts it's running on. You can check the FQDN with:
``` console
$ hostname --fqdn
host.example.com
```

However, on some systems that don't know the domain part, it just returns the
(short) hostname instead:
``` console
$ hostname --fqdn
host
```

If this is the case, you can fix that by editing the `/etc/hosts` file so look
like this:
```
127.0.0.1	localhost
127.0.1.1	host.example.com host
```

Afterwards, `hostname --fqdn` should return the FQDN. Beware that `sch` will
create new checks when the FQDN changes.
