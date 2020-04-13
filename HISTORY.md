## History

#### release notes for 0.1
- initial release
- testing the code on a couple of servers

### release notes for 0.2.x
- changed file structure
- first release on PyPI.
- moved all code back into `sch.py`
- previous released packages where broken...
- setting the user-agent string to 'sch/{version}' when interacting with the
  Healthchecks API
- got rid of outdated development section in the readme

### release notes for 0.3.0
- added command and filtering options for listing Healthchecks status

### release notes for 0.4.0
- changed command line flags for list
- improved table alignment for the list command

### release notes for 0.5.x
- when a command fails, include the command, exit code, stdout and stderr in
  the request body of the /fail ping 
- got rid of ttictoc as it broke on ubuntu 16 for some reason, using time instead

### release notes for 0.6.x
- listing of check status sorted by `last_ping`
- added configuration option sch:loglevel

### release notes for 0.7.x
- added `JOB_RNDWAIT` configuration option to introduce a random wait

