## History

#### release notes for v0.1
- initial release
- testing the code on a couple of servers

### release notes for 0.2.0
- changed file structure
- first release on PyPI.

### release notes for 0.2.3
- moved all code back into `sch.py`
- previous released packages where broken...

### release notes for 0.2.4
- setting the user-agent string to 'sch/{version}' when interacting with the
  Healthchecks API
- got rid of outdated development section in the readme

### release notes for 0.3.0
- added command and filtering options for listing Healthchecks status

### release notes for 0.4.0
- changed command line flags for list
- improved table alignment for the list command

### release notes for 0.5.0
- when a command fails, include the command, exit code, stdout and stderr in
  the request body of the /fail ping 
