#!/bin/bash

command="$2"
echo >> /tmp/test
date >> /tmp/test
echo " command: " "$command" >> /tmp/test

if ! grep -q 'JOB_ID' <<< "$command"
then
	echo "  - just run the command, no stuff with sch" >> /tmp/test
	echo "  - eval $command"                           >> /tmp/test
	exit 0
fi

echo "  - do something with sch" >> /tmp/test

