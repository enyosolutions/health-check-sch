#!/bin/bash


command="$2"

date >> /tmp/test
echo "command: " "$command" >> /tmp/test

if grep -q 'JOB_ID' <<< "$command"
then
	echo "do something with sch" >> /tmp/test
else
	echo "just run the command, no stuff with sch" >> /tmp/test
fi

eval "$command"
