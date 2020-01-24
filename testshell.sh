#!/bin/bash

# crude way to list cron commands in /etc/cron.d/test
grep -v ^# /etc/cron.d/test | grep . | sed 's/^.* root //' | sed 's/\ \#.*//' |
	while read line
	do
		
		echo "testing: sch -c $line" | boxes -d unicornthink
		sch -c "$line"
	done
