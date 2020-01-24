#!/bin/bash

box() {
	if hash boxes 2>/dev/null; then
		boxes -d unicornthink
	else
		echo ==========
		cat
	fi
}

# crude way to list cron commands in /etc/cron.d/test
grep -v ^# /etc/cron.d/test | grep . | sed 's/^.* root //' | sed 's/\ \#.*//' |
	while read line
	do
		
		echo "testing: sch -c $line" | box
		sch -c "$line"
	done
