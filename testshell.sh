#!/bin/bash

box() {
	if hash boxes 2>/dev/null; then
		boxes -d unicornthink
	else
		echo ==========
		cat
	fi
}

testcron=$(dirname $0)/doc/testcrontab
cronfile=/etc/cron.d/testcrontab

if [ ! -f $cronfile ]
then
	echo could not find $cronfile
	exit 1
fi

if [ "$(diff $testcron $cronfile)" != "" ]
then
	echo $cronfile differs from $testcron
	echo to overwrite $cronfile, use:
	echo
	echo sudo cp $testcron $cronfile
	echo
fi

# crude way to list cron commands in /etc/cron.d/test
grep -v ^# $cronfile |
	grep -v ^SHELL |
	grep -v ^MAILTO |
	# get rid of empty lines
	grep . |
	# strip the schedule and user part
	sed 's/^.* root //' |
	# strip optional trailing comment
	sed 's/\ \#.*//' |
	while read line
	do
		echo "testing: sch -c \"${line}\"" | box
		sch -c "$line"
	done
