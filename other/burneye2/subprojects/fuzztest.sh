#!/bin/sh

chmod 755 fuzzout
(sleep 1 ; killall fuzzout) 2>/dev/null &
killpid=$!
./fuzzout 2>/dev/null | grep "hello" >/dev/null 2>/dev/null || exit
kill -9 $killpid 2>/dev/null
./fuzzout >/dev/null 2>/dev/null
if [ $? != 123 ]; then
	exit
fi

fnum=$(expr $(ls fuzzsurv.* | tail -1 | cut -d '.' -f2) + 1)
fnumformat=$(echo | awk '{ printf ("%04u", '$fnum') }')
echo survived: fuzzsurv.$fnumformat

cp fuzzout fuzzsurv.$fnumformat

