#!/bin/sh

rm -f test-output rand.*

for i in `seq -f "%03g" 1 999`; do
	dd if=/dev/urandom of=rand.$i bs=1024 count=10 >/dev/null 2>/dev/null
	../objobf -r rand.$i -A -w 0.33 quicksort.o 2>/dev/null >/dev/null
	gcc -o main main.c output.o 2>/dev/null

	(echo -n "$i:"
		echo "0987654321" | ./main | grep -v "calling quicksort") | \
	tee -a test-output
done

cat test-output | grep ":012345678$" | wc -l

