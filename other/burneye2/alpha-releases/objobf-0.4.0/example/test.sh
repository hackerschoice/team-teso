#!/bin/sh

rm rand.*

for i in `seq -f "%03g" 1 100`; do
	dd if=/dev/urandom of=rand.$i bs=1024 count=10 >/dev/null 2>/dev/null
	../objobf -r rand.$i -e quicksort.o 2>/dev/null >/dev/null
	gcc -o main main.c output.o

	echo -n "$i:"
	echo "0987654321" | ./main | grep -v "calling quicksort"
done

