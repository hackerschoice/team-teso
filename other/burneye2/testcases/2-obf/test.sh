#!/bin/sh

rm -f test-output rand.*

./reducebind /usr/bin/id id.ref
echo "reference" | tee -a test-output
md5sum id.ref | tee -a test-output

for i in `seq -f "%04g" 1 1000`; do
	dd if=/dev/urandom of=rand.$i bs=1024 count=512 >/dev/null 2>/dev/null
	../../objobf -w 0.4 -r rand.$i -A reducebind.o 2>/dev/null >/dev/null
	gcc -o output output.o 2>/dev/null

	echo -n "$i:"
	rm -f id.static
	./output /usr/bin/id id.static >/dev/null 2>/dev/null
	md5sum id.static | tee -a test-output
done

