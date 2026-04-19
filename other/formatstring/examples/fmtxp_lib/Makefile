
DFLAGS=-ggdb
CC=gcc
CFLAGS=$(DFLAGS) -Wall
OBJS=fmtxp.o

all:	vuln xp

clean:
	rm -f *.o xp vuln

xp:	$(OBJS)
	$(CC) $(CFLAGS) -o xp xp.c $(OBJS)

vuln:	vuln.c
	$(CC) $(CFLAGS) $(DFLAGS) -o vuln vuln.c

