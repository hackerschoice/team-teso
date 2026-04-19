
DFLAGS=-ggdb
CC=gcc
CFLAGS=$(DFLAGS) -Wall
OBJS=fmtxp.o

all:	fmtbrute vuln

clean:
	rm -f *.o fmtbrute vuln

fmtbrute:	$(OBJS)
	$(CC) $(CFLAGS) -o fmtbrute fmtbrute.c $(OBJS)

vuln:	vuln.c
	$(CC) $(CFLAGS) $(DFLAGS) -o vuln vuln.c

