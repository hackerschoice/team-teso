
DFLAGS=-Wall
CC=cc
CFLAGS=$(DFLAGS) -O2
OBJS=network.o

all:	reverb

clean:
	rm -f *.o reverb

reverb:	$(OBJS)
	$(CC) $(CFLAGS) -o reverb reverb.c $(OBJS)
	strip reverb

network.o:	network.c
		$(CC) $(CFLAGS) -c network.c

