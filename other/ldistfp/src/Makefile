
#DFLAGS=-O2
DFLAGS=-g -ggdb
CC=cc
CFLAGS=$(DFLAGS) -Wall
OBJS=common.o network.o

all:	ldistfp

clean:
	rm -f *.o ldistfp

ldistfp:	$(OBJS)
		$(CC) $(CFLAGS) -o ldistfp ldistfp.c $(OBJS)
#		strip ldistfp
		mv ldistfp ../bin
