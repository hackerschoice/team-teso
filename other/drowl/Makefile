
DFLAGS=-g -Wall -DDEBUG -DLIBNET_LIL_ENDIAN
LIBS=-lnet
CC=gcc
CFLAGS=$(DFLAGS)

all:	drowl

clean:
	rm -f *.o drowl

drowl:	common.o dns-build.o network.o
	$(CC) $(CFLAGS) -o drowl drowl.c common.o dns-build.o network.o $(LIBS)

common.o:	common.c
		$(CC) $(CFLAGS) -c common.c

dns-spoof.o:	dns-spoof.c
		$(CC) $(CFLAGS) -c dns-spoof.c

network.o:	network.c
		$(CC) $(CFLAGS) -c network.c

