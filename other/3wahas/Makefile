
DFLAGS=-g -Wall -DDEBUG -DLIBNET_LIL_ENDIAN
LIBS=-lpcap -lnet
CC=gcc
CFLAGS=$(DFLAGS)
PREFIX=/usr/local

all:	3wahas

clean:
		rm -f *.o 3wahas

3wahas:		common.o network.o sniff.o packet.o 3wahas.c
		$(CC) $(CFLAGS) -o 3wahas 3wahas.c common.o sniff.o network.o packet.o $(LIBS)

common.o:	common.c
		$(CC) $(CFLAGS) -c common.c

network.o:	network.c
		$(CC) $(CFLAGS) -c network.c

packet.o:	packet.c
		$(CC) $(CFLAGS) -c packet.c

sniff.o:	sniff.c
		$(CC) $(CFLAGS) -c sniff.c

