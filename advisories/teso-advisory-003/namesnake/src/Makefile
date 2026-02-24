CFLAGS=-Wall -ggdb `libnet-config --defines`
LIBS=-lnet
CC=gcc
OBJS=common.o dns-build.o dns.o io-udp.o network.o

all:		namesnake rattlesnake

clean:
		rm -f *.o namesnake rattlesnake

rattlesnake:	rattlesnake.c $(OBJS)
		$(CC) $(CFLAGS) -static -o rattlesnake rattlesnake.c $(OBJS) $(LIBS)

namesnake:	namesnake.c $(OBJS)
		$(CC) $(CFLAGS) -o namesnake namesnake.c $(OBJS) $(LIBS)

