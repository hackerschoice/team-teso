CFLAGS=-Wall -g -ggdb -DDEBUG `libnet-config --defines` -D_REENTRANT -pthread
LIBS= -lncurses -lpcap -lnet
CC=gcc
OBJS =	common.o cipher-blowfish.o cipher-sha1.o dns.o dns-build.o \
	dns-spoof-int.o dns-spoof.o dns-tag.o dns-tools.o dnsid.o dnsq.o \
	gui.o io-udp.o network.o sniff.o output.o packet.o 
PREFIX=/usr/local 

all:	zodiac

clean:
	rm -f *.o ../zodiac

zodiac:		zodiac.c $(OBJS)
		$(CC) $(CFLAGS) -o zodiac -static zodiac.c $(OBJS) $(LIBS)
		mv zodiac ../

