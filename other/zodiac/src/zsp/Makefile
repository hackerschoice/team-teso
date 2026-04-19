CFLAGS=-Wall -g -ggdb -DDEBUG `libnet-config --defines` -D_REENTRANT
LIBS=-lnet
CC=gcc
OBJS = ../common.o ../io-udp.o ../cipher-blowfish.o ../cipher-sha1.o ../network.o
PREFIX=/usr/local 

all:	zsp zsp-test

clean:
	rm -f *.o zsp zsp-test

zsp:	zsp.c $(OBJS)
	$(CC) $(CFLAGS) -o zsp zsp.c $(OBJS) $(LIBS)
	mv zsp ../../

zsp-test:	zsp-test.c $(OBJS)
		$(CC) $(CFLAGS) -o zsp-test zsp-test.c $(OBJS) $(LIBS)

