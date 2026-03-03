CC=gcc
CFLAGS=-Wall -O2
LIBS=-lm
LIBNET_DEFS=`libnet-config --defines`
LIBNET_LIBS=`libnet-config --libs`

all:

	$(CC) $(CFLAGS) $(LIBNET_DEFS) arpmitm.c -o arpmitm $(LIBS) $(LIBNET_LIBS)
	strip arpmitm

clean:
	rm -vf arpmitm
