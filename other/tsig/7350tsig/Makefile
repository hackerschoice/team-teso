CC = gcc
CFLAGS = -Wall -g -ggdb
OBJS = tcp.o dnslib.o
all: tsig

tsig: $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	rm -rf $(OBJS) tsig
