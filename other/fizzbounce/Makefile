
CFILES=client.c main.c network.c relay.c
LIBS=-lpthread
CC=gcc
CFLAGS=-g -DDEBUG
PREFIX=/usr/local

all:	fizzbounce

clean:	rm -f *.o fizzbounce

fizzbounce:
	${CC} -o fizzbounce ${CFILES} ${CFLAGS} ${LIBS}


