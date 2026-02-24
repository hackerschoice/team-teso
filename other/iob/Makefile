
CFLAGS	+= -Wall -O2

all:	iob

iob:	iob.c pty.o
	$(CC) -o iob pty.o iob.c $(CFLAGS)

clean:
	rm -f iob
	rm -f *.o

