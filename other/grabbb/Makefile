CFLAGS=-Wall
CC=gcc
OBJS=grabbb.o

all:	grabbb

clean:
	rm -f *.o grabbb

arptool:	$(OBJS)
		$(CC) $(CFLAGS) -o grabbb $(OBJS)
		strip grabbb
