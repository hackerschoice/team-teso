CFLAGS=-Wall -g
CC=cc
OBJS=common.o network.o

all:	7350wu

clean:
	rm -f *.o 7350wu

7350wu:	7350wu.c $(OBJS)
	$(CC) $(CFLAGS) -o 7350wu 7350wu.c $(OBJS) $(LIBS)

