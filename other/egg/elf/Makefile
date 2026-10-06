CC = g++
CPPFLAGS = -O6 -Wall -I../shared
LDFLAGS = -L../shared
LIBS = -lelf++ -lstdc++
OBJS = eread.o
OBJS_SCRAMBLE = scramble.o

all: eread test scramble

eread: $(OBJS)
	$(CC) -o eread $(OBJS) $(LDFLAGS) $(LIBS) 

scramble: $(OBJS_SCRAMBLE)
	$(CC) -o scramble $(OBJS_SCRAMBLE) $(LDFLAGS) $(LIBS)

test: test.c unscramble.c
	gcc -c unscramble.c -o unscramble.o -Wall -O3
	gcc -c test.c -o test.o -Wall -O3 
	gcc -o test test.o unscramble.o

clean:
	rm -rf *.o eread test scramble
