CC = g++
CPPFLAGS = -O2 -Wall -I../shared
LDFLAGS = -L../shared
LIBS = -lelf++ -lstdc++
OBJS = infect.o

all: infect

infect: $(OBJS)
	$(CC) -o infect $(OBJS) $(LDFLAGS) $(LIBS) 

clean:
	rm -rf *.o infect 
