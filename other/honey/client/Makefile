CFLAGS = -Wall -g -I../
OBJS = client.o

all: client

client: $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	rm -rf client $(OBJS)
