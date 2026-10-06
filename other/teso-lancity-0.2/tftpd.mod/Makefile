CC=gcc

all: tftpd

%.o: %.c
	$(CC) $(CFLAGS) $< -c

%.o: %.cc
	$(CC) $(CFLAGS) $< -c

OBJS = tftpd.o tftpsubs.o

tftpd: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f *.o tftpd
