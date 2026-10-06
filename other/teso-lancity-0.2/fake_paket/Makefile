CC=gcc

all: fake_arp fake_icmp

%.o: %.c
	$(CC) $(CFLAGS) $< -c

fake_icmp: net.o fake_icmp.o
	$(CC) $(LDFLAGS) $^ -o $@

fake_arp: net.o fake_arp.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o fake_arp fake_icmp
