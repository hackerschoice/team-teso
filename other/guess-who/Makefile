CXX=c++
CFLAGS=-Wall -c -O2 -g
LIBS=-lcrypto -lpthread

all: ssh.o misc_block.o main.o thread.o base64.o
	$(CXX) ssh.o misc_block.o main.o thread.o base64.o $(LIBS) -o b

thread.o: thread.cc
	$(CXX) $(CFLAGS) thread.cc

ssh.o: ssh.cc
	$(CXX) $(CFLAGS) ssh.cc

misc.o: misc.cc
	$(CXX) $(CFLAGS) -DDONT_BLOCK misc.cc

misc_block.o: misc.cc
	$(CXX) $(CFLAGS) misc.cc -o misc_block.o


main.o: main.cc
	$(CXX) $(CFLAGS) main.cc

base64.o: base64.cc
	$(CXX) $(CFLAGS) base64.cc

keygen.o: keygen.cc
	$(CXX) $(CFLAGS) keygen.cc

keygen: keygen.o base64.o misc.o
	$(CXX) keygen.o base64.o misc.o -lcrypto -o keygen

pubscan: pubscan.o base64.o misc.o ssh.o misc.o
	$(CXX) ssh.o pubscan.o base64.o misc.o -lcrypto $(LIBS) -o pubscan

clean:
	rm -f *.o
		
