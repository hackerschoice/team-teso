all: fragd.o main.o misc.o
	$(CXX) fragd.o misc.o main.o -o fragd -lpthread -lpcap

main.o: main.cc
	$(CXX) -c main.cc -O2 -Wall

fragd.o: fragd.cc
	$(CXX) -c fragd.cc -O2 -Wall

misc.o: misc.cc
	$(CXX) -c misc.cc -O2 -Wall

fraggle: misc.o fraggle.o
	$(CXX) fraggle.o misc.o -o fraggle

fraggle.o: fraggle.cc
	$(CXX) -c -Wall -O2 fraggle.cc

clean:
	rm -f *.o
