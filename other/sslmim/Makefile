# (C) 2001 by Sebastian Krahmer.
#
#

# choose one of:
# FREEBSD
# LINUX22
# LINUX24

CXX=c++
CFLAGS=-Wall -O2 -c -DLINUX24 #-ansi -pedantic

.SUFFIXES: .o .cc

.cc.o:
	$(CXX) $(CFLAGS) $<

all: echo filterd mimd cf

cf: session.o certfetch.o
	$(CXX) certfetch.o session.o -o cf -lssl -lcrypto

filterd: socket.o misc.o filter.o filterd.o
	$(CXX) socket.o misc.o filter.o filterd.o -o filterd	

mimd:	session.o forward.o misc.o main.o socket.o dca.o
	$(CXX) session.o forward.o misc.o main.o socket.o  dca.o -o mimd -lssl -lcrypto

clean: 
	rm -rf *.o

echo:
	@echo "Make sure you choose the right target-OS by defining either of";
	@echo "LINUX22 (Linux, kernel 2.2),";
	@echo "LINUX24 (Linux, kernel 2.4) or";
	@echo "FREEBSD";
	@echo "in the Makefile.";
	@echo

