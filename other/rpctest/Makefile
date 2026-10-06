CC = gcc
CFLAGS = -Wall -O2
LIBS = 

TARGET = rpctest

OBJS = rpctest.o rpc.o stuff.o pmap.o build.o

DEPS = rpc.h

all: $(TARGET)

$(TARGET): $(OBJS) $(DEPS)
	@echo Compiling rpctest
	rm -rf $@
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -rf core *.o *~ $(TARGET)

