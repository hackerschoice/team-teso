# RATCS (rage against the configure scripts)
# Tested on linux glibc, freebsd 3.2, 3.3 and openbsd 2.5

CC = gcc
_CFLAGS = -O3 -Wall `libnet-config --defines` -D_REENTRANT
LDFLAGS = 
_LIBS =  -lpcap -lnet

TARGET = portscan

SRCS = main.c portscan.c parse.c stuff.c pingscan.c \
	aeroscan.c

OBJS = main.o portscan.o parse.o stuff.o pingscan.o \
	aeroscan.o

DEPS = portscan.h

all:
	@echo do make linux, bsd or freebsd

portscan: $(OBJS) $(DEPS)
	@echo Compiling portscan
	rm -rf portscan
	$(CC) $(LDFLAGS) -o portscan $(OBJS) $(LIBS)

linux:
	@make portscan "LIBS+=-lpthread $(_LIBS)" "CFLAGS+=$(_CFLAGS)"

freebsd:
	@make portscan LIBS+=-lc_r $(_LIBS) \
		CFLAGS+=-DPTHREAD_NO_CANCEL $(_CFLAGS)

openbsd:
	@make portscan LIBS+=-lc_r $(_LIBS) \
		CFLAGS+=-pthread $(_CFLAGS)

tarball:
	make clean
	cd ..
	rm -f portscan.tgz
	tar -zcf /tmp/portscan.tgz -C ../ portscan 
	mv /tmp/portscan.tgz ./

clean: 
	rm -rf *.o portscan
