all:
	cc -c -O2 eoe20.c -o eoe.o

install:
	cp eoe.o /lib/modules || true
	cp eoe.h /usr/include/linux || true
	chmod 0600 /usr/include/linux/eoe.h
	chmod 0600 /lib/modules/eoe.o
	mknod /dev/exec c 127 0 || true
	

	
