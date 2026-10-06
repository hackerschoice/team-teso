CC=gcc
SHELLCODES_BIN=shell_normal.bin shell_ucase.bin
SHELLCODES=shell_normal.h shell_ucase.h
TESTPROGS=test_normal test_ucase

all: dump $(SHELLCODES_BIN) $(SHELLCODES) $(TESTPROGS)

test_normal: test_normal.o

test_ucase: test_ucase.o

%.bin: %.asm
	nasm -f bin -o $@ $<
	ndisasm -u $@ > $(*F).disasm 

%.h: %.bin
	./dump $< shellcode > $@

dump: dump.c

clean:
	rm -f *~ *.bak *.o *.disasm $(SHELLCODES) $(SHELLCODES_BIN) $(TESTPROGS) dump

depend:
	@makedepend -Y *.c >/dev/null 2>&1

# DO NOT DELETE

test_normal.o: shell_normal.h
test_ucase.o: shell_ucase.h
