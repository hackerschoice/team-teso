CC = g++
CPPFLAGS = -Wall -O2
OBJS = elf.o elf_fault.o elf_str.o

all: $(OBJS)
	ar -cr libelf++.a $(OBJS)
	ranlib libelf++.a

clean:
	rm -rf *.o libelf++.a
