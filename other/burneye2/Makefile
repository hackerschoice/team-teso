
#FLAGS_PROFILE=-pg -a
#FLAGS_OPTIMIZE_MORE=-O6 -funroll-loops -fexpensive-optimizations \
	-finline-functions -fpeephole -ffast-math -fregmove -frerun-loop-opt
#FLAGS_OPTIMIZE=-O2 -DOPTIMIZE $(FLAGS_OPTIMIZE_MORE)
#FLAGS_DUPE_DEBUG=-DDUPE_DEBUG

DFLAGS=-Wall -g -ggdb $(FLAGS_PROFILE)
#DFLAGS=-Wall
#CC=i386-uclibc-gcc
CC=gcc
#CFLAGS=-O2 -DOPTIMIZE
#CFLAGS=-Os -fconserve-space
#CC=i386-uclibc-cc

export CFLAGS
export DFLAGS
export FLAGS_DUPE_DEBUG
export FLAGS_OPTIMIZE
export CC

DFLAGS+=$(FLAGS_DUPE_DEBUG)
CFLAGS+=$(DFLAGS) -I. -Icommon -Ielf -Iia32
CFLAGS+=$(FLAGS_OPTIMIZE)

OBJSMAN=common/common.o utility.o
OBJS=$(OBJSMAN) morph.o func_handling.o datahandler.o
OBJS_OBJOBF=objwriter.o codegen.o
#LIBS=-Lelf -lxelf -Lia32 -lia32
LIBS=-Lia32 -lia32 -Lelf -lxelf


all:	util loader hashgen objobf

release:	all
	strip loader

release-objobf:	clean all
	./release-objobf.sh

clean:
	rm -f loader $(OBJS) $(OBJS_OBJOBF)
	rm -f hashgen
	rm -f objobf
	rm -f *.dot *.ps
	rm -f gmon.out bb.out
	make -C ia32 clean
	make -C elf clean

count:
	find . -type f | \
		egrep -v "/tmp/|/testcases/|/alpha-releases/|/util/" | \
		egrep "\.[chly]$$|Makefile" | xargs wc -l

objobf:	objobf.c libia32 libxelf $(OBJS) $(OBJS_OBJOBF)
	$(CC) -o objobf objobf.c $(CFLAGS) $(OBJS) $(OBJS_OBJOBF) $(LIBS)

loader:	loader.c libia32 libxelf $(OBJS)
	$(CC) -o loader loader.c $(CFLAGS) -DTESTING $(OBJS) \
		$(LIBS)

tarball:	clean
	tar cfvz backup/burneye2-`cat version.h |grep 'VERSION."'|cut -d '"' -f2`.tar.gz \
		Makefile *.c *.h *.o \
		common/ doc/ elf/ ia32/ subprojects/ testcases/ tmp/

hashgen:	hashgen.c
	$(CC) -o hashgen hashgen.c $(CFLAGS) -DTESTING $(OBJSMAN)

libia32:
	make -C ia32 libia32

libxelf:
	make -C elf elflib

util:
	gcc -O2 -o util/sstrip util/sstrip.c


