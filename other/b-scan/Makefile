#
# Makefile of (m)bscan v0.0, skyper
# Massiv Banner Scanner
#
# GNU-make mandatory!

SUBDIRS=support src modules

# edit support/Makefile
# edit src/Makefile
# edit modules/Makefile

all:	
	for dir in $(SUBDIRS); do \
	    $(MAKE) -C $$dir; \
        done

clean:
	for dir in $(SUBDIRS); do \
	    $(MAKE) -C $$dir clean; \
        done

pack:
	rm -f bscan.tar.gz
	tar cfvz bscan.tar.gz support/*.c support/Makefile src/*.c src/*.l src/Makefile include/bscan/*.h Makefile MODULES PROBLEMS INSTALL  README modules/*.c modules/Makefile


