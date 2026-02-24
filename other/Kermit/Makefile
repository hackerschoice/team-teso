# written by palmers / teso
SUBDIRS = include lib src doc

all:
	for x in $(SUBDIRS); do \
		make -C $$x; \
	done

clean:
	for x in $(SUBDIRS); do \
		make -C $$x clean; \
	done


