all: telnetlogin

include ../MCONFIG
include ../MRULES

OBJS = telnetlogin.o

telnetlogin: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

$(OBJS): ../version.h

install: telnetlogin
	install -s -m4750 -oroot -gtelnetd telnetlogin $(INSTALLROOT)$(SBINDIR)
	install -m$(MANMODE) telnetlogin.8 $(INSTALLROOT)$(MANDIR)/man8

clean:
	rm -f *.o telnetlogin
