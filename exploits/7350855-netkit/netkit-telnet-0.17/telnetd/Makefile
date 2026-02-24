all: telnetd

include ../MCONFIG
include ../MRULES

# -DAUTHENTICATE

# If having unused tty devices root.root and mode 600 bugs you,
# take out -DPARANOID_TTYS.

CFLAGS += '-DISSUE_FILE="/etc/issue.net"' -DPARANOID_TTYS \
	   -DNO_REVOKE -DKLUDGELINEMODE -DDIAGNOSTICS \
	   -DLOGIN_WRAPPER=\"/usr/lib/telnetlogin\"
# LIBS += $(LIBTERMCAP)

OBJS = telnetd.o state.o termstat.o slc.o sys_term.o utility.o \
	global.o setproctitle.o

# authenc.o (empty)

# logout.o logwtmp.o (now from -lutil)


telnetd: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

$(OBJS): defs.h ext.h pathnames.h telnetd.h logwtmp.h logout.h setproctitle.h
telnetd.o: ../version.h

install: telnetd
	install -s -m$(DAEMONMODE) telnetd $(INSTALLROOT)$(SBINDIR)/in.telnetd
	install -m$(MANMODE) issue.net.5 $(INSTALLROOT)$(MANDIR)/man5/
	install -m$(MANMODE) telnetd.8 $(INSTALLROOT)$(MANDIR)/man8/in.telnetd.8
	ln -sf in.telnetd.8 $(INSTALLROOT)$(MANDIR)/man8/telnetd.8

clean:
	rm -f *.o telnetd 

