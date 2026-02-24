all: telnet

include ../MCONFIG
include ../MRULES

#CXXFLAGS:=$(patsubst -O2, -g, $(CXXFLAGS))

# -DAUTHENTICATE
CXXFLAGS += -DUSE_TERMIO -DKLUDGELINEMODE
LIBS += $(LIBTERMCAP)

SRCS = commands.cc main.cc network.cc ring.cc sys_bsd.cc telnet.cc \
	terminal.cc tn3270.cc utilities.cc genget.cc environ.cc netlink.cc

OBJS = $(patsubst %.cc, %.o, $(SRCS))

telnet: $(OBJS)
	$(CXX) $(LDFLAGS) $^ $(LIBS) -o $@

include depend.mk
depend:
	$(CXX) $(CXXFLAGS) -MM $(SRCS) >depend.mk

install: telnet
	install -s -m$(BINMODE) telnet $(INSTALLROOT)$(BINDIR)
	install -m$(MANMODE) telnet.1 $(INSTALLROOT)$(MANDIR)/man1

clean:
	rm -f *.o telnet

