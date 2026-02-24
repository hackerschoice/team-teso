commands.o: commands.cc ring.h externs.h defines.h types.h genget.h \
 environ.h proto.h ptrarray.h netlink.h
main.o: main.cc ../version.h ring.h externs.h defines.h proto.h
network.o: network.cc ring.h defines.h externs.h proto.h netlink.h
ring.o: ring.cc ring.h
sys_bsd.o: sys_bsd.cc ring.h defines.h externs.h types.h proto.h \
 netlink.h terminal.h
telnet.o: telnet.cc ring.h defines.h externs.h types.h environ.h \
 proto.h ptrarray.h netlink.h terminal.h
terminal.o: terminal.cc ring.h defines.h externs.h types.h proto.h \
 terminal.h
tn3270.o: tn3270.cc defines.h ring.h externs.h proto.h
utilities.o: utilities.cc ring.h defines.h externs.h proto.h \
 terminal.h
genget.o: genget.cc genget.h
environ.o: environ.cc ring.h defines.h externs.h environ.h array.h
netlink.o: netlink.cc netlink.h proto.h ring.h
