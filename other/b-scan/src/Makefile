#
# Makefile of (m)bscan v0.0, skyper
# Massiv Banner Scanner
#

CC=gcc
COPT=-Wall -ggdb -I../include -I/usr/include/pcap
LEX=flex
LEXOPT=
OBJS=bscan.o arpg.o snarf.o network_raw.o restore.o
OBJS2=tty.o system.o signal.o dcd_icmp.o garage.o cf_prse.o module.o
SUPOBJ=../support/hpuxdl.o ../support/snprintf.o
TARGET=bscan
INDENT=indent
INDENT_OPT=-bap -nbc -bbo -bl -bli0 -bls -ncdb -nce -cp1 -cs -di2 -ndj -nfc1 -nfca -hnl -i4 -ip5 -lp  -psl -nsc -nsob

# LINUX
#######
LOPT=-export-dynamic
DEFS=`libnet-config --defines` -DHAVE_DLSYM -D_SVID_SOURCE #-DDEBUG
LIBS=-lpcap -ldl -lm `libnet-config --libs` -lpthread

# SunOS 5.7/5.8 + gcc
#####################
#LOPT=-export-dynamic
#DEFS=`libnet-config --defines` -DHAVE_DLSYM #-DDEBUG
#LIBS=-lpcap -ldl -lm `libnet-config --libs` -lpthread

# HP-UX 11.00
#############
#LOPT=-Xlinker -E
#DEFS=`libnet-config --defines` -DHAVE_DLSYM #-DDEBUG
#LIBS=-lpcap -ldld -lm `libnet-config --libs` -lpthread

# HP-UX 10.20
# HP-UX 10.20 is not supported. You need snprintf.c and
# some hacks to use IP_HDRINCL and the kernel patches
# to access the link_layer interface.
#############
#LOPT=-Xlinker -E
#DEFS=`libnet-config --defines` -DHAVE_DLSYM -DHP10 #-DDEBUG
#LIBS=-lpcap -ldld -lm `libnet-config --libs` -lpthread

# OpenBSD
#########
#LOPT=
#DEFS=`libnet-config --defines` -DHAVE_DLSYM #-DDEBUG
#LIBS=-lpcap -lm `libnet-config --libs` -lpthread

all:	$(SUPOBJ) $(OBJS2) $(OBJS)
	$(CC) $(SUPOBJ) $(OBJS) $(OBJS2) $(LOPT) $(LIBS) -o $(TARGET)

cf_prse.o:
	$(LEX) $(LEXOPT) -ocf_prse.c cf_prse.l
	$(CC) $(COPT) -c cf_prse.c

dcd_icmp.o:	dcd_icmp.c
	$(CC) $(COPT) -c dcd_icmp.c

garage.o:	garage.c
	$(CC) $(COPT) -c garage.c

module.o:	module.c
	$(CC) $(COPT) $(DEFS) -c module.c

system.o:	system.c
	$(CC) $(COPT) -c system.c 

tty.o:		tty.c
	$(CC) $(COPT) -c tty.c

signal.o:	signal.c
	$(CC) $(COPT) -c signal.c

../support/hpuxdl.o:	../support/hpuxdl.c
	$(MAKE) -C ../support

../support/snprintf.o:	../support/snprintf.c
	$(MAKE) -C ../support

.c.o:
	$(CC) $(COPT) $(DEFS) -c $<

clean:
	rm -f $(OBJS) $(OBJS2) $(TARGET) cf_prse.c core *~

indent:
	$(INDENT) $(INDENT_OPT) *.c *.h
