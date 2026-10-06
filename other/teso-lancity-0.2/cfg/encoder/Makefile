#
# makefile for Unix based lcn
#
CC = gcc

OBJS=  main.o lcconfig.o lcerrors.o lcnmib.o snmp.o asn1.o md5.o

CFLAGS= -g -DUNIX_LCN

LcnConvert:	${OBJS}
	$(CC)  $(CFLAGS) -o LcnConvert $(OBJS) 

lcn_decode:	lcn_decode.c
	$(CC)  $(CFLAGS) lcn_decode.c -o lcn_decode 

clean:
	rm -f ${OBJS}
	rm -f LcnConvert
