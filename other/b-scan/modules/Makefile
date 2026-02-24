CC=gcc
COPT=-Wall -ggdb -shared -fPIC -I../include
DEFS=`libnet-config --defines` -DUSE_LIBNET #-DDEBUG
LIBS=
TARGETS=mod_snmp mod_banner mod_httpd mod_ping mod_bind

# HPUX 10.20
# DEFS=`libnet-config --defines` -DUSE_LIBNET -DHP10 #-DDEBUG

all:	
	for trgt in $(TARGETS); do \
	    $(CC) $(COPT) $(DEFS) -o $$trgt.so $$trgt.c; \
	done


clean:
	for trgt in $(TARGETS); do \
	    rm -f $$trgt.so; \
        done
	rm -f core *~


