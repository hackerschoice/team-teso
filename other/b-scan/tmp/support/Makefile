CC=gcc
COPT=-Wall -ggdb -I../include
DEFS=#-DDEBUG
OBJ=hpuxdl.o snprintf.o

# HPUX 11.00
# DEFS=-DNEED_SNPRINTF -DHAVE_SHL_LOAD #-DDEBUG

# HPUX 10.20
# DEFS=-DHP10 -DNEED_SNPRINTF -DHAVE_SHL_LOAD #-DDEBUG

all:	$(OBJ)

.c.o:
	$(CC) $(COPT) $(DEFS) -c $<

clean:
	rm -f $(OBJ) core *~


