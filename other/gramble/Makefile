CC	= gcc
#CFLAGS	= -Wall -O2 -static
CFLAGS	= -Wall -ggdb
#CFLAGS	= -Wall -ggdb -DDEBUG
#CFLAGS	= -Wall -ggdb -DYYDEBUG -DDEBUG

LIBS	=

YACC	= yacc
YACCOPT	= -d -v -t
LEX	= lex
LEXOPT	=

OBJS	= common.o \
	y.tab.o lex.yy.o input-driver.o


all:	inputtest

link:	$(OBJS)

dist:	lex.yy.c y.tab.h

inputtest:	$(OBJS) input-test.c
	$(CC) -o input-test input-test.c $(OBJS) $(CFLAGS) $(LIBS)

gramble:	$(OBJS)
	$(CC) -o gramble $(OBJS) $(CFLAGS) $(LIBS)

lex.yy.o:	lex.yy.c y.tab.h

lex.yy.c:	input.l
	$(LEX) $(LEXOPT) input.l

y.tab.c y.tab.h:	input.y
	$(YACC) $(YACCOPT) input.y

clean:
	rm -f y.tab.c y.tab.h y.output lex.yy.c
	rm -f gramble
	rm -f *.o

