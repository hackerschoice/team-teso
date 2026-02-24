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

OBJS	= ../../shared/common.o condition.o compiler_main.o branch.o call.o \
		element.o functions.o script.o symbol.o y.tab.o lex.yy.o


all:		compiler-test

link:		$(OBJS)

dist:		lex.yy.c y.tab.h

compiler-test:	$(OBJS) compiler-test.c
		$(CC) -o compiler-test compiler-test.c $(OBJS) $(CFLAGS) $(LIBS)

lex.yy.o:	lex.yy.c y.tab.h

lex.yy.c:	compiler.l
		$(LEX) $(LEXOPT) compiler.l

y.tab.c y.tab.h:	compiler.y
			$(YACC) $(YACCOPT) compiler.y

clean:
	rm -f y.tab.c y.tab.h y.output lex.yy.c
	rm -f compiler-test
	rm -f *.o

