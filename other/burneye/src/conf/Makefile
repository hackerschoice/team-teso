
CFLAGS	= -Wall
ifeq ($(debug),on)
CFLAGS	+= -ggdb
DFLAGS	+= -DDEBUG
else
CFLAGS	+= -O2
endif

YACC	= bison
YACCOPT	= -b conf-parser -p cf -d -t -v
LEX	= flex
LEXOPT	= -pcf -oconf-lexer.c


conf-lexer.c:	config.l
	$(LEX) $(LEXOPT) config.l

clean:
#	rm -f conf-parser.[ch] conf-parser.output
#	rm -f conf-lexer.c
