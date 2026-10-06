#

CC=gcc -ggdb -O2 -ansi -pedantic
LEX=flex
YACC=yacc

all: hellkit driver data2text

driver: driver.c
	$(CC) driver.c -o driver

hellkit: lexer1 main.o
	$(CC) lexer1.o main.o -lfl -o hellkit

main.o: main.c
	$(CC) -c main.c -o main.o

lexer1: hellkit.l
	$(LEX) hellkit.l
	$(CC) -c lex.yy.c -o lexer1.o
	
data2text: data2text.l
	$(LEX) data2text.l
	$(CC) -O2 lex.yy.c -o data2text -lfl

clean:
	rm -f *.o core y.tab.c y.tab.h lex.yy.c y.output
