#!/bin/sh

#c89 -c -o object.o $1
#objdump -D cbegin $1 | egrep "[0-9a-f]+:" | cut -c 7- | \
#	awk '{ printf ("\t\"\\x%s\\x%s\\x%s\\x%s\"\t/* %s\t*/\n", \
#		$1, $2, $3, $4, $5 $6 $7 $8 $9) }' > \
#	object.h
#gcc -o $2 ../codedump.c -DHPUX
#rm -f object.h

# i knew learning awk would repay some day ;-P
objdump -D execvesh | \
awk '
	function pbyte (CHAR) {
		if (match (CHAR, /(00)|(0a)|(0d)|(25)/))
			printf ("_");
		printf ("\\x%s", CHAR);
		if (match (CHAR, /(00)|(0a)|(0d)|(25)/))
			printf ("_");
		return;
	}

	BEGIN {
		foo = 0;
	}

	/cbegin/ {
		foo = 1;
		ccount = 0;
		printf ("unsigned char shellcode[] =");
	}

	foo == 1 && /cend/ {
		foo = 0;
		if (ccount == 0) {
			printf (";\n");
		} else {
			printf ("\";\n");
		}
	}

	foo == 1 && /[0123456789abcdef]+\:/ {
		if (ccount == 0) {
			printf ("\n\t\"");
		}
		pbyte($2);
		pbyte($3);
		pbyte($4);
		pbyte($5);
		ccount += 4;

		if (ccount == 12) {
			ccount = 0;
			printf ("\"")
		}
	}'

