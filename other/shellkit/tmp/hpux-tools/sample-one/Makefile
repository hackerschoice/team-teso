all: exploit vuln

exploit: exploit.c
	gcc exploit.c -o exploit
vuln: vuln.c
	gcc vuln.c -o vuln


clean:
	@rm -f core *.core *.o vuln exploit a.out
