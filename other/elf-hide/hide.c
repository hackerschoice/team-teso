/* ELF data hider by edi / teso

 * hides data in segments .note and .comments of ELF files, xor encrypted

 * -k specifies key
 * -d data to hide [optional]
 * -f files to hide in [optional] (directory and/or files, seperated by ':')
 * -u unhide
 * -v verbose [optional]

 * -f is $PATH by default
 * -u doesn't need -d 
 * if -d is not given, data is read from stdin

 * warning: using different keys on same files will clobber hidden data
 */


#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elf.h>

#define INPUT_BUFFER 1000

#ifndef ELFMAG
#define ELFMAG "\177ELF"
#endif

char *data=NULL, *key=NULL, *file=NULL;
int unhide=0, verbose=0;
unsigned int signature;

int eread (int fd, char *buf, size_t count) {
	int i, sig=signature;

	i = read (fd, buf, count);
	if (i>0) for (count=0; count<i; count++) {
		buf[count]^= (sig & 0xff);
		sig = (sig << 8) | (sig >> 24);
	}
	return i;
}

int ewrite (int fd, char *buf, size_t count, int adjust) {
	int i, sig=signature;
	char *e;
	e = malloc (count);
	adjust%=4;
	while (adjust--) sig = (sig<<8) | (sig>>24);
	for (i=0;i<count;i++) {
		e[i] = buf[i] ^ (sig & 0xff);
		sig = (sig << 8) | (sig >> 24);
	}
	i = write (fd, e, count);
	free (e);
	return i;
}

int hide (char *where) {
	int i, f;
	char *shstrtab;
	Elf32_Ehdr ehdr;
	Elf32_Shdr *shdr;

	if (verbose) {
		printf("%s: ", where);
		fflush (stdout);
	}

	f = open (where, unhide?O_RDONLY:O_RDWR);
	if (f == -1) {
		perror ("open");
		return 0;
	}

	read (f, &ehdr, sizeof (ehdr));

	if ( (!memcmp (&ehdr.e_ident, ELFMAG, 4)) && (ehdr.e_type == ET_EXEC)) {
		shdr = malloc (ehdr.e_shnum*ehdr.e_shentsize);
		lseek (f, ehdr.e_shoff, SEEK_SET);
		read (f, shdr, ehdr.e_shnum*ehdr.e_shentsize);

		shstrtab = malloc (shdr[ehdr.e_shstrndx].sh_size);
		lseek (f, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
		read (f, shstrtab, shdr[ehdr.e_shstrndx].sh_size);

		for (i=1; i<ehdr.e_shnum; i++) {
			if ((!strcmp (&shstrtab[shdr[i].sh_name], ".note")) ||
				(!strcmp (&shstrtab[shdr[i].sh_name], ".comment"))) {

				unsigned int sig, len;

				lseek (f, shdr[i].sh_offset, SEEK_SET);
				read (f, (char*) &sig, 4);
				read (f, (char*) &len, 4);
				len = len^signature;
				if (sig != signature) len=0;

				if (!unhide && (8 + strlen (data) + len < shdr[i].sh_size)) {
					lseek (f, shdr[i].sh_offset, SEEK_SET);
					write (f, (char*)&signature, 4);
					len+= strlen (data);
					len = len^signature;
					write (f, (char*)&len, 4);
					len = len^signature;
					lseek (f, len-strlen(data), SEEK_CUR);
					ewrite (f, data, strlen(data), len-strlen(data));
					if (verbose) printf ("%d bytes stored\n", strlen(data));
					return 1;
				} else if (unhide && sig==signature) {
					lseek (f, shdr[i].sh_offset+8, SEEK_SET);
					data = malloc (len);
					eread (f, data, len);
					if (verbose) printf ("%s> ", where);
					fflush (stdout);
					write (STDOUT_FILENO, data, len);
					if (verbose) printf ("\n");
					free (data);
				}
			}
		}
	}

	close(f);
	return 0;
}

int doit (char *what) {
	struct stat st;

	if (stat (what, &st)) return 0;

	if (S_ISDIR (st.st_mode)) {
		struct dirent *ent;

		DIR *dir = opendir (what);

		if (!dir) return 0;
		chdir (what);

		while ((ent = readdir (dir))) {
			if (!stat (ent->d_name, &st)) {
				if (S_ISREG (st.st_mode)) {
					if (hide (ent->d_name) && !unhide) return 1;
				}				
			}
		}
		closedir (dir);
	} else if (S_ISREG (st.st_mode)) return hide (what);

	return 0;
}

void arg() {
	exit (1);
}

int makesig (char *key) {
	unsigned int sig=0;

	while (*key) {
		sig = sig^*key;
		sig = (sig << 8) | (sig >> 24);
		key++;
	}

	return sig;
}

int main (int argc, char **argv) {
	char *subfile;

	argc--, argv++;
	while (argc) {
		if (!strcmp (*argv, "-v")) {
			verbose = 1;
		}
		if (!strcmp (*argv, "-k")) {
			argc--, argv++;
			if (!argc) arg();
			key = *argv;
		}
		if (!strcmp (*argv, "-f")) {
			argc--, argv++;
			if (!argc) arg();
			file = *argv;
		}
		if (!strcmp (*argv, "-d")) {
			argc--, argv++;
			if (!argc) arg();
			data = *argv;
		}
		if (!strcmp (*argv, "-u")) {
			unhide = 1;
		}
		argc--, argv++;
	}

	if (!key) return 1;

	signature = makesig (key);
	
	if (!data && !unhide)  {
		int num, pos = 0;
		data = malloc (INPUT_BUFFER);
		while ((num = read (0, data+pos, INPUT_BUFFER-pos)) ) pos+=num;
	}

	if (!file) {
		file = getenv ("PATH");
		if (!file) return 1;
	}

	subfile = file;
	while (*subfile) {
		if (*subfile == ':') *subfile = '\0';
		if (*subfile == '\0') {
			if (doit (file) && !unhide) return 0;
			file = ++subfile;
		} else subfile++;
	}
	if (doit (file)) return 0;

	return 1;
}
