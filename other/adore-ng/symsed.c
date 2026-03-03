#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>


int main(int argc, char **argv)
{
	int fd = 0;
	char *ptr = NULL, *orig_ptr = NULL;
	struct stat st;

	if (argc != 3) {
		printf("Usage: %s <file> <subst>\n", *argv);
		exit(1);
	}
	if (strlen(argv[2]) >= strlen("init_module")) {
		printf("Can't only substitute symbols by strings with at most"
		       "%u characters.\n", strlen("init_module"));
		exit(2);
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		perror("open");
		exit(errno);
	}
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(errno);
	}
	ptr = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	orig_ptr = ptr;
	if (!ptr) {
		perror("mmap");
		exit(errno);
	}
	for (; ptr < orig_ptr + st.st_size; ++ptr) {
		if (strncmp(ptr, "init_module", strlen("init_module")) == 0 ||
		    strncmp(ptr, "cleanup_module", strlen("cleanup_module")) == 0) {
			memcpy(ptr, argv[2], strlen(argv[2]));
			ptr += strlen(argv[2]);
		}
	}
	munmap(ptr, st.st_size);
	return 0;	
}

