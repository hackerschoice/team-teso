#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
	char buf[1024], buf2[1024];
	int i = 0;
	sprintf(buf, "/proc/%d/exe", getpid());

	if (readlink(buf, buf2, sizeof(buf2)) < 0) {
		perror("readlink");
		exit(errno);
	}
	printf("%s\n", buf2);
	for (i = 0; argv[i]; ++i)
		printf("%s\n", argv[i]);

	printf("- %s- \n", SAYSO);
	for (;;);

	return 0;
}

