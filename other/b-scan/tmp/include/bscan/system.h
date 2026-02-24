/*
 * generic system functions
 */

#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define DEV_ZERO	"/dev/zero"

/*
 * we use the 'do while' trick to use err_abort as if they were functions
 */
#define err_abort(code,text) do { \
	fprintf (stderr, "%s at \"%s\":%d: %s\n", \
		text, __FILE__, __LINE__, strerror (code)); \
	abort(); \
	} while (0)

#define errno_abort(text) do { \
	fprintf(stderr, "%s at \"%s\":%d: %s\n", \
		text, __FILE__, __LINE__, strerror (errno)); \
	abort(); \
	} while (0)


void *shmalloc (int, size_t);
void do_nanosleep (time_t, long);
void xchange (void *, void *, int);
void time_diff (struct timeval *, struct timeval *);
int ctoreal(char *, char *);
void save_write(FILE *, char *, unsigned char *, int);
int isprintdata(char *, int);
int dat2hexstr(unsigned char *, unsigned int, unsigned char *, unsigned int);
int dat2strip(unsigned char *, unsigned int, unsigned char *, unsigned int);

