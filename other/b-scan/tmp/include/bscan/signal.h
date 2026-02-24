/*
 * this space for rent....
 */

typedef void (*sighandler_t) (int);

#define SIG_SETALL	0x01


int sigctl (int, sighandler_t);
