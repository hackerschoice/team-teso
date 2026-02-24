/* based on ADMfzap
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pwd.h>
#include <errno.h>
#include <stdarg.h>


extern int errno;

#include "fzap.h"



/* does this work for any other than linux? */
void _fini()
{
    DBG("Warning: fzap unloaded!");
}

void _init()
{
    void *handle;

    handle = dlopen(LIB_PATH, 1);
    if (!handle) {
	fprintf(stderr, "\n[fzap] dlopen error!\n");
	return;
    }
    old_connect = dlsym(handle, SYM_CONNECT);
    if (!old_connect) {
	fprintf(stderr, "\n[fzap] dlopen error!\n");
	return;
    }
    DBG("Warning: fzap loaded!");
}


CONNECT(__fd, __addr, __len)
{
    int result, truc, t2 = sizeof(int), loport = 0;
    struct sockaddr_in *my_addr;
    char *lprt;
    void *handle;


    handle = dlopen(LIB_PATH, 1);
    if (!handle) {
	fprintf(stderr, "\n[fzap] dlopen error!\n");
	return -1;
    }
    DBG("dlopen ok!");

    old_connect = dlsym(handle, SYM_CONNECT);

    if (!old_connect) {
	fprintf(stderr, "\n[fzap] dlsym error!\n");
	return -1;
    }
    DBG("dlsym ok!");

    my_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr));

    if (getsockopt(__fd, SOL_SOCKET, SO_TYPE, (void *) &truc, &t2) < 0) {
	free(my_addr);
	return -1;
    }
    if ((lprt = getenv("LPORT")) != NULL) {
	loport = atoi(lprt);
    } else {
	switch (truc) {
	case SOCK_STREAM:
	    loport = 20;
	    break;
	case SOCK_DGRAM:
	    loport = 53;
	    break;
	default:
	    DBG("getsockopt=%i", result);
	    loport = 0;
	    break;
	}
    }

    DBG("loport=%i", loport);

    t2 = sizeof(my_addr);

    /* this checks if the socket has already a name, so we won't try to rebind
       it (the previous bind() call should have been trapped */

    if (getsockname(__fd, (struct sockaddr *) my_addr, &t2) < 0) {
	free(my_addr);
	return -1;
    }
    DBG("getsockname ok! (in connect())");

    if (((struct sockaddr_in *) my_addr)->sin_port == 0) {
	memset(my_addr, 0, sizeof(struct sockaddr));
	my_addr->sin_family = AF_INET;

	if (my_addr->sin_port == 0)
	    my_addr->sin_port = htons(loport);

	if (bind(__fd, (struct sockaddr *) my_addr, sizeof(struct sockaddr)) < 0)
	    switch (errno) {
	    case EINVAL:
		fprintf(stderr, "\n[fzap] Warning: couldn't bind to port %i\n", loport);
		break;
	    default:
		free(my_addr);
		return -1;
	    }
    }
    result = old_connect(__fd, __addr, __len);

    DBG("old_connect ok!");

    dlclose(handle);
    free(my_addr);
    return result;

}



BIND(__fd, __addr, __len)
{
    int result, truc, t2 = sizeof(int), loport = 0, oldport = 0;
    struct sockaddr_in *my_addr;
    char *lprt;
    void *handle;

    DBG("bind()");

    if (getsockopt(__fd, SOL_SOCKET, SO_TYPE, (void *) &truc, &t2) < 0) {
	free(my_addr);
	return -1;
    }
    if ((lprt = getenv("LPORT")) != NULL) {
	loport = atoi(lprt);
    } else {
	switch (truc) {
	case SOCK_STREAM:
	    loport = 20;
	    break;
	case SOCK_DGRAM:
	    loport = 53;
	    break;
	default:
	    DBG("getsockopt=%i", result);
	    loport = 0;
	    break;
	}
    }

    oldport = ((struct sockaddr_in *) __addr)->sin_port;

    if (loport)
	((struct sockaddr_in *) __addr)->sin_port = htons(loport);

    handle = dlopen(LIB_PATH, 1);
    if (!handle) {
	fprintf(stderr, "\n[fzap] dlopen error!\n");
	return -1;
    }
    DBG("dlopen ok!");

    old_bind = dlsym(handle, SYM_BIND);

    if (!old_bind) {
	fprintf(stderr, "\n[fzap] dlsym error!\n");
	return -1;
    }
    DBG("dlsym ok!");
    DBG("bind(): loport : %i", loport);

    if ((result = old_bind(__fd, __addr, __len)) < 0) {
	((struct sockaddr_in *) __addr)->sin_port = oldport;
	result = old_bind(__fd, __addr, __len);
    }
    return result;
}
