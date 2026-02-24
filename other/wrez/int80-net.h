

#ifndef	INT80_NET_H
#define	INT80_NET_H


#define	SOCK_STREAM	1
#define	SOCK_DGRAM	2
#define	SOCK_RAW	3

#define	PF_LOCAL	1
#define	PF_UNIX		PF_LOCAL
#define	PF_FILE		PF_LOCAL
#define	PF_INET		2
#define	PF_INET6	10
#define	PF_NETLINK	16
#define	PF_ROUTE	PF_NETLINK
#define	PF_PACKET	17

#define	AF_UNSPEC	PF_UNSPEC
#define	AF_LOCAL	PF_LOCAL
#define	AF_UNIX		PF_UNIX
#define	AF_FILE		PF_FILE
#define	AF_INET		PF_INET
#define	AF_INET6	PF_INET6
#define	AF_NETLINK	PF_NETLINK
#define	AF_ROUTE	PF_ROUTE
#define	AF_PACKET	PF_PACKET

#define	MSG_OOB		0x01
#define	MSG_PEEK	0x02
#define	MSG_DONTWAIT	0x40


#pragma pack(1)
struct in_addr {
	unsigned int	s_addr;
};

struct sockaddr_in {
//	unsigned char	sin_len;
	unsigned short	sin_family;
	unsigned short	sin_port;
	struct in_addr	sin_addr;
	char		sin_zero[8];
};

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/

typedef int socklen_t;


static inline int
socket (int domain, int type, int protocol)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (domain), "m" (type), "m" (protocol),
		"a" (__NR_socketcall), "b" (SYS_SOCKET) : "ecx");

	return (ret);
}


static inline int
bind (int sock, struct sockaddr_in *addr, socklen_t *addrlen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (addr), "m" (addrlen),
		"a" (__NR_socketcall), "b" (SYS_BIND) : "ecx");

	return (ret);
}


static inline int
connect (int sock, const struct sockaddr_in *addr, socklen_t *addrlen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (addr), "m" (addrlen),
		"a" (__NR_socketcall), "b" (SYS_CONNECT) : "ecx");

	return (ret);
}


static inline int
listen (int sock, int backlog)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x08, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (backlog),
		"a" (__NR_socketcall), "b" (SYS_LISTEN) : "ecx");

	return (ret);
}


static inline int
accept (int sock, struct sockaddr_in *addr, socklen_t *addrlen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (addr), "m" (addrlen),
		"a" (__NR_socketcall), "b" (SYS_ACCEPT) : "ecx");

	return (ret);
}


static inline int
getsockname (int sock, struct sockaddr_in *name, socklen_t *namelen)
{
	register int	ret;

	/* eeks, if just inlining was better documented.
	 */
	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (name), "m" (namelen),
		"a" (__NR_socketcall), "b" (SYS_GETSOCKNAME) : "ecx");

	return (ret);
}


static inline int
getpeername (int sock, struct sockaddr_in *name, socklen_t *namelen)
{
	register int	ret;

	/* eeks, if just inlining was better documented.
	 */
	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (name), "m" (namelen),
		"a" (__NR_socketcall), "b" (SYS_GETPEERNAME) : "ecx");

	return (ret);
}


static inline int
socketpair (int d, int type, int protocol, int sv[2])
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x10, %%esp
		" : "=a" (ret)
		: "m" (d), "m" (type), "m" (protocol), "m" (sv),
		"a" (__NR_socketcall), "b" (SYS_SOCKETPAIR) : "ecx");

	return (ret);
}


static inline int
send (int s, const void *msg, int len, int flags)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x10, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (msg), "m" (len), "m" (flags),
		"a" (__NR_socketcall), "b" (SYS_SEND) : "ecx");

	return (ret);
}


static inline int
recv (int s, void *buf, int len, int flags)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x10, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (buf), "m" (len), "m" (flags),
		"a" (__NR_socketcall), "b" (SYS_RECV) : "ecx");

	return (ret);
}


static inline int
sendto (int s, const void *msg, int len, int flags,
	const struct sockaddr_in *to, socklen_t tolen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%6
		pushl	%5
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x18, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (msg), "m" (len), "m" (flags), "m" (to),
		"m" (tolen), "a" (__NR_socketcall), "b" (SYS_SENDTO) : "ecx");

	return (ret);
}


static inline int
recvfrom (int s, void *buf, int len, int flags,
	struct sockaddr_in *from, socklen_t *fromlen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%6
		pushl	%5
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x18, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (buf), "m" (len), "m" (flags), "m" (from),
		"m" (fromlen), "a" (__NR_socketcall), "b" (SYS_RECVFROM) : "ecx");

	return (ret);
}


static inline int
shutdown (int sock, int how)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x08, %%esp
		" : "=a" (ret)
		: "m" (sock), "m" (how),
		"a" (__NR_socketcall), "b" (SYS_SHUTDOWN) : "ecx");

	return (ret);
}


static inline int
setsockopt (int s, int level, int optname, const void *optval,
	socklen_t optlen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%5
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x14, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (level), "m" (optname), "m" (optval),
		"m" (optlen), "a" (__NR_socketcall),
		"b" (SYS_SETSOCKOPT) : "ecx");

	return (ret);
}


static inline int
getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%5
		pushl	%4
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x14, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (level), "m" (optname), "m" (optval),
		"m" (optlen), "a" (__NR_socketcall),
		"b" (SYS_GETSOCKOPT) : "ecx");

	return (ret);
}


static inline int
sendmsg (int s, const void *msg, int flags)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (msg), "m" (flags),
		"a" (__NR_socketcall), "b" (SYS_SENDMSG) : "ecx");

	return (ret);
}

static inline int
recvmsg (int s, void *msg, int flags)
{
	register int	ret;

	__asm__ __volatile__ ("
		pushl	%3
		pushl	%2
		pushl	%1
		movl	%%esp, %%ecx
		int	$0x80
		addl	$0x0c, %%esp
		" : "=a" (ret)
		: "m" (s), "m" (msg), "m" (flags),
		"a" (__NR_socketcall), "b" (SYS_RECVMSG) : "ecx");

	return (ret);
}

#endif


