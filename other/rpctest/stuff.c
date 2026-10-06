/* rpctest
 *
 * smiler / teso
 */
#include "rpc.h"

int
resolv (char *hostname, struct in_addr *addr)
{
	struct hostent *blah;

	if (inet_aton (hostname, addr))
		return (1);

	blah = gethostbyname (hostname);
	if (blah == NULL)
		return (0);

	memcpy (addr, blah->h_addr, sizeof (struct in_addr));
	return (1);
}

int
udp_connect (struct in_addr addr, u_short port)
{
	int     fd;
	struct sockaddr_in sin;

	fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return (-1);

	bzero (&sin, sizeof (sin));
	sin.sin_addr.s_addr = addr.s_addr;
	sin.sin_family = AF_INET;
	sin.sin_port = htons (port);

	if (connect (fd, (SA *) & sin, sizeof (sin)) < 0)
		return (-1);

	return (fd);
}

int
send_recv (int s, const void *msg, int len,
	   void *recv_buf, int recv_len)
{
	struct timeval tv;
	fd_set  rset;
	int     sends = 0;

	while (sends < 3) {
		if (send (s, msg, len, 0) < len)
			return (-1);

		++sends;
		FD_ZERO (&rset);
		FD_SET (s, &rset);
		tv.tv_sec = 1;
		tv.tv_usec = 500000;

		if (select (s + 1, &rset, NULL, NULL, &tv) == 0)
			continue;
		return (recv (s, recv_buf, recv_len, 0));
	}

	errno = ETIMEDOUT;
	return (-1);
}

char   *
EATSPACE (char *tmp)
{

	while ((*tmp == ' ') || (*tmp == '\t'))
		tmp++;

	if ((*tmp == '\n') || (*tmp == '\r') || (!*tmp))
		return (NULL);
	return (tmp);
}

int
parse_args (char *str, char **args)
{
	int     a,
	        lastarg;
	char   *ptr;

	for (a = 0; a < MAXARGS; a++)
		args[a] = NULL;

	lastarg = a = 0;
	ptr = str;

	while (a < MAXARGS) {
		if ((ptr = EATSPACE (ptr)) == NULL)
			break;

		if (*ptr == ':') {
			ptr++;
			lastarg = 1;
		}
		args[a++] = ptr;

		while ((*ptr != ' ' || lastarg) && (*ptr != '\0'))
			ptr++;
		if (*ptr != ' ' || lastarg) {
			*ptr++ = 0;
			break;
		} else {
			*ptr++ = 0;
		}
	}
	return (a);
}

void
strip_crlf (char *s)
{
	s += strlen (s) - 1;
	while (*s == '\r' || *s == '\n')
		*s-- = '\0';
	return;
}
