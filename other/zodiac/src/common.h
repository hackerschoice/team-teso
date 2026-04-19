
#ifndef	Z_COMMON_H
#define	Z_COMMON_H

#include <sys/time.h>
#include <netinet/in.h>

#ifdef	DEBUG
void	debugp (char *filename, const char *str, ...);
void	hexdump (char *filename, unsigned char *data, unsigned int amount);
#endif
int			m_random (int lowmark, int highmark);
void			set_tv (struct timeval *tv, int seconds);
void			xstrupper (char *str);
void			scnprintf (char *os, size_t len, const char *str, ...);
unsigned long int	tdiff (struct timeval *old, struct timeval *new);
char			*ipv4_print (char *dest, struct in_addr in, int padding);
void			*xrealloc (void *m_ptr, size_t newsize);
char			*xstrdup (char *str);
void			*xcalloc (int factor, size_t size);
char			*allocncat (char **to, char *from, size_t len);
char			*alloccat (char **to, char *from);
char			*ip_get_random (void);

#endif

