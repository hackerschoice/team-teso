
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef	Z_COMMON_H
#define	Z_COMMON_H

#ifdef	DEBUG
void	debugp (char *filename, const char *str, ...);
void	hexdump (char *filename, unsigned char *data, unsigned int amount);
#endif
int			m_random (int lowmark, int highmark);
void			set_tv (struct timeval *tv, int seconds);
void			xstrupper (char *str);
void			scnprintf (char *os, size_t len, const char *str, ...);
unsigned long int	t_passed (struct timeval *old);
unsigned long int	tdiff (struct timeval *old, struct timeval *new);
char			*ipv4_print (char *dest, struct in_addr in, int padding);
void			*xrealloc (void *m_ptr, size_t newsize);
char			*xstrdup (char *str);
void			*xcalloc (int factor, size_t size);

#endif

