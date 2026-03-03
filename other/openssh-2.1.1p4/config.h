/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */
#ifndef _CONFIG_H
#define _CONFIG_H

/* Generated automatically from acconfig.h by autoheader. */
/* Please make your changes there */


/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define if your system defines sys_errlist[] */
#define HAVE_SYS_ERRLIST 1

/* Define if your system choked on IP TOS setting */
/* #undef IP_TOS_IS_BROKEN */

/* Define if you have the getuserattr function.  */
/* #undef HAVE_GETUSERATTR */

/* Work around problematic Linux PAM modules handling of PAM_TTY */
#define PAM_TTY_KLUDGE 1

/* Define if your snprintf is busted */
/* #undef BROKEN_SNPRINTF */

/* Define if you are on NeXT */
/* #undef HAVE_NEXT */

/* Define if you want to disable PAM support */
/* #undef DISABLE_PAM */

/* Define if you want to enable AIX4's authenticate function */
/* #undef WITH_AIXAUTHENTICATE */

/* Define if you have/want arrays (cluster-wide session managment, not C arrays) */
/* #undef WITH_IRIX_ARRAY */

/* Define if you want IRIX project management */
/* #undef WITH_IRIX_PROJECT */

/* Define if you want IRIX audit trails */
/* #undef WITH_IRIX_AUDIT */

/* Location of random number pool  */
#define RANDOM_POOL "/dev/urandom"

/* Location of EGD random number socket */
/* #undef EGD_SOCKET */

/* Builtin PRNG command timeout */
#define ENTROPY_TIMEOUT_MSEC 200

/* Define if your ssl headers are included with #include <openssl/header.h>  */
/* #undef HAVE_OPENSSL */

/* struct utmp and struct utmpx fields */
#define HAVE_HOST_IN_UTMP 1
#define HAVE_HOST_IN_UTMPX 1
#define HAVE_ADDR_IN_UTMP 1
#define HAVE_ADDR_IN_UTMPX 1
#define HAVE_ADDR_V6_IN_UTMP 1
#define HAVE_ADDR_V6_IN_UTMPX 1
/* #undef HAVE_SYSLEN_IN_UTMPX */
#define HAVE_PID_IN_UTMP 1
#define HAVE_TYPE_IN_UTMP 1
#define HAVE_TYPE_IN_UTMPX 1
#define HAVE_TV_IN_UTMP 1
#define HAVE_TV_IN_UTMPX 1
#define HAVE_ID_IN_UTMP 1
#define HAVE_ID_IN_UTMPX 1
#define HAVE_EXIT_IN_UTMP 1
/* #undef HAVE_TIME_IN_UTMP */
/* #undef HAVE_TIME_IN_UTMPX */

/* Define if you don't want to use your system's login() call */
/* #undef DISABLE_LOGIN */

/* Define if you don't want to use pututline() etc. to write [uw]tmp */
/* #undef DISABLE_PUTUTLINE */

/* Define if you don't want to use pututxline() etc. to write [uw]tmpx */
/* #undef DISABLE_PUTUTXLINE */

/* Define if you don't want to use lastlog */
/* #undef DISABLE_LASTLOG */

/* Define if you don't want to use utmp */
/* #undef DISABLE_UTMP */

/* Define if you don't want to use utmpx */
#define DISABLE_UTMPX 1

/* Define if you don't want to use wtmp */
/* #undef DISABLE_WTMP */

/* Define if you don't want to use wtmpx */
#define DISABLE_WTMPX 1

/* Define if you want to specify the path to your lastlog file */
/* #undef CONF_LASTLOG_FILE */

/* Define if you want to specify the path to your utmp file */
/* #undef CONF_UTMP_FILE */

/* Define if you want to specify the path to your wtmp file */
/* #undef CONF_WTMP_FILE */

/* Define if you want to specify the path to your utmpx file */
/* #undef CONF_UTMPX_FILE */

/* Define if you want to specify the path to your wtmpx file */
/* #undef CONF_WTMPX_FILE */

/* Define is libutil has login() function */
#define HAVE_LIBUTIL_LOGIN 1

/* Define if libc defines __progname */
#define HAVE___PROGNAME 1

/* Define if you want Kerberos 4 support */
/* #undef KRB4 */

/* Define if you want AFS support */
/* #undef AFS */

/* Define if you want S/Key support */
/* #undef SKEY */

/* Define if you want TCP Wrappers support */
/* #undef LIBWRAP */

/* Define if your libraries define login() */
#define HAVE_LOGIN 1

/* Define if your libraries define daemon() */
#define HAVE_DAEMON 1

/* Define if your libraries define getpagesize() */
#define HAVE_GETPAGESIZE 1

/* Define if xauth is found in your path */
#define XAUTH_PATH "/usr/X11R6/bin/xauth"

/* Define if rsh is found in your path */
#define RSH_PATH "/usr/bin/rsh"

/* Define if you want to allow MD5 passwords */
/* #undef HAVE_MD5_PASSWORDS */

/* Define if you want to disable shadow passwords */
/* #undef DISABLE_SHADOW */

/* Define if you want to use shadow password expire field */
/* #undef HAS_SHADOW_EXPIRE */

/* Define if you want have trusted HPUX */
/* #undef HAVE_HPUX_TRUSTED_SYSTEM_PW */

/* Define if you have Digital Unix Security Integration Architecture */
/* #undef HAVE_OSF_SIA */

/* Define if you have an old version of PAM which takes only one argument */
/* to pam_strerror */
/* #undef HAVE_OLD_PAM */

/* Set this to your mail directory if you don't have maillock.h */
#define MAIL_DIRECTORY "/var/spool/mail"

/* Data types */
#define HAVE_INTXX_T 1
#define HAVE_U_INTXX_T 1
/* #undef HAVE_UINTXX_T */
#define HAVE_SOCKLEN_T 1
#define HAVE_SIZE_T 1
#define HAVE_SSIZE_T 1
#define HAVE_MODE_T 1
#define HAVE_PID_T 1
#define HAVE_SA_FAMILY_T 1
#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#define HAVE_STRUCT_ADDRINFO 1
#define HAVE_STRUCT_IN6_ADDR 1
#define HAVE_STRUCT_SOCKADDR_IN6 1

/* Fields in struct sockaddr_storage */
/* #undef HAVE_SS_FAMILY_IN_SS */
#define HAVE___SS_FAMILY_IN_SS 1

/* Define if you have /dev/ptmx */
/* #undef HAVE_DEV_PTMX */

/* Define if you have /dev/ptc */
/* #undef HAVE_DEV_PTS_AND_PTC */

/* Define if you need to use IP address instead of hostname in $DISPLAY */
/* #undef IPADDR_IN_DISPLAY */

/* Specify default $PATH */
/* #undef USER_PATH */

/* Specify location of ssh.pid */
#define PIDDIR "/var/run"

/* Use IPv4 for connection by default, IPv6 can still if explicity asked */
/* #undef IPV4_DEFAULT */

/* getaddrinfo is broken (if present) */
/* #undef BROKEN_GETADDRINFO */

/* Workaround more Linux IPv6 quirks */
#define DONT_TRY_OTHER_AF 1

/* Detect IPv4 in IPv6 mapped addresses and treat as IPv4 */
#define IPV4_IN_IPV6 1

/* The number of bytes in a char.  */
#define SIZEOF_CHAR 1

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a long int.  */
#define SIZEOF_LONG_INT 4

/* The number of bytes in a long long int.  */
#define SIZEOF_LONG_LONG_INT 8

/* The number of bytes in a short int.  */
#define SIZEOF_SHORT_INT 2

/* Define if you have the __b64_ntop function.  */
/* #undef HAVE___B64_NTOP */

/* Define if you have the _getpty function.  */
/* #undef HAVE__GETPTY */

/* Define if you have the arc4random function.  */
/* #undef HAVE_ARC4RANDOM */

/* Define if you have the atexit function.  */
#define HAVE_ATEXIT 1

/* Define if you have the b64_ntop function.  */
/* #undef HAVE_B64_NTOP */

/* Define if you have the bcopy function.  */
#define HAVE_BCOPY 1

/* Define if you have the bindresvport_af function.  */
/* #undef HAVE_BINDRESVPORT_AF */

/* Define if you have the clock function.  */
#define HAVE_CLOCK 1

/* Define if you have the entutent function.  */
/* #undef HAVE_ENTUTENT */

/* Define if you have the entutxent function.  */
/* #undef HAVE_ENTUTXENT */

/* Define if you have the freeaddrinfo function.  */
#define HAVE_FREEADDRINFO 1

/* Define if you have the gai_strerror function.  */
#define HAVE_GAI_STRERROR 1

/* Define if you have the getaddrinfo function.  */
#define HAVE_GETADDRINFO 1

/* Define if you have the getnameinfo function.  */
#define HAVE_GETNAMEINFO 1

/* Define if you have the getpwanam function.  */
/* #undef HAVE_GETPWANAM */

/* Define if you have the getrusage function.  */
#define HAVE_GETRUSAGE 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the getutent function.  */
#define HAVE_GETUTENT 1

/* Define if you have the getutid function.  */
#define HAVE_GETUTID 1

/* Define if you have the getutline function.  */
#define HAVE_GETUTLINE 1

/* Define if you have the getutxent function.  */
#define HAVE_GETUTXENT 1

/* Define if you have the getutxid function.  */
#define HAVE_GETUTXID 1

/* Define if you have the getutxline function.  */
#define HAVE_GETUTXLINE 1

/* Define if you have the inet_aton function.  */
#define HAVE_INET_ATON 1

/* Define if you have the innetgr function.  */
#define HAVE_INNETGR 1

/* Define if you have the login function.  */
#define HAVE_LOGIN 1

/* Define if you have the logout function.  */
#define HAVE_LOGOUT 1

/* Define if you have the logwtmp function.  */
#define HAVE_LOGWTMP 1

/* Define if you have the md5_crypt function.  */
/* #undef HAVE_MD5_CRYPT */

/* Define if you have the memmove function.  */
#define HAVE_MEMMOVE 1

/* Define if you have the mkdtemp function.  */
/* #undef HAVE_MKDTEMP */

/* Define if you have the on_exit function.  */
#define HAVE_ON_EXIT 1

/* Define if you have the openpty function.  */
#define HAVE_OPENPTY 1

/* Define if you have the pam_getenvlist function.  */
#define HAVE_PAM_GETENVLIST 1

/* Define if you have the pututline function.  */
#define HAVE_PUTUTLINE 1

/* Define if you have the pututxline function.  */
#define HAVE_PUTUTXLINE 1

/* Define if you have the rresvport_af function.  */
/* #undef HAVE_RRESVPORT_AF */

/* Define if you have the setenv function.  */
#define HAVE_SETENV 1

/* Define if you have the seteuid function.  */
#define HAVE_SETEUID 1

/* Define if you have the setlogin function.  */
/* #undef HAVE_SETLOGIN */

/* Define if you have the setproctitle function.  */
/* #undef HAVE_SETPROCTITLE */

/* Define if you have the setreuid function.  */
#define HAVE_SETREUID 1

/* Define if you have the setutent function.  */
#define HAVE_SETUTENT 1

/* Define if you have the setutxent function.  */
#define HAVE_SETUTXENT 1

/* Define if you have the sigaction function.  */
#define HAVE_SIGACTION 1

/* Define if you have the sigvec function.  */
#define HAVE_SIGVEC 1

/* Define if you have the snprintf function.  */
#define HAVE_SNPRINTF 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strlcat function.  */
/* #undef HAVE_STRLCAT */

/* Define if you have the strlcpy function.  */
/* #undef HAVE_STRLCPY */

/* Define if you have the strsep function.  */
#define HAVE_STRSEP 1

/* Define if you have the time function.  */
#define HAVE_TIME 1

/* Define if you have the updwtmp function.  */
#define HAVE_UPDWTMP 1

/* Define if you have the utmpname function.  */
#define HAVE_UTMPNAME 1

/* Define if you have the utmpxname function.  */
#define HAVE_UTMPXNAME 1

/* Define if you have the vhangup function.  */
#define HAVE_VHANGUP 1

/* Define if you have the vsnprintf function.  */
#define HAVE_VSNPRINTF 1

/* Define if you have the <bstring.h> header file.  */
/* #undef HAVE_BSTRING_H */

/* Define if you have the <endian.h> header file.  */
#define HAVE_ENDIAN_H 1

/* Define if you have the <floatingpoint.h> header file.  */
/* #undef HAVE_FLOATINGPOINT_H */

/* Define if you have the <krb.h> header file.  */
/* #undef HAVE_KRB_H */

/* Define if you have the <lastlog.h> header file.  */
#define HAVE_LASTLOG_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <login.h> header file.  */
/* #undef HAVE_LOGIN_H */

/* Define if you have the <maillock.h> header file.  */
/* #undef HAVE_MAILLOCK_H */

/* Define if you have the <netdb.h> header file.  */
#define HAVE_NETDB_H 1

/* Define if you have the <netgroup.h> header file.  */
/* #undef HAVE_NETGROUP_H */

/* Define if you have the <netinet/in_systm.h> header file.  */
#define HAVE_NETINET_IN_SYSTM_H 1

/* Define if you have the <paths.h> header file.  */
#define HAVE_PATHS_H 1

/* Define if you have the <poll.h> header file.  */
#define HAVE_POLL_H 1

/* Define if you have the <pty.h> header file.  */
#define HAVE_PTY_H 1

/* Define if you have the <security/pam_appl.h> header file.  */
#define HAVE_SECURITY_PAM_APPL_H 1

/* Define if you have the <shadow.h> header file.  */
#define HAVE_SHADOW_H 1

/* Define if you have the <stddef.h> header file.  */
#define HAVE_STDDEF_H 1

/* Define if you have the <sys/bitypes.h> header file.  */
#define HAVE_SYS_BITYPES_H 1

/* Define if you have the <sys/bsdtty.h> header file.  */
/* #undef HAVE_SYS_BSDTTY_H */

/* Define if you have the <sys/cdefs.h> header file.  */
#define HAVE_SYS_CDEFS_H 1

/* Define if you have the <sys/poll.h> header file.  */
#define HAVE_SYS_POLL_H 1

/* Define if you have the <sys/select.h> header file.  */
#define HAVE_SYS_SELECT_H 1

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/stropts.h> header file.  */
#define HAVE_SYS_STROPTS_H 1

/* Define if you have the <sys/sysmacros.h> header file.  */
#define HAVE_SYS_SYSMACROS_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/ttcompat.h> header file.  */
/* #undef HAVE_SYS_TTCOMPAT_H */

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <usersec.h> header file.  */
/* #undef HAVE_USERSEC_H */

/* Define if you have the <util.h> header file.  */
/* #undef HAVE_UTIL_H */

/* Define if you have the <utmp.h> header file.  */
#define HAVE_UTMP_H 1

/* Define if you have the <utmpx.h> header file.  */
#define HAVE_UTMPX_H 1

/* Define if you have the dl library (-ldl).  */
#define HAVE_LIBDL 1

/* Define if you have the krb library (-lkrb).  */
/* #undef HAVE_LIBKRB */

/* Define if you have the nsl library (-lnsl).  */
#define HAVE_LIBNSL 1

/* Define if you have the resolv library (-lresolv).  */
/* #undef HAVE_LIBRESOLV */

/* Define if you have the socket library (-lsocket).  */
/* #undef HAVE_LIBSOCKET */

/* Define if you have the z library (-lz).  */
#define HAVE_LIBZ 1

/* ******************* Shouldn't need to edit below this line ************** */

#include "defines.h"

#endif /* _CONFIG_H */
