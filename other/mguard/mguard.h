
void DBG(char *fmt,...)
{
    va_list *ap;
#ifdef DEBUG
    va_start(ap, fmt);
    fprintf(stderr, "\n[fzap:DBG]\t");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
#endif
}


#if defined(__linux__) || (defined(__svr4__) && defined(__sun__)) || defined(sgi) || defined(__osf__)
#define US ""
#else
#define US "_"
#endif

#define SYM_CONNECT US"connect"
#define SYM_BIND US"bind"


#ifdef LINUX_LIBC
#define LIB_PATH "/lib/libc.so.5"
#define CONNECT(A,B,C) int connect __P((int A, const struct sockaddr * B, int C))
int (*old_connect) (int, struct sockaddr *, int) = NULL;
#define BIND(A,B,C) int bind __P ((int A, const struct sockaddr * B, socklen_t C))
int (*old_bind) (int, const struct sockaddr * , socklen_t) = NULL;
#endif

#ifdef LINUX_GLIBC
#define LIB_PATH "/lib/libc.so.6"
#define CONNECT(A,B,C) int connect __P((int A, __CONST_SOCKADDR_ARG B, socklen_t C))
int (*old_connect) (int, __CONST_SOCKADDR_ARG, int) = NULL;
#define BIND(A,B,C) int bind __P ((int A, const struct sockaddr * B, socklen_t C))
int (*old_bind) (int, __CONST_SOCKADDR_ARG, socklen_t) = NULL;
#endif




#ifdef SOLARIS
#define LIB_PATH "/usr/lib/libsocket.so"
#define CONNECT(A,B,C) int connect (int A, const struct sockaddr * B, socklen_t C)
int (*old_connect) (int, const struct sockaddr *, int) = NULL;
#endif


#ifdef __FreeBSD__
#define LIB_PATH "/usr/lib/libc.so.3.0"
#define CONNECT(A,B,C) int connect(int A, const struct sockaddr *B, int C)
int (*old_connect)(int, const struct sockaddr *, int)=NULL;
#define BIND(A,B,C) int bind __P((int A, const struct sockaddr * B, int C))
int (*old_bind)(int, const struct sockaddr *, int);
#endif


