#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>

#ifndef SHMMNI
#define SHMMNI  100
#endif

#define MAXSHM	4		/* its bscan. we need <4 shm's */

static int shm_id = -1;		/* last used id */
static int shm_c = -1;		/* shm_alloc counter */

static struct _shm
{
    int id;
    void *ptr;
}
shm[MAXSHM];


/*
 * uhm. hard job for the process coz the process
 * does not get the shm_id. uhm. i should make a static traking list
 * of all shared memory segments (addr <-> id mapping maybe ?)
 * on the other hand...since an attachment count is maintained for
 * the shared memory segment the segment gets removed when the last
 * process using the segment terminates or detaches it.
 * hmm. Seems the following function is completly useless....:>
 * Hey. why are you reading my comments ? write me: anonymous@segfault.net!
 */
int
shmfree (int shm_id)
{
    if (shm_id < 0)
	return (-1);
    return (shmctl (shm_id, IPC_RMID, 0));
}

/*
 * kill ALL shm's
 * uhm. this is brutal. but shm is risky. you can bring
 * down ANY system if you waste all shm's. Shm's dont get 
 * freed on process-exit !!! syslog will fail, inetd will fail, ..
 * any program that tries to alloc shared memory...nono good :>
 * root can use 'ipcrm shm <id>' do free the shm's.
 * that's why we use this brutal "killall"-method.
 * something else: killall-method is realy BRUTAL. believe me!
 * If you have other functions registered on exit (atexit)
 * and you try to reference to a shm within these function...you are lost
 * Unexpected things will happen....
 */
void
shmkillall ()
{
    int c;

    for (c = 0; c < shm_c; c++)
	shmfree (shm[c].id);
}

/*
 * allocate shared memory (poor but fast IPC)
 * the value returned is a pointer to the allocated 
 * memory, which is suitably aligned for any kind of
 * variable, or NULL if the request fails.
 *
 * TODO: on SVR4 use open("/dev/zero", O_RDWR); and mmap trick for speedup 
 */
void *
shmalloc (int flag, size_t length)
{
    void *shm_addr;
    int c = 0;

    if (shm_c == -1)		/* init all the internal shm stuff */
    {
	atexit (shmkillall);
	shm_c = 0;
    }

    if (shm_c >= MAXSHM)
	return (NULL);		/* no space left in list. no bscan ?? */

    if (flag == 0)
	flag = (IPC_CREAT | IPC_EXCL | SHM_R | SHM_W);

    while (c < SHMMNI)		/* brute force a NEW shared memory section */
	if ((shm_id = shmget (getpid () + c++, length, flag)) != -1)
	    break;
	else
	    return (NULL);

    if ((shm_addr = shmat (shm_id, NULL, 0)) == NULL)
	return (NULL);

    shm[shm_c].id = shm_id;
    shm[shm_c].ptr = shm_addr;
    shm_c++;			/* increase shm-counter */

    return (shm_addr);
}

#ifdef WITH_NANOSLEEP
/* add lib '-lrt' */
/*
 * nanosec must be in the range  0 to 999 999 999
 * ..we dont care about signals here...
 */
void
do_nanosleep (time_t sec, long nsec)
{
    struct timespec mynano;
    mynano.tv_sec = sec;
    mynano.tv_nsec = nsec;
    nanosleep (&mynano, NULL);
}
#endif


/*
 * xchange data p1 <-> p2 of length len
 */
void
xchange (void *p1, void *p2, int len)
{
    unsigned char buf[len];

    memcpy (buf, p1, len);
    memcpy (p1, p2, len);
    memcpy (p2, buf, len);
}

/*
 * calculate time-difference now - in
 * and return diff in 'now'
 */
void
time_diff (struct timeval *in, struct timeval *now)
{
    if ((now->tv_usec -= in->tv_usec) < 0)
    {
	now->tv_sec--;
	now->tv_usec += 1000000;
    }
    now->tv_sec -= in->tv_sec;
}

/*
 * converts a 'esc-sequenced' string to normal string
 * return string in dst.
 * returns 0 on success
 * todo: \ddd decoding
 */
int
ctoreal(char *src, char *dst)
{
    char c;

    if ((src == NULL) || (dst == NULL))
    {
	dst = NULL;
        return(0);	/* yes, its ok. */
    }

    while (*src != '\0')
        if (*src == '\\')
        {
            switch((c = *++src))
            {
                case 'n':
                    *dst++ = '\n';
                    break;
                case 'r':
                    *dst++ = '\r';
                    break;
                case 't':
                    *dst++ = '\t';
                    break;
                case '\\':
                    *dst++ = '\\';
                    break;
                case 's':
                    *dst++ = ' ';
                    break;
                default:
                    *dst++ = c;
                  /*  printf("unknown escape sequence 0x%2.2x\n", c);*/
                    break;
            }
            src++;
        } else
        {
            *dst++ = *src++;
        }
    *dst = '\0';
    return(0);
}


/*
 * parse data, format data and print to fd (only prinatable chars)
 * supress \r, nonprintable -> '_';
 * output line by line [\n] with 'prefix' before each line.
 * prefix is a 0-terminated string
 */
void
save_write(FILE *fd, char *prefix, unsigned char *data, int data_len)
{
    int 	c;
    unsigned char 	*ptr = data;
    unsigned char 	*startptr = data;
    const char	trans[] =
                "................................ !\"#$%&'()*+,-./0123456789"
                ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
                "nopqrstuvwxyz{|}~...................................."
                "....................................................."
                "........................................";


   if (prefix == NULL)
	prefix = "";

    for (c = 0; c < data_len; c++)
    {
	if (*data == '\r')	/* i dont like these */
	{
	    data++;
	    continue;
	}
	if (*data == '\n')
	{
	    *ptr = '\0';
	    fprintf (fd, "%s%s\n", prefix, startptr);
	    startptr = ++data;
	    ptr = startptr;
	    continue;
	}

	*ptr++ = trans[*data++];
	
    }

   if (ptr != startptr)
   {
	*ptr = '\0';
	fprintf (fd, "%s%s\n", prefix, startptr);
   }

}

/*
 * check if data contains any non-printable chars [except \n]
 * return 0 if yes,,,,1 if not.
 */
int
isprintdata(char *ptr, int len)
{
    char 	c;

    while(len-- > 0)
    {
	c = *ptr++;
	if (c == '\n')
	    continue;
	if (!isprint((int)c))
	    return(0);
    }

  return(1);
}

/*
 * convert some data into hex string
 * We DO 0 terminate the string.
 * dest = destination
 * destlen = max. length of dest (size of allocated memory)
 * data = (non)printable input data
 * len = input data len
 * return 0 on success, 1 if data does not fit into dest, -1 on error
 */
int
dat2hexstr(unsigned char *dest, unsigned int destlen, unsigned char *data,
		 unsigned int len)
{
    unsigned int	i = 0;
    unsigned int 	slen = 0;
    unsigned char 	*ptr = dest;
    unsigned char 	c;
    char 		hex[] = "0123456789ABCDEF";

    memset(dest, '\0', destlen);

    while (i++ < len)
    {
        c = *data++;
        if (slen + 3 < destlen)
        {
            *dest++ = hex[c / 16];
            *dest++ = hex[c % 16];
            *dest++ = ' ';
            slen += 3;
            ptr += 3;
         } else {
                return(1);
        }
    }

    return(0);
}


/* dat2strip
 *
 * print the data at `data', which is `len' bytes long to the char
 * array `dest', which is `destlen' characters long. filter out any
 * non-printables. NUL terminate the dest array in every case.
 *
 * return the number of characters written
 */

int
dat2strip(unsigned char *dest, unsigned int destlen, unsigned char *data,
		unsigned int len)
{
    unsigned char	*dp;

    for (dp = dest ; dp - dest < destlen && len > 0 ; --len, ++data, ++dp) {
	if (isprint (*data))
	    *dp = *data;
    }

    if (dp - dest < destlen)
	*dp = '\0';
    dest[destlen - 1] = '\0';

    return (dp - dest);
}


