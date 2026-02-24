
#include "int80.h"
#include "unistd.h"
#include "fingerprint.h"
#include "crypto.h"


unsigned int
fp_get (void)
{
	unsigned int	hash;
	struct utsname	thishost;


	uname (&thishost);
	hash = mhash ((unsigned char *) &thishost, sizeof (thishost));

	return (hash);
}


