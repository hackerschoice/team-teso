/* crypto, cipher and obfuscation related functions
 */

#include "crypto.h"


/* a very simple homemade hash function with no strong properties at all.
 */
unsigned int
mhash (unsigned char *src, unsigned int len)
{
	unsigned int	hash = len;	/* some small initial gain */

	for (hash = 0 ; len > 0 ; --len, ++src) {
		hash ^= *src;
		hash = ((hash & 0xffe00000) >> 21) |
			((hash & 0x001fffff) << 11);
		hash += *src;
		hash += len;
	}

	return (hash);
}

