
#ifndef	CRYPTO_H
#define	CRYPTO_H


/* mhash
 *
 * produce a weak 32 bit hash value from a memory block at `src'. use `len'
 * bytes from it to compute the hash value. it has no strong properties, but
 * is sufficient for simple stuff. the hash value is also dependant on the
 * `len' parameter.
 *
 * XXX: the memory block to be hashed should be at least 8 bytes long for the
 *      hash to be sufficient !
 *
 * return hash value in any case
 */

unsigned int
mhash (unsigned char *src, unsigned int len);

#endif

