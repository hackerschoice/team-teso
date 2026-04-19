/* sha-1 implementation
 *
 * by steve reid <steve@edmweb.com>
 * modified by scut
 *
 * include file
 */

#ifndef _FNX_CIPHER_SHA1_H
#define	_FNX_CIPHER_SHA1_H


/* SHA1Hash
 *
 * hash an ASCIIZ password into a 20 byte long hash byte buffer
 *
 * return in any case
 */

void	SHA1Hash (char *password, unsigned char *hash);


#endif

