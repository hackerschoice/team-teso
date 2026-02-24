
#ifndef	CIPHER_MRSA_INTERFACE_H
#define	CIPHER_MRSA_INTERFACE_H

#include "cipher-mrsa.h"


typedef struct {
	NN	pq;	/* n = p * q */
	NN	e;	/* public exponent */
} rsa_pubkey;

typedef struct {
	NN	d;	/* private exponent */
	NN	p, q;
	NN	dp, dq, qp;
} rsa_privkey;


/* rsa_keypair_generate
 *
 * generate a 512 bit rsa keypair and copy only required components into the
 * appropiate structure.
 *
 * return 0 on success
 * return != 0 on failure
 */

int
rsa_keypair_generate (rsa_pubkey *pub, rsa_privkey *priv);


/* rsa_keypair_dump
 *
 * output the two keys in human readable form to `fd'. when they are set to
 * NULL, they are not exported.
 *
 * return in any case
 */

void
rsa_keypair_dump (int fd, rsa_pubkey *pub, rsa_privkey *priv);


/* rsa_keypair_import
 *
 * import a 512 bit rsa keypair from `fd' in human readable format to the
 * `pub' and `priv' structures. each can be set to NULL to skip them.
 *
 * return in any case
 */

void
rsa_keypair_import (int fd, rsa_pubkey *pub, rsa_privkey *priv);


/* rsa_encrypt
 *
 * encrypt RSA_SIZE byte array at `data' with the public key `pub'.
 *
 * return in any case
 */

void
rsa_encrypt (rsa_pubkey *pub, unsigned char *data);


/* rsa_decrypt
 *
 * decrypt RSA_SIZE byte array at `data' with the private key `priv'.
 *
 * return in any case
 */

void
rsa_decrypt (rsa_privkey *priv, unsigned char *data);

#endif

