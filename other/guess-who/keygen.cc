/* Key generator for rsa keys (SSH2!)
 * (C) 2002 Sebastian Krahmer.
 * WARNING: theres no random is the keys, so
 * THE GENERATED KEYS ARE WEAK! Do not use it to
 * generate your pubkeys, this program is for debugging only.
 */ 
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

extern "C" {
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
}

#include <string.h>

#include "base64.h"
#include "misc.h"


int rsa2blob(RSA *key, unsigned char *buf, size_t buflen)
{
	size_t blen = buflen;
	int h;
	unsigned char *tmp;

	if (blen < 4)
		return -1;

	if (key->e->neg || key->n->neg)
		printf("AAA");

	size_t l = strlen("ssh-rsa");
	unsigned char *ptr = buf;
	*(unsigned int*)ptr = htonl(l);
	ptr += 4; blen -= 4;
	if (blen < l)
		return -1;
	memcpy(ptr, "ssh-rsa", l); // HAH! 
	ptr += l; blen -= l;

	unsigned int n = BN_num_bytes(key->e);
	if (blen < n+1+4)
		return -1;

	tmp = new unsigned char [n];
	BN_bn2bin(key->e, tmp);
	h = (tmp[0] & 0x80) ? 1 : 0;
	*(unsigned int*)ptr = htonl(n+h);
	ptr += 4; blen -= 4;
	*ptr = 0;
	memcpy(ptr+h, tmp, n);
	ptr += n; blen -= n;
	ptr += h; blen -= h;
	delete [] tmp;

	n = BN_num_bytes(key->n);
	if (blen < n+1+4)
		return -1;

	tmp = new unsigned char [n];
	BN_bn2bin(key->n, tmp);
	h = (tmp[0] & 0x80) ? 1 : 0;
	*(unsigned int*)ptr = htonl(n+h);
	ptr += 4; blen -= 4;
	*ptr = 0;
	memcpy(ptr+h, tmp, n);
	ptr += n; blen -= n;
	ptr += h; blen -= h;
	delete [] tmp;

	return ptr-buf;
}


int main(int argc, char **argv)
{

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <bits> <privfile> <pubfile>\n",
		        *argv);
		return -1;
	}

	RSA *r;
	int bits = atoi(argv[1]);
	r = RSA_generate_key(bits, 35, NULL, NULL);

	FILE *f = fopen(argv[2], "w");
	if (!f)
		die("fopen");

	PEM_write_RSAPrivateKey(f, r, NULL, NULL, 0, NULL, NULL);
	fclose(f);

	unsigned char key_string[1024];
	char uu_key_string[2049];
	memset(uu_key_string, 0, sizeof(uu_key_string));
	memset(key_string, 0, sizeof(key_string));

	int n = rsa2blob(r, key_string, sizeof(key_string));
	printf("%d\n", n);
	if (n < 0)
		die("Not enough memory to store key.");
	b64_ntop(key_string, n, uu_key_string, 2*n);

	f = fopen(argv[3], "w");
	if (!f)
		die("fopen");

	fprintf(f, "ssh-rsa %s icke@dort\n", uu_key_string);
	fclose(f);

	return 0;
}

