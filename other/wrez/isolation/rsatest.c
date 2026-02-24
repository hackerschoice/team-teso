/*
 * rsatest.c
 */

#include <stdio.h>
#include <stdlib.h>
#include "cipher-mrsa.h"

void
main(int i, char **v) {
	NN m,c,d;
	rsa_key key;
	rsa_key key_pub;
	rsa_key key_priv;
	char s[RSA_SIZE*4+2];

	if(i==4) {
		hn(c,v[1]);
		hn(d,v[2]);
		hn(m,v[3]);
		em(c,d,m);
		nh(s,c); puts(s);
		exit(EXIT_SUCCESS);
	}

	if(i!=3) {
		puts("Usage: mtest [hex_pseed] [hex_qseed]");
		exit(EXIT_FAILURE);
	}

	hn(key.p,v[1]);
	hn(key.q,v[2]);

	puts("Generating key...");
	if(!rsa_gen(&key)) {
		puts("Failed, try other seed values.");
		exit(EXIT_FAILURE);
	}
	puts("Done, key components: pq,e,d,p,q,dp,dq,qp");		
	puts("   public components: pq,e");
	puts("  private components:      d,p,q,dp,dq,qp");
	printf("bits = %u\n",key.b);

	nh(s,key.pq); puts(s);
	nh(s,key.e); puts(s);
	nh(s,key.d); puts(s); 
	nh(s,key.p); puts(s);
	nh(s,key.q); puts(s);
	nh(s,key.dp); puts(s);
	nh(s,key.dq); puts(s);
	nh(s,key.qp); puts(s);
	puts("testing, msg,cip,dec1,dec2");
	cl(m);
	randomize(m, key.b-2);
	nh(s,m); puts(s);

	memset (&key_pub, 0x00, sizeof (key_pub));
	cp (key_pub.pq, key.pq);
	cp (key_pub.e, key.e);
#if 0
	memcpy (&key_pub, &key, sizeof (key_pub));
#if 0
	cl(key_pub.pq);
	cl(key_pub.e);
#endif
	cl(key_pub.p);
	cl(key_pub.q);
	cl(key_pub.d);
	cl(key_pub.dp);
	cl(key_pub.dq);
	cl(key_pub.qp);
#endif
	cp(c,m); rsa_enc(c,&key_pub);

	nh(s,c); puts(s);
#if 0
	cp(d,c); em(d,key.d,key.pq); /* slow way */
	nh(s,d); puts(s);
#endif
#if 0
	cl(key.p);
	cl(key.q);
	cl(key.dp);
	cl(key.dq);
	cl(key.qp);

	cl(key.pq);
	cl(key.e);
#endif
	memset (&key_priv, 0x00, sizeof (key_priv));
	cp (key_priv.p, key.p);
	cp (key_priv.q, key.q);
	cp (key_priv.dp, key.dp);
	cp (key_priv.dq, key.dq);
	cp (key_priv.qp, key.qp);

	cp(d,c); rsa_dec(d,&key_priv); /* faster way */
	nh(s,d); puts(s);
	exit(EXIT_SUCCESS);
}

