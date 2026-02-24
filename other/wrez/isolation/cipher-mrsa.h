/*
 * mrsa.h -- Multiprecision math and  RSA public key crypt library
 * 1993 Risto Paasivirta, paasivir@jyu.fi
 * Public Domain, no warranty. Use as you wish.
 */

#ifndef	CIPHER_MRSA_H
#define CIPHER_MRSA_H

#ifndef RSA_SIZE
/* #define RSA_SIZE 32 for max 512 (actually 511) bit modulus */
#define RSA_SIZE 16
#endif

/*
 * unsigned 16 and 32 -bit types (other sizes may need some porting)
 */

#ifndef	UWORD	
typedef unsigned short UWORD;
#endif
#ifndef	ULONG
typedef unsigned long ULONG;
#endif

typedef UWORD *N, NN[RSA_SIZE];

typedef struct rsa_key {
	ULONG b;
	NN pq,e,d,p,q,dp,dq,qp;
} rsa_key;

#if !defined(RSA_ONLY) || defined(MRSA_C)

#define UNIT_BITS 16		/* unit bits */
#define SIGN_BIT (1<<15)	/* top bit of unit */
#define PRIMES 54		/* number of primes in prime table */

#ifdef	RSA_ONLY	/* define RSA_ONLY if math stuff not needed */
#define PRIVATE static
#else
#define PRIVATE
#endif


int	ts(N a);		/* test signed, returns -1, 0 or 1 */
ULONG	ng(N a);		/* negate, return carry*/
void	cl(N a);		/* clear */
void	cp(N a,N b);		/* copy, a = b */
int	cu(N a,N b);		/* compare unsigned, returns, -1 0 or 1 */
ULONG	ad(N a,N b);		/* add, a += b */
ULONG	sb(N a,N b);		/* substract, a -= b */
ULONG	sr(N a);		/* shift right, a >>= 1, return carry */
ULONG	sl(N a);		/* shift left, a <<= 1, return carry */
void	dm(N a,N b,N c);	/* div-mod unsigned, a /= b, c = a % b */
void	mu(N a,N b);		/* multiply unsigned, a *= b */
void	mm(N a,N b,N m);	/* modular multiply, a = a * b mod m */
void	em(N a,N e,N m);	/* modular exponentiation, a = a^e mod m */
void	gd(N a,N b);		/* greatst common divisor, a = gcd(a,b) */
void	iv(N a,N b);		/* multiplicative inverse, a = a^{-1} mod p */
void	nh(char *a,N b);	/* convert number to hex string */
void	hn(N a,char *b);	/* convert lowercase hex string to number */
ULONG	ri();			/* weak pseudorandom integer */

#endif /* RSA_C */

void	randomize(N a, ULONG bits);
ULONG	sieve_prime(N);
int	prob_prime(N);
void	next_prime(N);
ULONG 	rsa_gen(rsa_key *);
void 	rsa_enc(N,rsa_key *);
void 	rsa_dec(N,rsa_key *);
ULONG 	n_to_b(unsigned char *,N);
void 	b_to_n(N,unsigned char *,ULONG);

#endif


