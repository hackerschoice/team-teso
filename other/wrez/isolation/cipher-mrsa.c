/*
 * mrsa.c -- portable multiprecision math and RSA library
 * 1993 Risto Paasivirta, paasivir@jyu.fi
 * Public Domain, no warranty. 
 */

#define MRSA_C 1

#include "cipher-mrsa.h"

/*
 * math library stuff
 */

/*
 * sign = ts(N a) -- test signed, returns 1, 0 or -1 
 */

PRIVATE int
ts(N a)
{
	ULONG i = RSA_SIZE;
	if (a[RSA_SIZE - 1] & SIGN_BIT)
		return -1;
	while (i--)
		if (*a++)
			return 1;
	return 0;
}

/*
 * carry = ng(N a) -- negate, returns carry
 */

PRIVATE ULONG
ng(N a)
{
	ULONG c = 0, i = RSA_SIZE;
	while (i--) {
		c = 0 - *a - c;
		*a++ = c;
		c = (c >> UNIT_BITS) & 1;
	} return c;
}

/*
 * cl(N a) -- clear value, a = 0
 */

PRIVATE void
cl(N a)
{
	ULONG i = 0;
	while (i++ < RSA_SIZE)
		*a++ = 0;
}

/*
 * cp(N a, N b) -- copy, a = b
 */

PRIVATE void
cp(N a, N b)
{
	ULONG i = RSA_SIZE;
	while (i--)
		*a++ = *b++;
}

/*
 * flag = cu(a, b) -- compare unsigned, returns <0 if a<b, 0 if a==b, >0 if a>b
 */
 
PRIVATE int
cu(N a, N b)
{
	ULONG i = RSA_SIZE;
	a += RSA_SIZE;
	b += RSA_SIZE;
	while (i--)
		if (*--a - *--b)
			return (int) *a - (int) *b;
	return 0;
}

/*
 * carry = ad(N a, N b) -- add, a += b
 */

PRIVATE ULONG
ad(N a, N b)
{
	ULONG c = 0, i = RSA_SIZE;
	while (i--) {
		c = *b++ + *a + c;
		*a++ = c;
		c >>= UNIT_BITS;
	} 
	return c;
}

/*
 * carry = sb(N a, N b) -- substract, a -= b
 */

PRIVATE ULONG
sb(N a, N b)
{
	ULONG c = 0, i = RSA_SIZE;
	while (i--) {
		c = *a - *b++ - c;
		*a++ = c;
		c = (c >> UNIT_BITS) & 1;
	}
	return c;
}

/*
 * carry = sr(N a) -- shift right, a >>= 1
 */

PRIVATE ULONG
sr(N a)
{
	ULONG c = 0, i = RSA_SIZE;
	a += RSA_SIZE;
	while (i--) {
		c |= *--a;
		*a = c >> 1;
		c = (c & 1) << UNIT_BITS;
	}
	return c;
}

/*
 * carry = sl(N a) -- shift left, a <<= 1
 */

PRIVATE ULONG
sl(N a)
{
	ULONG c = 0, i = RSA_SIZE;
	while (i--) {
		c |= (ULONG) * a << 1;
		*a++ = c;
		c = (c >> UNIT_BITS) & 1;
	}
	return c;
}

/*
 * dm(N a, N b, N c) -- divide-modulo unsigned, a = a / b, c = a % b
 */

PRIVATE void
dm(N a, N b, N c)
{
	ULONG i = RSA_SIZE * UNIT_BITS;
	cl(c);
	while (i--) {
		sl(c);
		*c |= sl(a);
		if (sb(c, b)) {
			ad(c, b);
		} else {
			*a |= 1;
		}
	}
}

/*
 * remainder = di(N a, int n) -- divide by integer
 */

PRIVATE ULONG
di(N a, ULONG t)
{
	ULONG c = 0, i = RSA_SIZE;
	while (i--) {
		c = (c << UNIT_BITS) | a[i];
		a[i] = c / t;
		c = c % t;
	} 
	return c;
}

/*
 * mu(N a, N b) -- multiply unsigned, a *= b
 */

PRIVATE void
mu(N a, N b)
{
	ULONG i = RSA_SIZE * UNIT_BITS;
	NN c;
	cl(c);
	while (i--) {
		sl(c);
		if (sl(a))
			ad(c, b);
	}
	cp(a, c);
}

/*
 * mm(N a, N b, N m) -- modular multiply, a = a * b mod m 
 */

PRIVATE void
mm(N a, N b, N m)
{
	ULONG i = RSA_SIZE * UNIT_BITS;
	NN c;
	cl(c);
	while (i--) {
		sl(c);
		if (sb(c, m))
			ad(c, m);
		if (sl(a))
			ad(c, b);
		if (sb(c, m))
			ad(c, m);
	}
	cp(a, c);
}

/*
 * pmm(N a, N b, N m, ULONG p) -- internal modmul w/precision for modexp
 */

static void
pmm(N aa, N b, N m, ULONG p)
{
	ULONG k, c, j = UNIT_BITS, i;
	NN v;
	N a;
	i = p;
	cl(v);
	a = aa + p;
	while (!*--a
	       && i)
		i--;
	if (i) {
		while (!(*a & (1 << j)) && j)
			j--;
		cp(v, b);
	} while (i--) {
		while (j--) {
			for (k = 0, c = 0; k < p; k++) {
				c |= (ULONG) v[k] << 1;
				v
					[k] = c;
				c >>= UNIT_BITS;
			} for (k = 0, c = 0; k < p; k++) {
				c = v[k] - m[k] - c;
				v[k] = c;
				c = (c >> UNIT_BITS) & 1;
			} if (c)
				for (k = 0, c = 0; k < p; k++) {
					c = v[k] + m[k] + c;
					v[k] = c;
					c >>= UNIT_BITS;
			} if (*a & (1 << j)) {
				for (k = 0, c = 0; k < p; k++) {
					c = v[k] + b[k] + c;
					v[k] = c;
					c >>= UNIT_BITS;
				} for (k = 0, c = 0; k < p; k++) {
					c = v[k] - m[k] - c;
					v[k] = c;
					c = (c >> UNIT_BITS) & 1;
				} if (c)
					for (k = 0, c = 0; k < p; k++) {
						c = v[k] + m[k] + c;
						v[k] = c;
						c >>= UNIT_BITS;
					}
			}
		}
		a--;
		j = UNIT_BITS;
	}
	cp(aa, v);
}

/*
 * em(N a, N b, N m) -- modular exponentation, a = a^b mod n
 */

PRIVATE void
em(N a, N e, N m)
{
	ULONG i = RSA_SIZE, j = UNIT_BITS, p = RSA_SIZE;
	NN c;
	N mp;
	cl(c);
	*c = 1;
	e += RSA_SIZE;
	while (!*--e && i)
		i--;
	if (i) {
		while (!(*e & (1 << j)))
			j--;
		cp(c, a);
	}
	mp = m + RSA_SIZE;
	while (!*--mp && p)
		p--;
	if (*mp & SIGN_BIT && p < RSA_SIZE)
		p++;
	while (i--) {
		while (j--) {
			pmm(c, c, m, p);
			if (*e & (1 << j))
				pmm(c, a, m, p);
		}
		e--;
		j = UNIT_BITS;
	}
	cp(a, c);
}

/*
 * gd(N a, N b) -- a = greatest common divisor(a,b)
 */

PRIVATE void
gd(N a, N bb)
{
	NN r, b;
	cp(b, bb);
	while (ts(b)) {
		dm(a, b, r);
		cp(a, b);
		cp(b, r);
	}
}

/*
 * iv(N a, N b) -- multiplicative inverse, a = a^{-1} mod b 
 */

PRIVATE void
iv(N a, N b)
{
	NN c, d, e, f, g, y;
	cp(c, b);
	cl(e);
	cl(f);
	*f = 1;
	while (ts(a)) {
		cp(y, c);
		dm(y, a, d);
		if (f[RSA_SIZE - 1] & SIGN_BIT) {
			ng(f);
			mu(y, f);
			ng(f);
			ng(y);
		} else
			mu(y, f);
		cp(g, e);
		sb(g, y);
		cp(c, a);
		cp(a, d);
		cp(e, f);
		cp(f, g);
	}
	if (e[RSA_SIZE - 1] & SIGN_BIT)
		ad(e, b);
	cp(a, e);
}

/*
 * nh(char *a, N b) -- convert value to a hex string (use for debugging)
 */

PRIVATE void
nh(char *a, N b)
{
	char *d = "0123456789abcdef";
	NN c;
	ULONG i = RSA_SIZE * sizeof(UWORD) * 2; /* 2 digits/byte! */
	cp(c, b);
	a += RSA_SIZE * sizeof(UWORD) * 2;
	*a = 0;
	while (i--) {
		*--a = d[*c & 15];
		sr(c);
		sr(c);
		sr(c);
		sr(c);
	}
}

/*
 * hn(N a, char *b) -- lower-case hex string to value (use for constants)
 */

PRIVATE void
hn(N a, char *b)
{
	cl(a);
	while (*b) {
		sl(a);
		sl(a);
		sl(a);
		sl(a);
		*a += *b < 'a' ? *b - '0' : *b - ('a' - 10);
		b++;
	}
}

/*
 * integer = ri() -- generate weak pseudorandom integer (range 0-65535)
 */

PRIVATE ULONG
ri(void)
{
	static ULONG s = 27182;
	s = (s * 31421 + 6927) & 0xffff;
	return s;
}

/*
 * prime generation and RSA stuff
 */

/*
 * randomize(N n, ULONG bits) -- pseudorandomize n, limit to value to
 * range 2^bits to 2^(bits+1)-1. This function eors n with weak random
 * generator, n should be initialized with at least bits-bit strong random
 * value before call.
 * (XXX check portablility when converting to >16-bit UWORD machine)
 */

void
randomize(N a, ULONG b)
{
	ULONG i;
	NN c;
	N d = c;
	cp(c,a);
	cl(a);
	if(b>UNIT_BITS*RSA_SIZE-2) {
		i = RSA_SIZE-1;
		b = UNIT_BITS-2;
	} else {
		i = b / UNIT_BITS;
		b = b % UNIT_BITS;
	}
	while (i--)
		*a++ = *d++ ^ ri();
	*a = ((*d ^ ri()) & ((1 << b) - 1)) | (1 << b);
}

/*
 * const sp[PRIMES], PRIMES -- table of small primes, number of primes in table
 */

static unsigned char sp[PRIMES] = {
  2,  3,  5,  7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
 59, 61, 67, 71, 73, 79, 83, 89, 97,101,103,107,109,113,127,131,
137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,
227,229,233,239,241,251
};

/*
 * divisor = sieve_prime(N n) -- try to find divisor of n by sieving
 * with small integers returns divisor or 0 if no divisor found.
 */

ULONG
sieve_prime(N n)
{
	ULONG i;
	NN a;
	for(i=0;i<PRIMES;i++) {
		cp(a,n);
		if(!di(a,sp[i]))
			return ((ULONG)sp[i]);
	}
	return (0);
}

/*
 * flag = prob_prime(N n) -- test if 2^(n-1) mod n == 1. Returns 0 if
 * test failed, !0 if success. Large n which passes this test is a
 * probable prime. This test does not work well with small value of n. 
 * Because this test is slow, you should first try sieving n.
 */

int
prob_prime(N m)
{
	ULONG i = RSA_SIZE, j = UNIT_BITS, p = RSA_SIZE;
	NN c, ee;
	N mp, e = ee + RSA_SIZE;
	cl(c);
	*c = 1;
	cp(ee, m);
	sb(ee, c);
	while (!*--e && i)
		i--;
	if (i) {
		while (!(*e & (1 << j)))
			j--;
		*c = 2;
	}
	mp = m + RSA_SIZE;
	while (!*--mp && p)
		p--;
	if (*mp & SIGN_BIT && p < RSA_SIZE)
		p++;
	while (i--) {
		while (j--) {
			pmm(c, c, m, p);
			if (*e & (1 << j)) {
				sl(c);
				if(sb(c, m)) ad(c, m);
			}
		}
		e--;
		j = UNIT_BITS;
	}
	cl(ee);
	*ee = 1;
	return (!cu(c,ee));
}

#ifndef THINK_SILENTLY

/*
 * tw() -- indicate working when checking/generating primes
 */

#include <stdio.h>		/* only for tw() */

static void
tw(void)
{
	static ULONG j = 0;
	putchar("/-\\|"[j & 3]);
	j++;
	putchar('\b');
	fflush(stdout);
}

#endif /* THINK_SILENTLY */

/*
 * next_prime(N a) -- find next probable prime >= a
 */

void
next_prime(N a)
{
	NN b;
	*a |= 1;
	cl(b); *b = 2;
	for (;;) {
#ifndef THINK_SILENTLY
		tw();
#endif /* THINK_SILENTLY */
		if (!sieve_prime(a)) {
			if (prob_prime(a))
				return;
		}
		ad(a, b);
	}
}

/*
 * bits rsa_gen(rsa_key *key) -- generate a RSA key from key->p and key->q
 * Initialize key->p and key->q either with primes or strong random
 * integers of apporopriate size. Returns number of bits in modulus key->pq
 * or 0 if key generation failed.
 */

ULONG
rsa_gen(rsa_key *k)
{
	NN p1, q1, pq1, f, g, t;
	next_prime(k->p);
	next_prime(k->q);
	if (cu(k->p, k->q) < 0) {
		cp(t, k->p);
		cp(k->p, k->q);
		cp(k->q, t);
	}
	hn(t, "1");
	cp(p1, k->p);
	sb(p1, t);
	cp(q1, k->q);
	sb(q1, t);
	cp(g, p1);
	gd(g, q1);
	hn(t, "ff");
	if (cu(t, g) < 0)
		return 0;
	cp(k->pq, k->p);
	mu(k->pq, k->q);
	cp(pq1, p1);
	mu(pq1, q1);
	cp(f, pq1);
	dm(f, g, t);
	hn(k->e, "3");
	hn(k->qp, "1");
	cp(t, pq1);
	gd(t, k->e);
	if (cu(t, k->qp)) {
		hn(k->e, "10001");
		cp(t, pq1);
		gd(t, k->e);
		if (cu(t, k->qp))
			return 0;
	}
	cp(k->d, k->e);
	iv(k->d, f);
	cp(t, k->d);
	dm(t, p1, k->dp);
	cp(t, k->d);
	dm(t, q1, k->dq);
	cp(k->qp, k->q);
	iv(k->qp, k->p);
	cp(t, k->pq);
	for(k->b = 0; ts(t); sr(t), k->b++)
		; /* VOID */
	return (k->b);
}

/*
 * rsa_dec(N m, rsa_key *key) -- low level rsa decryption. Result undefined
 * (ie. wrong) if key is not private rsa key.
 */

void
rsa_dec(N m, rsa_key * k)
{
	NN mp, mq, t;
	cp(t, m);
	dm(t, k->p, mp);
	cp(t, m);
	dm(t, k->q,
	   mq);
	em(mp, k->dp, k->p);
	em(mq, k->dq, k->q);
	if (sb(mp, mq))
		ad(mp, k->p);
	mm(mp, k->qp,
	   k->p);
	mu(mp, k->q);
	ad(mp, mq);
	cp(m, mp);
}

/*
 * rsa_enc(N m, rsa_key *k) -- low level rsa encryption
 */

void
rsa_enc(N m, rsa_key * k)
{
	em(m, k->e, k->pq);
}

/*
 * len = n_to_b(unsigned char *buf, N a) -- convert a to bytes, most
 * significant byte first. Returns number of bytes written to buf. buf
 * should be large enough to hold sizeof(NN) bytes. (Note that number
 * is handled as unsigned, negative value converts to sizeof(NN) bytes.)
 * (XXX check portablility when converting to not-16/32 bit machine)
 */

ULONG
n_to_b(unsigned char *b, N a)
{
	ULONG i = RSA_SIZE - 1, l = 1;
	a += RSA_SIZE;
	while (!*--a && i)
		i--;
	if (*a > 255) {
		*b++ = *a >> 8;
		l++;
	}
	*b++ = *a;
	while (i--) {
		*b++ = *--a >> 8;
		*b++ = *a;
		l += 2;
	} 
	return (l);
}

/*
 * b_to_n(N a, unsigned char *buf,ULONG len) -- convert len bytes from
 * buf to value a. Conversion is unsigned, most significant byte first.
 * (XXX check portablility when converting to not-16/32 bit machine)
 */

void
b_to_n(N a, unsigned char *b, ULONG l)
{
	ULONG i;
	if (l > RSA_SIZE * sizeof(UWORD))
		l = RSA_SIZE * sizeof(UWORD);
	b += l;
	cl(a);
	i = l / 2;
	while (i--) {
		*a = *--b;
		*a++ |= (ULONG) *--b << 8;
	}
	if (l & 1)
		*a = *--b;
}

