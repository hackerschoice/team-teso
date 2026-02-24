
/* shellcode.h - shellcode structure and function definitions
 *
 * team teso
 */

#ifndef	SHELLCODE_H
#define	SHELLCODE_H


/* (nop_gen) function type which will generate a nop space:
 * parameters: unsigned char *dest, unsigned int dest_len
 *
 * will generate no more than dest_len bytes of nop space. the length
 * is rounded down to a multiple of arch_codelen, so for risc archs be
 * sure dest_len % arch_codelen is zero
 *
 * return the number of nop bytes generated (not the instruction count)
 *
 * XXX: name your functions <arch>_nop
 */
typedef unsigned int (* nop_gen)(unsigned char *, unsigned int,
	unsigned char *, int);

/* helper macro to set individual bits
 */
#define	BSET(dest, len, val, bw) { \
	dest &= ~(((unsigned char) ~0) >> bw);	/* clear lower bits */ \
	dest |= val << (8 - bw - len);		/* set value bits */ \
	bw += len; \
}


typedef struct {
	char *		code_string;	/* description string of the code */
	unsigned int	code_len;	/* length of code in bytes */
	unsigned char *	code;		/* code byte array */
} shellcode;


typedef struct {
	char *		arch_string;	/* description string of this arch */
	unsigned int	arch_codelen;	/* minimum instruction length */
	nop_gen		arch_nop;	/* nop space generation function */
	shellcode **	arch_codes;	/* shellcode array for this arch */
} arch;


unsigned long int
random_get (unsigned long int low, unsigned long int high);

void
random_init (void);

int
bad (unsigned char u);

int
badstr (unsigned char *code, int code_len, unsigned char *bad, int bad_len);

#endif

