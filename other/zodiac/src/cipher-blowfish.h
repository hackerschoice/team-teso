#ifndef _H_BLOWFISH
#define _H_BLOWFISH

#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define MAXKEYBYTES	56          /* 448 bits */
#define bf_N		16
#define noErr		0
#define DATAERROR	-1
#define KEYBYTES	8

#define UBYTE_08bits	unsigned char
#define UWORD_16bits	unsigned short

#define nmalloc(x) n_malloc((x),__FILE__,__LINE__)

#define SIZEOF_INT 4
#define SIZEOF_LONG 4

#if SIZEOF_INT==4
#  define UWORD_32bits  unsigned int
#else
#  if SIZEOF_LONG==4
#  define UWORD_32bits  unsigned long
#  endif
#endif

/* choose a byte order for your hardware */

#ifdef WORDS_BIGENDIAN
/* ABCD - big endian - motorola */
union aword {
	UWORD_32bits	word;
	UBYTE_08bits	byte[4];

	struct {
		unsigned int	byte0:8;
		unsigned int	byte1:8;
		unsigned int	byte2:8;
		unsigned int	byte3:8;
	} w;
};
#endif  /* WORDS_BIGENDIAN */

#ifndef WORDS_BIGENDIAN
/* DCBA - little endian - intel */
union aword {
	UWORD_32bits	word;
	UBYTE_08bits	byte[4];

	struct {
		unsigned int	byte3:8;
		unsigned int	byte2:8;
		unsigned int	byte1:8;
		unsigned int	byte0:8;
	} w;
};
#endif  /* !WORDS_BIGENDIAN */


/* bf_encipher
 *
 * safely encrypt a sequenced byte block pointed to by `data' with length
 * `data_len'. as encryption key a hash build out of an asciiz string
 * `keyphrase' is used. the length of the resulting data block is
 * stored in the variable pointed to by `result_len'.
 *
 * return a pointer to a new allocated encrypted data block
 */

unsigned char	*bf_encipher (char *keyphrase, unsigned char *data,
	size_t data_len, size_t *result_len);


/* bf_decipher
 *
 * decrypt a blowfish encrypted data block pointed to by `data'. as key use a
 * hash value build out of the asciiz string `keyphrase'. the data block is
 * `data_len' bytes in length and must be padded to an 8 byte boundary.
 *
 * return NULL on failure (boundary error)
 * return a pointer to a new allocated decrypted data block
 */

unsigned char	*bf_decipher (char *keyphrase, unsigned char *data,
	size_t data_len);


#endif


