/* zodiac - advanced dns spoofer
 *
 * blowfish encryption routines, reference implementation
 *
 * by: (unknown, possible bruce schneier)
 * additions by random
 * slightly modified by scut
 */

#include <string.h>
#include "cipher-sha1.h"
#include "cipher-blowfish.h"
#include "cipher-blowfish-tab.h"
#include "common.h"

#define BOXES  3

/* #define S(x,i) (bf_S[i][x.w.byte##i])  */
#define S0(x) (bf_S[0][x.w.byte0])
#define S1(x) (bf_S[1][x.w.byte1])
#define S2(x) (bf_S[2][x.w.byte2])
#define S3(x) (bf_S[3][x.w.byte3])
#define bf_F(x) (((S0(x) + S1(x)) ^ S2(x)) + S3(x))
#define ROUND(a,b,n) (a.word ^= bf_F(b) ^ bf_P[n])

struct	box_t {
	UWORD_32bits *P;
	UWORD_32bits **S;
	char key[81];
	char keybytes;
} box[BOXES];

static void	blowfish_encipher (UWORD_32bits *xl, UWORD_32bits *xr);
static void	blowfish_decipher (UWORD_32bits *xl, UWORD_32bits *xr);
static void	blowfish_init (UBYTE_08bits *key, short keybytes, int bxtouse);


UWORD_32bits	*bf_P;
UWORD_32bits	**bf_S;


static void
blowfish_encipher (UWORD_32bits *xl, UWORD_32bits *xr)
{
	union aword	Xl;
	union aword	Xr;

	Xl.word = *xl;
	Xr.word = *xr;

	Xl.word ^= bf_P[0];
	ROUND (Xr, Xl, 1);
	ROUND (Xl, Xr, 2);
	ROUND (Xr, Xl, 3);
	ROUND (Xl, Xr, 4);
	ROUND (Xr, Xl, 5);
	ROUND (Xl, Xr, 6);
	ROUND (Xr, Xl, 7);
	ROUND (Xl, Xr, 8);
	ROUND (Xr, Xl, 9);
	ROUND (Xl, Xr, 10);
	ROUND (Xr, Xl, 11);
	ROUND (Xl, Xr, 12);
	ROUND (Xr, Xl, 13);
	ROUND (Xl, Xr, 14);
	ROUND (Xr, Xl, 15);
	ROUND (Xl, Xr, 16);
	Xr.word ^= bf_P[17];

	*xr = Xl.word;
	*xl = Xr.word;
}


static void
blowfish_decipher (UWORD_32bits *xl, UWORD_32bits *xr)
{
	union aword	Xl;
	union aword	Xr;

	Xl.word = *xl;
	Xr.word = *xr;

	Xl.word ^= bf_P[17];
	ROUND (Xr, Xl, 16);
	ROUND (Xl, Xr, 15);
	ROUND (Xr, Xl, 14);
	ROUND (Xl, Xr, 13);
	ROUND (Xr, Xl, 12);
	ROUND (Xl, Xr, 11);
	ROUND (Xr, Xl, 10);
	ROUND (Xl, Xr, 9);
	ROUND (Xr, Xl, 8);
	ROUND (Xl, Xr, 7);
	ROUND (Xr, Xl, 6);
	ROUND (Xl, Xr, 5);
	ROUND (Xr, Xl, 4);
	ROUND (Xl, Xr, 3);
	ROUND (Xr, Xl, 2);
	ROUND (Xl, Xr, 1);
	Xr.word ^= bf_P[0];

	*xl = Xr.word;
	*xr = Xl.word;
}


static void
blowfish_init (UBYTE_08bits *key, short keybytes, int bxtouse)
{
	int		i, j, bx;
	UWORD_32bits	data;
	UWORD_32bits	datal;
	UWORD_32bits	datar;
	union aword	temp;

	for (i = 0 ; i < BOXES ; i++)
		if (box[i].P != NULL) {
			if ((box[i].keybytes == keybytes) &&
				(strncmp ((char *) (box[i].key), (char *) key, keybytes) == 0))
			{
				bf_P = box[i].P;
				bf_S = box[i].S;

				return;
			}
		}

	bx = (-1);

	for (i = 0 ; i < BOXES ; i++) {
		if (box[i].P == NULL) {
			bx = i;
			i = BOXES + 1;
		}
	}

	if (bx < 0) {
		bx = bxtouse;
		free (box[bx].P);

		for (i = 0 ; i < 4 ; i++)
			free (box[bx].S[i]);

		free (box[bx].S);
	}

	box[bx].P = (UWORD_32bits *) malloc ((bf_N + 2) * sizeof (UWORD_32bits));
	box[bx].S = (UWORD_32bits **) malloc (4 * sizeof (UWORD_32bits *));

	for (i = 0 ; i < 4 ; i++)
		box[bx].S[i] = (UWORD_32bits *) malloc (256 * sizeof (UWORD_32bits));

	bf_P = box[bx].P;
	bf_S = box[bx].S;
	box[bx].keybytes = keybytes;
	strncpy (box[bx].key, key, keybytes);

	for (i = 0 ; i < bf_N + 2 ; i++)
		bf_P[i] = initbf_P[i];

	for (i = 0 ; i < 4 ; i++)
		for (j = 0 ; j < 256 ; j++)
			bf_S[i][j] = initbf_S[i][j];

	for (i = 0, j = 0; i < bf_N + 2; ++i) {
		temp.word = 0;
		temp.w.byte0 = key[j];
		temp.w.byte1 = key[(j + 1) % keybytes];
		temp.w.byte2 = key[(j + 2) % keybytes];
		temp.w.byte3 = key[(j + 3) % keybytes];
		data = temp.word;
		bf_P[i] = bf_P[i] ^ data;
		j = (j + 4) % keybytes;
	}

	datal = 0x00000000;
	datar = 0x00000000;

	for (i = 0 ; i < bf_N + 2 ; i += 2) {
		blowfish_encipher (&datal, &datar);

		bf_P[i] = datal;
		bf_P[i + 1] = datar;
	}

	for (i = 0 ; i < 4 ; ++i) {
		for (j = 0 ; j < 256 ; j += 2) {

			blowfish_encipher(&datal, &datar);

			bf_S[i][j] = datal;
			bf_S[i][j + 1] = datar;
		}
	}
}


unsigned char *
bf_encipher (char *keyphrase, unsigned char *data, size_t data_len, size_t *result_len)
{
	UWORD_32bits		left, right;	/* blowfish halfs */
	unsigned long int	dp_i;		/* data pointer relative */
	unsigned char		key[20];	/* hash used as bf key */
	unsigned char		*data_enc,
				*dp;
	unsigned char		*sp,
				*source;
	long int		do_count;

	/* build a strong hash out of a weak keyphrase
	 */
	SHA1Hash (keyphrase, key);
	blowfish_init (key, sizeof (key), 0);

	sp = source = xcalloc (1, data_len + (8 - (data_len % 8)) + 1);
	memcpy (source, data, data_len);
	dp = data_enc = xcalloc (1, data_len + 9);

	do_count = data_len / 8;
	if ((data_len % 8) != 0)
		do_count += 1;

	*result_len = do_count * 8;

	for (dp_i = 0 ; dp_i < do_count ; ++dp_i) {
		left = ((*sp++) << 24);
		left |= ((*sp++) << 16);
		left |= ((*sp++) << 8);
		left |= (*sp++);
		right = ((*sp++) << 24);
		right |= ((*sp++) << 16);
		right |= ((*sp++) << 8);
		right |= (*sp++);

		blowfish_encipher (&left, &right);
		*dp++ = (right & 0xff000000) >> 24;
		*dp++ = (right & 0x00ff0000) >> 16;
		*dp++ = (right & 0x0000ff00) >> 8;
		*dp++ = (right & 0x000000ff);
		*dp++ = (left & 0xff000000) >> 24;
		*dp++ = (left & 0x00ff0000) >> 16;
		*dp++ = (left & 0x0000ff00) >> 8;
		*dp++ = (left & 0x000000ff);
	}

	free (source);

	return (data_enc);
}


unsigned char *
bf_decipher (char *keyphrase, unsigned char *data, size_t data_len)
{
	UWORD_32bits		left, right;	/* blowfish halfs */
	unsigned long int	dp_i;		/* data pointer relative */
	unsigned char		key[20];	/* hash used as bf key */
	unsigned char		*data_dec,
				*dp;
	unsigned char		*sp;
	long int		do_count;

	/* sanity checking
	 */
	if ((data_len % 8) != 0)
		return (NULL);

	/* build a strong hash out of a weak keyphrase
	 */
	SHA1Hash (keyphrase, key);
	blowfish_init (key, sizeof (key), 0);

	sp = data;
	dp = data_dec = xcalloc (1, data_len);

	do_count = data_len / 8;

	for (dp_i = 0 ; dp_i < do_count ; ++dp_i) {
		right = ((*sp++) << 24);
		right |= ((*sp++) << 16);
		right |= ((*sp++) << 8);
		right |= (*sp++);
		left = ((*sp++) << 24);
		left |= ((*sp++) << 16);
		left |= ((*sp++) << 8);
		left |= (*sp++);

		blowfish_decipher (&left, &right);

		*dp++ = (left & 0xff000000) >> 24;
		*dp++ = (left & 0x00ff0000) >> 16;
		*dp++ = (left & 0x0000ff00) >> 8;
		*dp++ = (left & 0x000000ff);
		*dp++ = (right & 0xff000000) >> 24;
		*dp++ = (right & 0x00ff0000) >> 16;
		*dp++ = (right & 0x0000ff00) >> 8;
		*dp++ = (right & 0x000000ff);
	}

	return (data_dec);
}


