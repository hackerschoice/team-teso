/* pack.c - burneye2 object to stub conversion
 *
 * by scut
 */


typedef struct {
	unsigned int	branch_id;
	unsigned int	branch_data;
	unsigned int	branch_data_len;

	unsigned int	keytab_idx;
} brinfo;

typedef struct {
	brinfo		brtrue;		/* also: brtransfer */
	brinfo		brfalse;	/* also: brstay */

	/* 7654.3210, 7 = link, 6 = cond, 5432 = condflags, 0 = return
	 */
#define	BRENT_M_LINK	0x80
#define	BRENT_LINK(flags)	((flags) & BRENT_M_LINK)
#define	BRENT_S_LINK(val)	((val) << 7)

#define	BRENT_M_COND	0x40
#define	BRENT_COND(flags)	((flags) & BRENT_M_COND)
#define	BRENT_S_COND(val)	((val) << 6)

#define	BRENT_M_CONDFLAGS	0x3c
#define	BRENT_CONDFLAGS(flags)	(((flags) & BRENT_M_CONDFLAGS) >> 2)
#define	BRENT_S_CONDFLAGS(val)	((val) << 2)

#define	BRENT_M_RETURN	0x01
#define	BRENT_RETURN(flags)	((flags) & BRENT_M_RETURN)
#define	BRENT_S_RETURN(val)	(val)

	unsigned char	flags;
} brent;


unsigned int	cur_bid;



