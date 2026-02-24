#define	TTYADD(c)	{ if (!(SYNCHing||flushout)) ttyoring.putch(c); }
#define	TTYBYTES()	(ttyoring.full_count())
#define	TTYROOM()	(ttyoring.empty_count())

void tlink_init(void);

void EmptyTerminal(void);


int tlink_getifd(void);
int tlink_getofd(void);
