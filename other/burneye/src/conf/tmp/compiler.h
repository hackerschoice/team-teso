/* fornax - distributed network
 *
 * by team teso
 *
 * compiler include file
 */

#ifndef	FNX_COMPILER_H
#define	FNX_COMPILER_H

int		yyerror (char *str);
int		yywrap (void);
element **	cp_compile (char *buf, int buf_len);
int		cp_yyinput (char *buf, int size_max);

#endif


