/* gramble - gammar ramble
 *
 * team teso
 *
 * input functions include file
 */

#ifndef	GRAMBLE_INPUT_H
#define	GRAMBLE_INPUT_H

int yyerror (char *str);
int yywrap (void);
int in_yyinput (char *buf, int size_max);
void *in_parse (char *buf, int buf_len);

#endif

