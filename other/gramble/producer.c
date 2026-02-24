/* gramble - grammar ramble
 * production engine for grammar derivations
 *
 * -scut
 */


/* we use a pushdown ntm like construct to generate valid derivations of the
 * original grammar.
 */


/* terminal structure
 *
 * a simple word consisting of characters
 */
typedef struct {
	unsigned int	word_len;	/* length, not including NUL */
	unsigned char *	word;		/* if word_Len > 0: must be non-NULL */
} terminal;


/* nonterminal structure
 *
 * contains 'plist', a pointer to a production list of that nonterminal
 */
typedef struct {
	unsigned int	pcount;	/* number of productions for that nterm */
	symbol **	plist;	/* list of productions for that nonterminal */
} nonterminal;


/* symbol structure
 *
 * shared linked list of symbols consisting of terminals and nonterminals.
 * `next' being NULL marks the end of the derivation. `prev' being NULL marks
 * the first.
 * exactly one of `term' or `nterm' has to be non-NULL and point to a valid
 * structure.
 */
typedef struct symbol {
	symbol *	prev;
	symbol *	next;
	terminal *	term;
	nonterminal *	nterm;
} symbol;


/* prod_genstatement
 *
 * derive a nonterminal completely to nonterminals. stop when the output
 * buffer `obuf' has been filled with `obuf_len' bytes or when there are
 * no more nonterminals to derive. start to derive from nonterminal `step'.
 *
 * return number of terminal characters derived on success
 * return -1 on failure
 */

unsigned int
prod_genstatement (nonterminal *step,
	unsigned char *obuf, unsigned long int obuf_len)
{
	unsigned int	produced = 0,
			sub_produced = 0;
	unsigned int	psel;	/* production selector */
	symbol *	prod;	/* production to use */


	if (obuf_len == 0)
		return (0);

	/* TODO: choose a more custom selection over a random pick
	 */
	psel = random_get (0, step->pcount - 1);

	for (prod = start->plist[psel] ; prod != NULL ; prod = prod->next) {

		/* terminals */
		if (prod->term != NULL) {
			if (prod->term->word_len < obuf_len) {
				memcpy (obuf, prod->term->word,
					prod->term->word_len);
				obuf += prod->term->word_len;
				obuf_len -= prod->term->word_len;
				produced += prod->term->word_len;
			} else	/* no room left :-( */
				return (produced);

		/* non-terminals */
		} else if (prod->nterm != NULL) {

			sub_produced = prod_genstatement (prod->nterm,
				obuf, obuf_len);
			obuf += sub_produced;
			obuf_len -= sub_produced;
		}
	}

	/* finished deriving */
	return (produced);
}


