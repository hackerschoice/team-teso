/* hashgen.c - burneye2 core hash function generator, include file
 *
 * by scut
 */

#ifndef	HASHGEN_H
#define	HASHGEN_H


typedef struct ht_node {
#define	HT_OP_INVALID	0
	/* zero operands: _OP_IMM */
#define	HT_OP_ZERO	1
#define	HT_OP_IMM	1
#define	HT_OP_IN	2
	/* one operands: _OP_NEG, _OP_NOT */
#define	HT_OP_ONE	3
#define	HT_OP_NEG	3
#define	HT_OP_NOT	4
#define	HT_OP_ROL	5
#define	HT_OP_ROR	6
	/* two operands: */
#define	HT_OP_TWO	7
#define	HT_OP_ADD	7
#define	HT_OP_SUB	8
#define	HT_OP_XOR	9
#define	HT_OP_MUL	10
#define	HT_OP_MAX	11
	int		oper;
	unsigned int	imm;

	struct ht_node *	n1;
	struct ht_node *	n2;
} ht_node;


typedef struct {
	unsigned int	len;
	unsigned char *	data;
} spill;


typedef struct {
	unsigned int	base;
	unsigned int	a;
	unsigned int	b;
	unsigned int	c;
} simile_parameters;



typedef struct {
	/* the mapping function is available as raw machine code
	 */
	unsigned char *		map_func;
	unsigned int		map_func_len;

	/* the demap function is partly available as machine code, part is
	 * done with the simile_unmap function.
	 */
	unsigned char *		unmap_func;
	unsigned int		unmap_func_len;

	simile_parameters	simdata;
} ht_map_pair;


/* ht_new
 *
 * create a new ht_node structure
 *
 * return pointer to new structure
 */

ht_node *
ht_new (void);


/* ht_eval
 *
 * evaluate a node tree `node' and compile to `dst'. if `inputspill' is
 * non-NULL, it is used to generate the input functionality, and called by
 * inputspill (dst, data);
 *
 * return pointer to byte after compiled code
 */

unsigned char *
ht_eval (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data);


/* ht_spill_fix
 *
 * spill a fixed byte sequence `sp' to `dst'.
 *
 * return pointer after last spilled byte
 */

unsigned char *
ht_spill_fix (unsigned char *dst, spill *sp);


/* ht_spill_imm32
 *
 * spill 32 bit immediate value `imm' to `dst'
 * _imm8 is the same, but spills an 8 bit value.
 *
 * return pointer after last spilled byte
 */

unsigned char *
ht_spill_imm32 (unsigned char *dst, unsigned int imm);

unsigned char *
ht_spill_imm8 (unsigned char *dst, unsigned int imm);


/* ht_generate
 *
 * generate a hash function tree with `depth' levels
 *
 * return root node of hashtree.
 */

ht_node *
ht_generate (int depth);


/* ht_free
 *
 * free a tree starting from `root'.
 *
 * return in any case
 */

void
ht_free (ht_node *root);


/* ht_count
 *
 * count number of unique nodes in tree starting at `root'.
 *
 * return number of nodes counted
 */

unsigned int
ht_count (ht_node *root);


/* ht_count_in
 *
 * count number of input nodes in tree starting at `root'.
 *
 * return number of input nodes counted
 */

unsigned int
ht_count_in (ht_node *root);


/* ht_generate_map_pair
 *
 * generate a mapping function pair to `*root_enc' and `*root_dec' whose tree
 * is approximatly depth items long.
 *
 * return in any case (pointers have been changed in any case)
 */

void
ht_generate_map_pair (ht_node **root_enc, ht_node **root_dec,
	unsigned int depth);


/* ht_generate_map_strong
 *
 * generate strong property mapping function (as strong as this simple stuff
 * allows it to become). the coders are roughly `level' treenodes deep and
 * there are `runs' coders generated from which the strongest is selected.
 * roughly, what you want is a level between 10 and 20 and runs ranging from
 * 1000 to 10000.
 *
 * return ht_map_pair structure on success
 */

ht_map_pair *
ht_generate_map_strong (unsigned int level, unsigned int runs);


/* ht_generate_hash_strong
 *
 * generate a strong property hashing function (64 bit to 32 bit). the hash
 * function is roughly `level' treenodes deep and `runs' functions are
 * generated from which the strongest is selected.
 *
 * return the root node of the hash function on success
 */

ht_node *
ht_generate_hash_strong (unsigned int level, unsigned int runs);


/* ht_clone
 *
 * deep clone an entire hashtree starting from `root'.
 *
 * return cloned tree root node
 */

ht_node *
ht_clone (ht_node *root);


/* ht_output
 *
 * output a graphviz .dot file directed graph to file pointer `fp', starting
 * with tree root node `root' and use `description' as graph name.
 *
 * return in any case
 */

void
ht_output (FILE *fp, ht_node *root, char *description);


/* simile_map
 *
 * map with the simile function, `base' is anything between 1 and 32, `a', `b'
 * and `c' are constants within the range 0 to 2^(base-1), `k' is the index we
 * want to hash, also in the range from 0 to 2^(base-1).
 *
 * return index i(k)
 */

unsigned int
simile_map (unsigned int base, unsigned int k, unsigned int a, unsigned int b,
	unsigned int c);


/* simile_unmap
 *
 * reverse map with the simile function. parameters the same as for
 * 'simile_map', but `i' is the reversed index now.
 *
 * return index k(i)
 */

unsigned int
simile_unmap (unsigned int base, unsigned int i, unsigned int a,
	unsigned int b, unsigned int c);


/* ht_map_domap
 *
 * map through `mp': out = map (in)
 *
 * return out
 */

unsigned int
ht_map_domap (ht_map_pair *mp, unsigned int in);


/* ht_map_dounmap
 *
 * unmap through `mp', in = unmap (out)
 *
 * return in
 */

unsigned int
ht_map_dounmap (ht_map_pair *mp, unsigned int out);


#endif


