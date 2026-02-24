/* hashgen.c - burneye2 core hash function generator
 *
 * by scut
 */

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <string.h>

#include <common.h>
#include <hashgen.h>
#include <utility.h>


/*** static prototypes
 */

static ht_node *
ht_generate_neutral (unsigned int depth);

static void
ht_output_2 (FILE *fp, ht_node *root);

static unsigned char *
ht_eval_two (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data);

static unsigned char *
ht_eval_one (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data);

unsigned char *
ht_eval_zero (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data);

static unsigned int
ht_ndepth (unsigned int depth);

static unsigned int
ht_hspeedtest (unsigned char *func);

static unsigned int
ht_hfunctest (unsigned char *func, unsigned int hi, unsigned int lo);

static unsigned char *
ht_spill_simile_map (unsigned char *dst, unsigned int base,
	unsigned int a, unsigned int b, unsigned int c);

static unsigned char *
ht_map_inputspill (unsigned char *dst, void *sim_);

static unsigned int
simile_unmap_2 (unsigned int k, unsigned int m, unsigned int base,
	unsigned int i, unsigned int a, unsigned int b, unsigned int c);

static void
moment (unsigned int data[], int n, float *ave, float *adev, float *sdev,
	float *var, float *skew, float *curt);

#ifndef	OPTIMIZE
static float
sqrt (float f);
#endif

int	ht_gentab[] = { 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2 };

spill	ht_push_eax = { 1, (unsigned char *) "\x50" };
spill	ht_push_edx = { 1, (unsigned char *) "\x52" };
spill	ht_pop_edx = { 1, (unsigned char *) "\x5a" };
spill	ht_pop_eax = { 1, (unsigned char *) "\x58" };
spill	ht_xor_eax_edx = { 2, (unsigned char *) "\x31\xd0" };
spill	ht_add_eax_edx = { 2, (unsigned char *) "\x01\xd0" };
spill	ht_sub_eax_edx = { 2, (unsigned char *) "\x29\xd0" };
spill	ht_mul_eax_edx = { 2, (unsigned char *) "\xf7\xe2" };
spill	ht_xor_edx_edx = { 2, (unsigned char *) "\x31\xd2" };
spill	ht_div_eax_edx = { 2, (unsigned char *) "\xf7\xf2" };
spill	ht_div_eax_ebx = { 2, (unsigned char *) "\xf7\xf3" };
spill	ht_neg_eax = { 2, (unsigned char *) "\xf7\xd8" };
spill	ht_not_eax = { 2, (unsigned char *) "\xf7\xd0" };
spill	ht_rol_eax = { 2, (unsigned char *) "\xc1\xc0" };
spill	ht_ror_eax = { 2, (unsigned char *) "\xc1\xc8" };
spill	ht_mov_edx_eax = { 2, (unsigned char *) "\x89\xc2" };
spill	ht_mov_eax_imm32 = { 1, (unsigned char *) "\xb8" };
spill	ht_mov_eax_in = { 4, (unsigned char *) "\x89\xd8\x31\xc8" };
spill	ht_push_ebx = { 1, (unsigned char *) "\x53" };
spill	ht_pop_ebx = { 1, (unsigned char *) "\x5b" };

spill	ht_int3 = { 1, (unsigned char *) "\xcc" };
spill	ht_ret = { 1, (unsigned char *) "\xc3" };


spill *	ht_combine_eax_edx[] = { &ht_xor_eax_edx, &ht_add_eax_edx,
	&ht_sub_eax_edx };
#define	HT_COMBINE_MAX	3


ht_node *
ht_new (void)
{
	return (xcalloc (1, sizeof (ht_node)));
}


int	ht_gen_map_pair_tab[] = { HT_OP_NEG, HT_OP_NOT, HT_OP_ADD, HT_OP_SUB,
	HT_OP_XOR, HT_OP_ROL, HT_OP_ROR };
#define	HT_GEN_MAP_PAIR_MAX	7


void
ht_output (FILE *fp, ht_node *root, char *description)
{
	fprintf (fp, "digraph %s {\n", description != NULL ?
		description : "graph");

	ht_output_2 (fp, root);

	fprintf (fp, "}\n");

	return;
}


char *	ht_output_operstr[] = { "invalid", "imm", "in", "neg", "not",
	"rol", "ror", "add", "sub", "xor", "mul" };

static void
ht_output_2 (FILE *fp, ht_node *root)
{
	fprintf (fp, "\t\"0x%08x\" [ label = ", (unsigned int) root);
	fprintf (fp, "\"%s", ht_output_operstr[root->oper]);

	if (root->oper == HT_OP_IMM)
		fprintf (fp, " 0x%08x", root->imm);
	else if (root->oper == HT_OP_ROL || root->oper == HT_OP_ROR)
		fprintf (fp, " %d", root->imm & 0x0f);

	fprintf (fp, "\" ];\n");

	switch (ht_gentab[root->oper]) {
	case (0):
		break;
	case (2):
		fprintf (fp, "\t\"0x%08x\" -> \"0x%08x\";\n",
			(unsigned int) root, (unsigned int) root->n2);
		ht_output_2 (fp, root->n2);
	case (1):
		fprintf (fp, "\t\"0x%08x\" -> \"0x%08x\";\n",
			(unsigned int) root, (unsigned int) root->n1);
		ht_output_2 (fp, root->n1);
		break;
	}

	return;
}


void
ht_generate_map_pair (ht_node **root_enc, ht_node **root_dec,
	unsigned int depth)
{
	ht_node **	dec_in_ptr;
	ht_node *	new_enc;
	ht_node *	new_dec;


	*root_enc = ht_new ();
	(*root_enc)->oper = HT_OP_IN;
	*root_dec = ht_new ();
	(*root_dec)->oper = HT_OP_IN;

	dec_in_ptr = root_dec;

	for ( ; depth > 0 ; --depth) {
		new_enc = ht_new ();
		new_dec = ht_new ();

		new_enc->oper = ht_gen_map_pair_tab[be_random (HT_GEN_MAP_PAIR_MAX)];
		assert (new_enc->oper >= 0 && new_enc->oper <= 10);

		new_enc->imm = be_random (0xf0000000) + 0x10000000;

		switch (new_enc->oper) {
		case (HT_OP_NEG):
		case (HT_OP_NOT):
			new_enc->n1 = *root_enc;
			*root_enc = new_enc;

			new_dec->oper = new_enc->oper;
			new_dec->n1 = *dec_in_ptr;
			*dec_in_ptr = new_dec;

			if (dec_in_ptr == root_dec)
				*root_dec = new_dec;

			dec_in_ptr = &new_dec->n1;
			break;

		case (HT_OP_ROL):
		case (HT_OP_ROR):
			new_enc->n1 = *root_enc;
			*root_enc = new_enc;

			new_dec->oper = (new_enc->oper == HT_OP_ROL) ?
				HT_OP_ROR : HT_OP_ROL;
			new_dec->imm = new_enc->imm;
			new_dec->n1 = *dec_in_ptr;
			*dec_in_ptr = new_dec;

			if (dec_in_ptr == root_dec)
				*root_dec = new_dec;

			dec_in_ptr = &new_dec->n1;
			break;

		case (HT_OP_ADD):
		case (HT_OP_SUB):
			new_enc->n1 = *root_enc;
			*root_enc = new_enc;

			new_dec->oper = HT_OP_SUB;
			if (new_enc->oper == HT_OP_ADD)
				new_dec->n2 = *dec_in_ptr;
			else
				new_dec->n1 = *dec_in_ptr;

			*dec_in_ptr = new_dec;

			if (dec_in_ptr == root_dec)
				*root_dec = new_dec;


			if (new_enc->oper == HT_OP_ADD) {
				new_enc->n2 = ht_generate_neutral (3);
				new_dec->n1 = ht_clone (new_enc->n2);
				dec_in_ptr = &new_dec->n2;
			} else {
				new_enc->n2 = ht_generate_neutral (3);
				new_dec->n2 = ht_clone (new_enc->n2);
				dec_in_ptr = &new_dec->n1;
			}
			break;

		case (HT_OP_XOR):
			new_enc->n1 = *root_enc;
			*root_enc = new_enc;

			/* xor is fully symmetric
			 */
			new_dec->oper = new_enc->oper;
			new_dec->n1 = *dec_in_ptr;
			*dec_in_ptr = new_dec;

			if (dec_in_ptr == root_dec)
				*root_dec = new_dec;

			dec_in_ptr = &new_dec->n1;

			new_enc->n2 = ht_generate_neutral (3);
			new_dec->n2 = ht_clone (new_enc->n2);

			break;
		default:
			break;
		}
	}
}


static ht_node *
ht_generate_neutral (unsigned int depth)
{
	ht_node *	new;


	new = ht_new ();
	new->imm = be_random (0xf0000000) + 0x10000000;

	if (depth == 0) {
		new->oper = HT_OP_IMM;

		return (new);
	}

	new->oper = HT_OP_MUL;
	while (new->oper == HT_OP_MUL)
		new->oper = be_random (HT_OP_MAX - HT_OP_ONE) + HT_OP_ONE;

	new->n1 = ht_generate_neutral (ht_ndepth (depth));
	if (ht_gentab[new->oper] == 2)
		new->n2 = ht_generate_neutral (ht_ndepth (depth));

	return (new);
}


ht_node *
ht_clone (ht_node *root)
{
	ht_node *	new = ht_new ();


	memcpy (new, root, sizeof (ht_node));
	new->n1 = new->n2 = NULL;

	switch (ht_gentab[root->oper]) {
	case (0):
		break;
	case (2):
		new->n2 = ht_clone (root->n2);
	case (1):
		new->n1 = ht_clone (root->n1);
		break;
	default:
		break;
	}

	return (new);
}


unsigned char *
ht_eval (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data)
{
	/* zero operands
	 */
	if (node->n1 == NULL && node->n2 == NULL)
		return (ht_eval_zero (node, dst, inputspill, data));

	if (node->n1 != NULL && node->n2 == NULL)
		return (ht_eval_one (node, dst, inputspill, data));

	if (node->n1 != NULL && node->n2 != NULL)
		return (ht_eval_two (node, dst, inputspill, data));

	assert (0);

	return (NULL);
}


unsigned char *
ht_spill_fix (unsigned char *dst, spill *sp)
{
	memcpy (dst, sp->data, sp->len);
	
	return (dst + sp->len);
}


unsigned char *
ht_spill_imm8 (unsigned char *dst, unsigned int imm)
{
	dst[0] = imm & 0xff;

	return (dst + 1);
}


unsigned char *
ht_spill_imm32 (unsigned char *dst, unsigned int imm)
{
	dst[0] = imm & 0xff;
	dst[1] = (imm >> 8) & 0xff;
	dst[2] = (imm >> 16) & 0xff;
	dst[3] = (imm >> 24) & 0xff;

	return (dst + 4);
}


static unsigned char *
ht_eval_two (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data)
{
	dst = ht_eval (node->n1, dst, inputspill, data);
	dst = ht_spill_fix (dst, &ht_push_eax);
	dst = ht_eval (node->n2, dst, inputspill, data);
	dst = ht_spill_fix (dst, &ht_pop_edx);

	switch (node->oper) {
	case (HT_OP_ADD):
		dst = ht_spill_fix (dst, &ht_add_eax_edx);
		break;
	case (HT_OP_SUB):
		dst = ht_spill_fix (dst, &ht_sub_eax_edx);
		break;
	case (HT_OP_XOR):
		dst = ht_spill_fix (dst, &ht_xor_eax_edx);
		break;
	case (HT_OP_MUL):
		dst = ht_spill_fix (dst, &ht_mul_eax_edx);
		dst = ht_spill_fix (dst, ht_combine_eax_edx[node->imm % HT_COMBINE_MAX]);
		break;
#if 0
	case (HT_OP_DIV):
		dst = ht_spill_fix (dst, &ht_div_eax_edx);
		dst = ht_spill_fix (dst, &ht_xor_eax_edx);
		break;
#endif
	default:
		break;
	}

	return (dst);
}


static unsigned char *
ht_eval_one (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data)
{
	dst = ht_eval (node->n1, dst, inputspill, data);

	switch (node->oper) {
	case (HT_OP_NEG):
		dst = ht_spill_fix (dst, &ht_neg_eax);
		break;
	case (HT_OP_NOT):
		dst = ht_spill_fix (dst, &ht_not_eax);
		break;
	case (HT_OP_ROL):
		dst = ht_spill_fix (dst, &ht_rol_eax);
		dst = ht_spill_imm8 (dst, node->imm & 0x0f);
		break;
	case (HT_OP_ROR):
		dst = ht_spill_fix (dst, &ht_ror_eax);
		dst = ht_spill_imm8 (dst, node->imm & 0x0f);
		break;
	default:
		break;
	}

	return (dst);
}


unsigned char *
ht_eval_zero (ht_node *node, unsigned char *dst,
	unsigned char * (* inputspill)(unsigned char *, void *), void *data)
{
	switch (node->oper) {
	case (HT_OP_IMM):
		dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
		dst = ht_spill_imm32 (dst, node->imm);
		break;
	case (HT_OP_IN):
		if (inputspill == NULL) {
			dst = ht_spill_fix (dst, &ht_mov_eax_in);
			break;
		}

		dst = inputspill (dst, data);
		break;
	default:
		break;
	}

	return (dst);
}



static unsigned int
ht_ndepth (unsigned int depth)
{
	unsigned int	nd;


	if (depth == 0)
		return (0);

	nd = depth;
	nd -= 1;
	if (nd >= 3)
		nd -= be_random (2);

	return (nd);
}


void
ht_free (ht_node *root)
{
	if (root == NULL)
		return;

	ht_free (root->n1);
	ht_free (root->n2);
	free (root);

	return;
}


#if 0
/* used to debug double free's */
void
ht_check (ht_node *root)
{
	if (root->n2 != NULL)
		ht_check (root->n2);
	if (root->n1 != NULL)
		ht_check (root->n1);

	assert (root->oper >= 0 && root->oper <= 10);
}
#endif


unsigned int
ht_count (ht_node *root)
{
	unsigned int	subcount = 0;


	if (root->n2 != NULL)
		subcount = ht_count (root->n2);
	if (root->n1 != NULL)
		subcount += ht_count (root->n1);

	return (1 + subcount);
}


unsigned int
ht_count_in (ht_node *root)
{
	unsigned int	subcount = 0;


	if (root->n2 != NULL)
		subcount = ht_count_in (root->n2);
	if (root->n1 != NULL)
		subcount += ht_count_in (root->n1);

	if (root->oper == HT_OP_IN)
		return (1 + subcount);
	else
		return (subcount);
}


ht_node *
ht_generate (int depth)
{
	ht_node *	narr;
	unsigned int	ndepth;


	assert (depth > 0);

	narr = xcalloc (1, sizeof (ht_node));
	narr->imm = be_random (0xf0000000) + 0x10000000;

	if (depth == 1) {
		narr->oper = be_random (HT_OP_ONE - HT_OP_ZERO) + HT_OP_ZERO;

		return (narr);
	}

	narr->oper = be_random (HT_OP_MAX - HT_OP_ONE) + HT_OP_ONE;

	/* fill in subnodes
	 */
	ndepth = ht_ndepth (depth);
	narr->n1 = ht_generate (ndepth);
	if (ht_gentab[narr->oper] == 2) {
		ndepth = ht_ndepth (depth);
		narr->n2 = ht_generate (ndepth);
	}

	return (narr);
}


static unsigned char *
ht_map_inputspill (unsigned char *dst, void *sim_)
{
	simile_parameters *	sim = (simile_parameters *) sim_;

	return (ht_spill_simile_map (dst, sim->base, sim->a, sim->b, sim->c));
}


ht_map_pair *
ht_generate_map_strong (unsigned int level, unsigned int runs)
{
	unsigned int	n,
			trun;
	ht_node *	dec;
	ht_node *	enc;

	ht_node *	best_dec = NULL;
	ht_node *	best_enc = NULL;
	float		best_skew;
	simile_parameters	best_simdata;

	float		ave, adev, sdev, var, skew, curt;

	unsigned char	dbuf_enc[32768];
	unsigned char	dbuf_dec[32768];
	unsigned char *	dst;

	unsigned int	result1,
			result2;
	unsigned int	tarr[512];

	ht_map_pair *	mp;


	mp = xcalloc (1, sizeof (ht_map_pair));

	mp->simdata.base = 32;
	mp->simdata.a = be_random (0);
	mp->simdata.b = be_random (0);
	mp->simdata.c = be_random (0);

	for (n = 0 ; n < runs ; ++n) {
		ht_generate_map_pair (&enc, &dec, level);

		dst = ht_eval (enc, &dbuf_enc[0], ht_map_inputspill, &mp->simdata);
		dst = ht_spill_fix (dst, &ht_ret);

		dst = ht_eval (dec, &dbuf_dec[0], NULL, NULL);
		dst = ht_spill_fix (dst, &ht_ret);

		for (trun = 0 ; trun < (sizeof (tarr) / sizeof (tarr[0]));
			++trun)
		{
			result1 = ht_hfunctest (dbuf_enc, 0, trun);
			result2 = ht_hfunctest (dbuf_dec, 0, result1);

#if 0
			printf ("  map (0x%08x) = 0x%08x\n", trun, result1);
			printf ("unmap (0x%08x) = 0x%08x\n", result1, result2);
			printf (" sUnM (0x%08x) = 0x%08x\n", result2,
				simile_unmap (simdata.base, result2,
					simdata.a, simdata.b, simdata.c));
#endif
			result2 = simile_unmap (mp->simdata.base, result2,
				mp->simdata.a, mp->simdata.b, mp->simdata.c);

			assert (trun == result2);
			tarr[trun] = result1;
		}

		moment (tarr, sizeof (tarr) / sizeof (tarr[0]),
			&ave, &adev, &sdev, &var, &skew, &curt);

#if 0
		fprintf (stderr, "skew = %f, ave = %f, curt = %f\n", skew, ave, curt);
#endif
		if (ave <= 2000000000.0 || ave >= 2200000000.0 ||
			fabs (skew) >= 1.0)
		{
			;
		} else if (best_dec == NULL || fabs (skew) < best_skew) {
			if (best_dec != NULL) {
				ht_free (best_dec);
				ht_free (best_enc);
			}

			best_enc = enc;
			best_dec = dec;
			best_skew = fabs (skew);
			memcpy (&best_simdata, &mp->simdata,
				sizeof (best_simdata));
		}

		if (best_dec != dec) {
			ht_free (dec);
			ht_free (enc);
		}
	}

	if (best_dec == NULL) {
		fprintf (stderr, "no best decryptor found, doh\n");

		exit (EXIT_FAILURE);
	}

	memcpy (&mp->simdata, &best_simdata, sizeof (mp->simdata));

#ifdef	TESTING
	fprintf (stderr, "best: nodes = %d, skew = %f\n", ht_count (best_dec),
		best_skew);

	for (trun = 0 ; trun < 128 ; ++trun) {
		unsigned int	res_testing;

		if ((trun % 5) == 0)
			fprintf (stderr, "\n");

		res_testing = ht_hfunctest (dbuf_dec, 0, trun);
		res_testing = simile_unmap (mp->simdata.base, res_testing,
			mp->simdata.a, mp->simdata.b, mp->simdata.c);
		fprintf (stderr, " 0x%08x", res_testing);

		res_testing = ht_hfunctest (dbuf_enc, 0, res_testing);
		fprintf (stderr, " %3d", res_testing);
	}
	fprintf (stderr, "\n");
#endif

	dst = ht_eval (best_enc, &dbuf_enc[0],
		ht_map_inputspill, &mp->simdata);
	dst = ht_spill_fix (dst, &ht_ret);
	mp->map_func_len = dst - dbuf_enc;
	mp->map_func = xcalloc (1, mp->map_func_len);
	memcpy (mp->map_func, &dbuf_enc[0], mp->map_func_len);

	dst = ht_eval (best_dec, &dbuf_dec[0], NULL, NULL);
	dst = ht_spill_fix (dst, &ht_ret);
	mp->unmap_func_len = dst - dbuf_dec;
	mp->unmap_func = xcalloc (1, mp->unmap_func_len);
	memcpy (mp->unmap_func, &dbuf_dec[0], mp->unmap_func_len);

	return (mp);
}


unsigned int
ht_map_domap (ht_map_pair *mp, unsigned int in)
{
	return (ht_hfunctest (mp->map_func, 0, in));
}


unsigned int
ht_map_dounmap (ht_map_pair *mp, unsigned int out)
{
	unsigned int	interm;


	interm = ht_hfunctest (mp->unmap_func, 0, out);
	interm = simile_unmap (mp->simdata.base, interm,
		mp->simdata.a, mp->simdata.b, mp->simdata.c);


	return (interm);
}


ht_node *
ht_generate_hash_strong (unsigned int level, unsigned int runs)
{
	unsigned int	n;
	ht_node *	root;

	ht_node *	best = NULL;
	float		best_skew;

	unsigned int	testcount;
	unsigned int	tarr[64];
	float		ave, adev, sdev, var, skew, curt;

	unsigned char	dbuf[16384];
	unsigned char *	dst;


	for (n = 0 ; n < runs ; ++n) {
		root = ht_generate (level);

		dst = ht_eval (root, &dbuf[0], NULL, NULL);
		dst = ht_spill_fix (dst, &ht_ret);

		for (testcount = 0 ; testcount < 64 ; ++testcount)
			tarr[testcount] = ht_hfunctest (dbuf, testcount, 0);

		moment (tarr, 64, &ave, &adev, &sdev, &var, &skew, &curt);

		if (ht_count_in (root) <= 3 || ave <= 100.0 ||
			fabs (curt) >= 100.0 || fabs (skew) >= 1.0)
		{
			;
		} else if (best == NULL || fabs (skew) < best_skew) {
			if (best != NULL)
				ht_free (best);

			best = root;
			best_skew = fabs (skew);
		}

		if (best != root)
			ht_free (root);
	}

	return (best);
}


static unsigned char *
ht_spill_simile_map (unsigned char *dst, unsigned int base,
	unsigned int a, unsigned int b, unsigned int c)
{
	unsigned int	mod = 1 << base;


	if (base == 32)
		mod = 0;

	/* c * k */
	dst = ht_spill_fix (dst, &ht_mov_eax_in);
	dst = ht_spill_fix (dst, &ht_mov_edx_eax);
	dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
	dst = ht_spill_imm32 (dst, c);
	dst = ht_spill_fix (dst, &ht_mul_eax_edx);

	/* 2 * c * k */
	dst = ht_spill_fix (dst, &ht_mov_edx_eax);
	dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
	dst = ht_spill_imm32 (dst, 2);
	dst = ht_spill_fix (dst, &ht_mul_eax_edx);

	/* b + (2 * c * k) */
	dst = ht_spill_fix (dst, &ht_mov_edx_eax);
	dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
	dst = ht_spill_imm32 (dst, b);
	dst = ht_spill_fix (dst, &ht_add_eax_edx);

	/* edx = (b + (2 * c * k)) % mod */
	if (mod != 0) {
		dst = ht_spill_fix (dst, &ht_push_ebx);
		dst = ht_spill_fix (dst, &ht_push_eax);

		dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
		dst = ht_spill_imm32 (dst, mod);

		dst = ht_spill_fix (dst, &ht_push_eax);
		dst = ht_spill_fix (dst, &ht_pop_ebx);
		
		dst = ht_spill_fix (dst, &ht_pop_eax);
		dst = ht_spill_fix (dst, &ht_xor_edx_edx);
		dst = ht_spill_fix (dst, &ht_div_eax_ebx);
		dst = ht_spill_fix (dst, &ht_pop_ebx);
	} else {
		dst = ht_spill_fix (dst, &ht_mov_edx_eax);
	}
	dst = ht_spill_fix (dst, &ht_push_edx);

	/* (a + k) % mod */
	dst = ht_spill_fix (dst, &ht_mov_eax_in);
	dst = ht_spill_fix (dst, &ht_mov_edx_eax);
	dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
	dst = ht_spill_imm32 (dst, a);
	dst = ht_spill_fix (dst, &ht_add_eax_edx);

	if (mod != 0) {
		dst = ht_spill_fix (dst, &ht_push_ebx);
		dst = ht_spill_fix (dst, &ht_push_eax);

		dst = ht_spill_fix (dst, &ht_mov_eax_imm32);
		dst = ht_spill_imm32 (dst, mod);

		dst = ht_spill_fix (dst, &ht_push_eax);
		dst = ht_spill_fix (dst, &ht_pop_ebx);
		
		dst = ht_spill_fix (dst, &ht_pop_eax);
		dst = ht_spill_fix (dst, &ht_xor_edx_edx);
		dst = ht_spill_fix (dst, &ht_div_eax_ebx);
		dst = ht_spill_fix (dst, &ht_pop_ebx);
	} else {
		dst = ht_spill_fix (dst, &ht_mov_edx_eax);
	}
	dst = ht_spill_fix (dst, &ht_pop_eax);
	dst = ht_spill_fix (dst, &ht_xor_eax_edx);

	return (dst);
}


unsigned int
simile_map (unsigned int base, unsigned int k, unsigned int a, unsigned int b,
	unsigned int c)
{
	unsigned int	mod;


	assert (base >= 1 && base <= 32);
	if (base == 32)
		mod = 0;
	else
		mod = 1 << base;

	if (mod == 0)
		return ((a + k) ^ (b + (2 * c * k)));

	return (((a + k) % mod) ^ ((b + (2 * c * k)) % mod));
}


unsigned int
simile_unmap (unsigned int base, unsigned int i, unsigned int a,
	unsigned int b, unsigned int c)
{
	unsigned int	n;
	unsigned int	kbits[32];
	unsigned int	k = 0;


	for (n = 0 ; n < base ; ++n) {
		kbits[n] = simile_unmap_2 (k, n, base, i, a, b, c);
		k |= kbits[n] << n;
	}

	return (k);
}


static unsigned int
simile_unmap_2 (unsigned int k, unsigned int m, unsigned int base,
	unsigned int i, unsigned int a, unsigned int b, unsigned int c)
{
	unsigned int	ret,
			mask,
			mod1;


	/* termination case
	 */
	if (m == 0)
		return ((i & 0x01) ^ (a & 0x01) ^ (b & 0x01));

	mask = 1 << m;
	if (m == 31)
		mod1 = 0;
	else
		mod1 = 1 << (m + 1);

	if (mod1 == 0) {
		ret = (i & mask) >> m;
		ret ^= (a + k ) >> m;
		ret ^= (b + (c * (k << 1))) >> m;
		ret &= 0x01;

		return (ret);
	}

	ret = (i & mask) >> m;
	ret ^= ((a % mod1) + (k % mod1)) >> m;
	ret ^= ((b % mod1) + ((c % mod1) * ((k << 1) % mod1))) >> m;
	ret &= 0x01;

	return (ret);
}


#ifdef	TESTING


int
main (int argc, char *argv[])
{
	ht_node *	hash;
	ht_map_pair *	hmp;

#if 0
	unsigned int	n;
	unsigned int	rnd_a, rnd_b, rnd_c;
	unsigned int	sim[64];

	unsigned char	code[256];
	unsigned char *	dst;


	be_randinit ();

	rnd_a = be_random (0);
	rnd_b = be_random (0);
	rnd_c = be_random (0);
	printf ("rnd_a = %u, rnd_b = %u, rnd_c = %u\n", rnd_a, rnd_b, rnd_c);

	for (n = 0 ; n < 64 ; ++n) {
		sim[n] = simile_map (32, n, rnd_a, rnd_b, rnd_c);
		if (n % 8 == 0)
			printf ("\n");
		printf (" 0x%08x", sim[n]);
	}
	printf ("\n");

	memset (code, 0x00, sizeof (code));
	dst = ht_spill_simile_map (&code[0], 32, rnd_a, rnd_b, rnd_c);
	dst = ht_spill_fix (dst, &ht_ret);

	for (n = 0 ; n < 64 ; ++n) {
		if (n % 8 == 0)
			printf ("\n");

		printf (" 0x%08x", ht_hfunctest (&code[0], 0, n));
	}
	printf ("\n");

	for (n = 0 ; n < 64 ; ++n) {
		if (simile_unmap (32, sim[n], rnd_a, rnd_b, rnd_c) != n) {
			printf ("fatal on index %u, with a = %u, b = %u, "
				"c = %u\n", n, rnd_a, rnd_b, rnd_c);
		}
	}

//	exit (EXIT_SUCCESS);
#endif


	hmp = ht_generate_map_strong (16, 512);

	hash = ht_generate_hash_strong (16, 512);
	ht_free (hash);

	exit (EXIT_SUCCESS);
}


static unsigned int
ht_hfunctest (unsigned char *func, unsigned int hi, unsigned int lo)
{
	unsigned int	result;

	__asm__ __volatile__ (
		"call	*%%eax\n"
		: "=a" (result)
		: "0" (func), "b" (lo), "c" (hi)
		: "dx");

	return (result);
}


/* return hashes performed per second
 */
static unsigned int
ht_hspeedtest (unsigned char *func)
{
	unsigned long long int	n;
	struct timeval	tv_start,
			tv_end;
	long long int	tvs,
			tve;

	gettimeofday (&tv_start, NULL);
	for (n = 0 ; n < 1000000 ; ++n)
		ht_hfunctest (func, n + 1, n);

	gettimeofday (&tv_end, NULL);
	tvs = (tv_start.tv_sec * 1000000) + tv_start.tv_usec;
	tve = (tv_end.tv_sec * 1000000) + tv_end.tv_usec;
	tve -= tvs;

	return ((n * 1000000) / tve);
}


static void
moment (unsigned int data[], int n, float *ave, float *adev, float *sdev,
	float *var, float *skew, float *curt)
{
	int	j;
	float	ep = 0.0,
		s = 0.0,
		p;


	if (n <= 1)
		return;

	for (j = 0 ; j < n ; ++j)
		s += data[j];
	*ave = s / (n + 1);
	
	*adev = (*var) = (*skew) = (*curt) = 0.0;
	for (j = 0 ; j < n ; ++j) {
		*adev += fabs (s = data[j] - (*ave));
		ep += s;
		*var += (p = s * s);
		*skew += (p *= s);
		*curt += (p *= s);
	}

	*adev /= n;
	*var = (*var - ep*ep/n) / (n - 1);
	*sdev = sqrt (*var);
	if (*var) {
		*skew /= (n * (*var) * (*sdev));
		*curt = (*curt) / (n * (*var) * (*var)) - 3.0;
	}
}


#ifndef	OPTIMIZE
static float
sqrt (float f)
{
	if (f <= 0.0)
		return (0.0);

	__asm__ __volatile__ (
		"fsqrt"
		:"=t" (f)
		: "0" (f));

	return (f);
}
#endif

#endif



