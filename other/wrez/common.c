
#ifndef	COMMON_C
#define	COMMON_C

#ifndef NULL
#define NULL	((void *) 0)
#endif


static inline void
memcpy (void *dst, void *src, unsigned int len)
{
	__asm__ __volatile__ ("
		cld
		rep movsb
		" : : "c" (len), "S" (src), "D" (dst));
}


static inline int
memcmp (unsigned char *s1, unsigned char *s2, unsigned int len)
{
	register unsigned int	reg_ecx;

	__asm__ __volatile__ ("
		cld
		repe cmpsb
		je	lme
		incl	%%ecx
	lme:
		" : "=c" (reg_ecx) : "c" (len), "S" (s1), "D" (s2));

	return (reg_ecx);
}


static inline void
memset (void *dst, unsigned char wrbyte, unsigned int len)
{
	__asm__ __volatile__ ("
		cld
		rep stosb
		" : : "c" (len), "D" (dst), "a" (wrbyte));
}


static inline int
strcmp (unsigned char *s1, unsigned char *s2)
{
	register unsigned int	reg_ecx;

	__asm__ __volatile__ ("
		xorl	%%ecx, %%ecx
		xorl	%%eax, %%eax
		pushl	%%esi
		cld
	ls0:	lodsb
		incl	%%ecx
		or	%%eax, %%eax
		jnz	ls0

		popl	%%esi
		repe	cmpsb
		" : "=c" (reg_ecx) : "S" (s1), "D" (s2) : "eax");

	return (reg_ecx);
}


static inline int
strlen (unsigned char *s1)
{
	register unsigned int	reg_ecx;

	__asm__ __volatile__ ("
		xorl	%%eax, %%eax
		movl	%%eax, %%ecx
		decl	%%ecx
		repne scasb
		not	%%ecx
		decl	%%ecx
		" : "=c" (reg_ecx) : "D" (s1) : "eax");

	return (reg_ecx);
}


#if 0
/* gcc's version is smaller, doh!
 */
static inline int
strstr (unsigned char *s1_hay, unsigned char *s2_needle)
{
	register unsigned int	reg_ecx;

	__asm__ __volatile__ ("
		xorl	%%ecx, %%ecx
	lss_%=:	movb	(%%esi), %%al
		orb	%%al, %%al
		jz	lso_%=
		pushl	%%esi
		pushl	%%edi
	ls0_%=:	cmpsb
		jne	ls1_%=
		cmpb	$0x0, (%%edi)
		je	lse_%=
		jmp	ls0_%=
	ls1_%=:	popl	%%edi
		popl	%%esi
		incl	%%esi
		jmp	lss_%=
	lso_%=:	incl	%%ecx
	lse_%=:
		" : "=c" (reg_ecx) : "S" (s1_hay), "D" (s2_needle) : "eax");

}
#endif


static inline void
strcpy (unsigned char *dst, unsigned char *src)
{
	memcpy (dst, src, strlen (src) + 1);
}

#endif


