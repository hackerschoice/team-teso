/* initial infector link description */

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH("i386")

ENTRY(wrez_init)

PHDRS
{
	text PT_LOAD FILEHDR PHDRS FLAGS (0x0007);	/* PF_R | PF_W | PF_X */
	data PT_LOAD FLAGS (0x0006);			/* PF_R | PF_W */
}

SECTIONS
{
	. = 0x06660000 ;
	.text : {
		wrez.o(.text)
		wrcore.o(.text)
#ifdef	POLYMORPHISM
		lime-interface.o(.text)
		lime.o(.text)
#endif
#ifdef	LOOKUP
		lookup.o(.text)
#endif
#ifdef	INMEM
		inmem.o(.text)
#endif
#ifdef	FINGERPRINT
		fingerprint.o(.text)
		crypto.o(.text)
#endif
		*(.text)
		*(.rodata)
		*(.data)
	} : text

	/* save calls to objcopy, huh */
	/DISCARD/ : {
		*(.bss)
		*(.eh_frame)
		*(.comment)
		*(.note)
	}
}
