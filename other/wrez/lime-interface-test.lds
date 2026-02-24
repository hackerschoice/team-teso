
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)

ENTRY(main)

PHDRS
{
	text PT_LOAD FILEHDR PHDRS FLAGS (0x0007);	/* PF_R | PF_W | PF_X */
	data PT_LOAD FLAGS (0x0006);			/* PF_R | PF_W */
}

SECTIONS
{
	. = 0x06660000 ;
	.text : {
		lime-interface-test.o(.text)
		lime-interface.o(.text)
		lime.o(.text)
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
