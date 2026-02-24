
	BITS 32

	org	0x08048000

ehdr:					; Elf32_Ehdr
	db      0x7F, "ELF", 1, 1, 1	;  e_ident
	times 9	db	0
	dw	2			;  e_type
	dw	3			;  e_machine
	dd	1			;  e_version
	dd	_start			;  e_entry
	dd	phdr - $$		;  e_phoff
	dd	0			;  e_shoff
	dd	0			;  e_flags
	dw	ehdrsize		;  e_ehsize
	dw	phdrsize		;  e_phentsize
	dw	1			;  e_phnum
	dw	0			;  e_shentsize
	dw	0			;  e_shnum
	dw	0			;  e_shstrndx

ehdrsize	equ	($ - ehdr)

phdr:				; Elf32_Phdr
	dd	1		;  p_type
	dd	0		;  p_offset
	dd	$$		;  p_vaddr
	dd	$$		;  p_paddr
	dd	filesize	;  p_filesz
	dd	filesize	;  p_memsz
	dd	7		;  p_flags
	dd	0x1000		;  p_align

phdrsize	equ	($ - phdr)

prefixarr	db	0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x67, 0xf2, 0xf3
prefixlen	dd	9

; fd 0 = random file
; fd 1 = output file
_start:

	db	0x3e
	db	0x26
	db	0x64
	db	0x65
	db	0x67
	db	0x36
	db	0x2e
	db	0xf3
	db	0xf2
	pushf

; WORKS
;	db	0x3e
;	pushf

; WORKS
;	db	0x26
;	pushf

; WORKS
;	db	0x64
;	pushf

; WORKS
;	db	0x65
;	pushf

; WORKS, pulls lower 16 bits only
;	db	0x66
;	pushf

; WORKS
;	db	0x67
;	pushf

; WORKS
;	db	0x36
;	pushf

; WORKS
;	db	0x2e
;	pushf

; WORKS
;	db	0xf3
;	pushf

; WORKS
;	db	0xf2
;	pushf

; SIGILL
;	db	0xf0
;	popf

	int3

filesize	equ	($ - $$)


