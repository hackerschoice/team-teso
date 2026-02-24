
; LDE32 -- Length-Disassembler Engine
; FREEWARE
;
; programmed by Z0MBiE, http://z0mbie.cjb.net
;
; release 1.00          8-12-99
; release 1.01          9-12-99
; release 1.02         17-03-00  0xF6/0xF7 'test' opcode bugfixed
; release 1.03         21-04-00  bugfix: some prefixes before 0F were cleared
;                                bugfix: error in MODRM analysis
;                                CD 20 now is 6 bytes length
; release 1.04          1-05-00  AAM & AAD bugfixed (was 1-byte len)
; release 1.05         xx-xx-xx  special edition, flags changed
; release 1.06          3-01-01  partially rewritten, __cdecl

; some very small mods/changes by scut to compile under nasm


C_ERROR		equ	-1              ; never change it

C_MEM1		equ	0x0001       ; |
C_MEM2		equ	0x0002       ; |may be used simultaneously
C_MEM4		equ	0x0004       ; |
C_DATA1		equ	0x0100       ; |
C_DATA2		equ	0x0200       ; |may be used simultaneously
C_DATA4		equ	0x0400       ; |
C_67		equ	0x0010       ; used with C_PREFIX
C_MEM67		equ	0x0020       ; C_67 ? C_MEM2 : C_MEM4
C_66		equ	0x1000       ; used with C_PREFIX
C_DATA66	equ	0x2000       ; C_66 ? C_DATA2 : C_DATA4
C_PREFIX	equ	0x0008       ; prefix. take opcode again
C_MODRM		equ	0x4000       ; MODxxxR/M
C_DATAW0	equ	0x8000       ; opc&1 ? C_DATA66 : C_DATA1


; void __cdecl lde_init(void* tableptr);

	BITS	32

	GLOBAL	lde_init

lde_init:
	pusha
	mov	edi, [esp+32+4]
	cld

	; Huffman-compressed 2048-byte table
	xor	eax, eax
	push	eax
	push	eax
	push	eax
	push	dword 0x002AAA800
	push	dword 0x03FFF687F
	push	dword 0x0FFE6DEA0
	push	dword 0x0DBD5FFFF
	push	dword 0x0FFFEAAAA
	push	dword 0x0AAAAAAAA
	push	dword 0x0AAAA0000
	push	eax
	push	eax
	push	eax
	push	eax
	push	eax
	push	eax
	push	dword 0x000000154
	push	dword 0x041FFF555
	push	dword 0x055DEDDAA
	push	dword 0x019955111
	push	dword 0x011111FFF
	push	dword 0x0FA11FFAA
	push	dword 0x08E60CF96
	push	dword 0x0FC72D6AA
	push	dword 0x0AAAAAA88
	push	dword 0x0888888D5
	push	dword 0x0528D559B
	push	dword 0x0366CD553
	push	dword 0x0355555FF
	push	dword 0x0FFFED6F9
	push	dword 0x068888888
	push	dword 0x088888888
	push	dword 0x08D5347CA
	push	dword 0x0DCC67BDF
	push	dword 0x0AAAAAAAA
	push	dword 0x0AAAAAAAA
	push	dword 0x0ABA94FFD
	push	dword 0x0D4A7FEEA
	push	dword 0x053FF7529
	push	dword 0x0FFA4A7FE
	push	dword 0x0929FFA4A
	push	dword 0x07FE929FF

	mov	ecx, 512
	xor	ebx, ebx
cycle:	xor	eax, eax
	call	tree
	stosd
	loop	cycle

	popa
	retn

getbit:	or	ebx, ebx
	jnz	skip
	pop	ebp
	pop	esi
	pop	edx
	push	esi
	push	ebp
	mov	bl, 32
skip:	dec	ebx
	shr	edx, 1
	retn

	; Huffman-tree, compiled into decompressor code
tree:	call	getbit
	jnc	tree0
tree1:	call	getbit
	jnc	tree10
tree11:	mov	ah, (C_MODRM >> 8)
	retn
tree10:	call	getbit
	jc	tree101
tree100:
	call	getbit
	jnc	tree1000
tree1001:
	call	getbit
	jnc	tree10010
tree10011:
	call	getbit
	jc	tree100111
tree100110:
	call	getbit
	jnc	tree1001100
tree1001101:
	mov	al, C_MEM67
	retn
tree1001100:
	call	getbit
	jnc	tree10011000
tree10011001:
	mov	ax, C_DATA66+C_MEM2
	retn
tree10011000:
	call	getbit
	jnc	tree100110000
tree100110001:
	mov	ax, C_PREFIX+C_66
	retn
tree100110000:
	mov	ah, ((C_DATA2+C_DATA1) >> 8)
	retn
tree100111:
	call	getbit
	jnc	tree1001110
tree1001111:
	mov	ah, ((C_MODRM+C_DATA66) >> 8)
	retn
tree1001110:
	call	getbit
	jnc	tree10011100
tree10011101:
	mov	al, C_PREFIX+C_67
	retn
tree10011100:
	mov	ah, (C_DATA2 >> 8)
	retn
tree10010:
	mov	ah, (C_DATAW0 >> 8)
	retn
tree1000:
	mov	ah, (C_DATA1 >> 8)
	retn
tree101:
	call	getbit
	jnc	tree1010
tree1011:
	call	getbit
	jnc	tree10110
tree10111:
	mov	al, C_PREFIX
	retn
tree10110:
	mov	ah, ((C_MODRM+C_DATA1) >> 8)
	retn
tree1010:
	mov	ah, (C_DATA66 >> 8)
	retn
tree0:	call	getbit
;	jc      tree01
	adc	al, 0
tree00:	dec	eax
tree01:	retn


; int __cdecl lde_dis(void* opcodeptr, void* tableptr)
; {

; returns opcode length in EAX or -1 if error

	GLOBAL	lde_dis

lde_dis:
	pusha

	mov	esi, [esp+32+4]	; tableptr
	mov	ecx, [esp+32+8]	; param = opcode ptr

	xor	edx, edx	; flags
	xor	eax, eax

prefix:	and	dl, ~C_PREFIX

	mov	al, [ecx]
	inc	ecx

	or	edx, [esi+eax*4]

	test	dl, C_PREFIX
	jnz	prefix

	cmp	al, 0xf6
	je	btest
	cmp	al, 0xf7
	je	btest

	cmp	al, 0xcd
	je	bint

	cmp	al, 0x0f
	je	b0F

cont:	test	dh, (C_DATAW0 >> 8)
	jnz	dataw0

dataw0done:
	test	dh, (C_MODRM >> 8)
	jnz	near modrm

exitmodrm:
	test	dl, C_MEM67
	jnz	mem67

mem67done:
	test	dh, (C_DATA66 >> 8)
	jnz	data66

data66done:
	mov	eax, ecx
	sub	eax, [esp+32+8]

	and	edx, C_MEM1+C_MEM2+C_MEM4 + C_DATA1+C_DATA2+C_DATA4
	add	al, dl
	add	al, dh

exit:	mov	[esp+7*4], eax
	popa
	retn

btest:	or	dh, (C_MODRM >> 8)
	test	byte [ecx], 00111000b	; F6/F7 -- test
	jnz	cont
	or	dh, (C_DATAW0 >> 8)
	jmp	cont

bint:	or	dh, (C_DATA1 >> 8)
	cmp	byte [ecx], 0x20
	jne	cont
	or	dh, (C_DATA4 >> 8)
	jmp	cont

b0F:	mov	al, [ecx]
	inc	ecx
	or	edx, [esi+eax*4+1024]	; 2nd half
	cmp	edx, -1
	jne	cont

error:	mov	eax, edx
	jmp	exit

dataw0:	xor	dh, (C_DATA66 >> 8)
	test	al, 00000001b
	jnz	dataw0done
	xor	dh, ((C_DATA66+C_DATA1) >> 8)
	jmp	dataw0done

mem67:	xor	dl, C_MEM2
	test	dl, C_67
	jnz	mem67done
	xor	dl, C_MEM4+C_MEM2
	jmp	mem67done

data66:	xor	dh, (C_DATA2 >> 8)
	test	dh, (C_66 >> 8)
	jnz	data66done
	xor	dh, ((C_DATA4+C_DATA2) >> 8)
	jmp	data66done

modrm:	mov	al, [ecx]
	inc	ecx

	mov	ah, al		; ah=mod, al=rm

	and	ax, 0xc007
	cmp	ah, 0xc0
	je	near exitmodrm

	test	dl, C_67
	jnz	modrm16

modrm32:
	cmp	al, 0x04
	jne	a

	mov	al, [ecx]	; sib
	inc	ecx
	and	al, 0x07

a:	cmp	ah, 0x40
	je	mem1
	cmp	ah, 0x80
	je	mem4

	cmp	ax, 0x0005
	jne	near exitmodrm

mem4:	or	dl, C_MEM4
	jmp	exitmodrm

mem1:	or	dl, C_MEM1
	jmp	exitmodrm

modrm16:
	cmp	ax, 0x0006
	je	mem2
	cmp	ah, 0x40
	je	mem1
	cmp	ah, 0x80
	jne	near exitmodrm

mem2:	or	dl, C_MEM2
	jmp	exitmodrm


