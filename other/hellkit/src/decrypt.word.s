.text
.align 4
.globl main
.type main,@function

main:		jmp .nonzero
.getip:		popl %esi
		jmp .next
.nonzero:	call .getip
.next:		addl $10, %esi
		xorl %ecx, %ecx
		movw $1122, %ecx
.loop1:		xorb $77, (%esi)
		incl %esi
		loop .loop1

