KMenuInc_Start:
MenuStart	Proc
 	call   	DialogBoxParamA, [hInst], DLG_LIST, [hMain], offset ListProc, 0
	ret
MenuStart	EndP


ListProc	proc uses ebx edi esi, hwnd:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD

	cmp     [wmsg], WM_INITDIALOG
	jz      lp_wmcreate
        	cmp     [wmsg], WM_COMMAND  ; EIN BUTTON ?
        	je      lp_wmcommand
	cmp	[wmsg], WM_DESTROY
	je	ListEnd
	xor     eax, eax
	jmp	ListEnd
lp_wmcreate:
	call	ListBoxIni, [hwnd], 1001
;	call	CenterWindow, hwnd

; Dialog Title Selector
	movzx   eax, DialogAPI
	shl     eax, 2
	call    SetWindowTextA, [hwnd], dword ptr [offset DialogTable+eax]
	mov	edi,dword ptr [FunctionCounter] ; get the first function name
	mov	eax,60
	mul	edi                      ; multiply it by 60
	add	eax,dword ptr [TextBuffer]
	xchg	eax,edi                 ; edi points to the fucking first functionname
	mov	ecx,dword ptr [YSize]    ; 25 = normal mode (80*60)

RefreshFunctionNames:

	push	ecx

	cmp	byte ptr [edi],0         ; end of the functiontable?
	jz	FunctionTableEnd          ; if yes, then jump
	mov	esi,edi                  ; esi = pointer to the string offset
	xor	al,al
	mov	ecx,0FFFFFFFFh           ; <- lame eh?
	repnz	scasb                  ; scan for null terminated string m0thafuckah
	mov	ecx,60
ParseFunctionName:
	cmp	byte ptr [edi],0
	jnz	FunctionNameParsed
SecondChar:
	inc	edi
	dec	ecx
	jnz	ParseFunctionName
FunctionNameParsed:
	cmp	byte ptr [edi],90h
	jz	SecondChar
	push	esi                  ; push the functionname
	call	ListBoxAdd           ; call the r0cking diSplayr0utine
	pop	ecx
	dec	ecx
	jmp	RefreshFunctionNames

FunctionTableEnd:
	pop	ecx
	mov	eax, TRUE
	jmp	ListEnd

lp_wmcommand:
	cmp	[wparam], 1
	je	lp_OK
	cmp	[wparam], IDCANCEL
	je	lp_OK
	jmp	ListEnd
lp_OK:
;int	3
	Call	SendMessageA, hList, LB_GETSELITEMS, 500, offset FunctionT
	lea	edi, FunctionT
	lea	esi, FunctionT
FormatFT:
	lodsd
	stosw
	cmp	dword ptr [esi], 0
	jnz	FormatFT
	mov	ecx, edi
	sub	ecx, offset FunctionT
	mov	eax, 0
	rep	stosb
        	call    EndDialog, [hwnd], 1
	jmp	ListEnd

ListEnd:
	ret
ListProc	endp

KMenuInc_End:

.Data
             Ypos dd 0  ; yposition of the fucking kewl lightbar
            YSize dd 24 ; resolution = 80*30
  FunctionCounter dd 0  ; numba of all imported functions
;
; Dialog Title Infos
; Added by G-RoM
;
        DialogAPI db 0  ;
  DialogTitle1    DB "API hooking Protection",0
  DialogTitle2	   DB "API breakpoint protection",0
  DialogTable	   DD offset DialogTitle1
	   DD offset DialogTitle2
