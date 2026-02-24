         .486P
	LOCALS
	JUMPS
         .Model  Flat,StdCall
         %nolist
         %list

UNICODE=0

WriteConsole2 Macro oText
 pusha
 call TextBoxWrite, offset oText, 0
 popa
EndM

F1CKEN Macro _Byte
 Jmp $+3
 db _Byte
EndM

F1CKEN2 Macro _Byte
 jmp $+4
 int 20h
 jmp $+5
 db _Byte
 int 20h
EndM

F1CKEN3 Macro _Byte
 call $+8
 int 20h
 db _Byte
EndM

F1CKEN4 Macro _Byte
 push eax
 call $+13
 db _Byte
 db 0FFh
 pop eax
 jmp $+26
 F1CKEN 0Fh
 F1CKEN2 _Byte
 pop eax
 inc eax
 F1CKEN 8Bh
 inc eax
 jmp $+4
 db 36h
 db 83h
 push eax
 ret
EndM

F1CKEN5 Macro
 test eax,eax
 jnc $+4
 db 0F7h
 db 05h
EndM


CONFUSE Macro _Byte
 jmp $+8
 int 20h
 db _Byte
 db 00h
 db 05h
 db 00h
 jmp $+6
 int 20h
 db 06h
 db 00h
 jmp $+6
 int 20h
 db 05h
 db 00h
EndM

CONFUSE2 Macro _Byte
 jmp $+6
 jmp $+6
 jmp $+12
 jmp $-4
 jmp $-4
 int 20h
 db _Byte
 db 00H
 db 05h
 db 00h
EndM

SEH_TRICK1 Macro _Byte
 CONFUSE 0EAh
 mov edx,(offset $+30 - offset ToAdd)
 CONFUSE 08Dh
 add edx,ebx
 dw 0FFFFh
 db _Byte
 mov ebp,ebx
EndM

CheckforHookedFunctions Macro
 pushad
 mov al,byte ptr [(offset Thunktable+4+3 - offset ToAdd)+ebx]
 F1CKEN2 0EAh
 cmp al,byte ptr [(offset Thunktable+4+4+3 - offset ToAdd)+ebx]
 jnz DeCompressResources
 mov al,byte ptr [(Thunktable - offset ToAdd)+3+ebx]
 F1CKEN2 0EFh
 cmp al,byte ptr [(offset Thunktable+4+4+3 - offset ToAdd)+ebx]
 jnz DeCompressResources
 mov edx,(offset ModuleDLL - offset ToAdd)
 add edx,ebx
 F1CKEN2 0FFh
 push edx
 call dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx] ; call "GetmoduleHandle"
 shr eax,32-8
 cmp al,byte ptr [(Thunktable - offset ToAdd)+3+ebx]
 F1CKEN2 0E9h
 jnz DeCompressResources
 cmp al,byte ptr [(offset Thunktable+4+4+3 - offset ToAdd)+ebx]
 F1CKEN2 0C7h
 jnz DeCompressResources
 cmp al,byte ptr [(offset Thunktable+4+3 - offset ToAdd)+ebx]
 F1CKEN2 0C8h
 jnz DeCompressResources
 popad
EndM


include w32.inc
Include k-data.inc
include	r-data.inc
Include r-loader.inc
include k-engine.asm

.Code

PeCryptAsm_Start:

;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
; Fixed ;) Now it acts da right way and we have a REAL win95 task
; means we have only one task even if several dilaog are active
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
Main:
 call    FindWindow, offset szClassPE, offset DialogTitle
 test    eax, eax
 jnz     Already_Open

 pusha
 push 4
 push 1000h
 push (ToAdd_END - offset CRC_Block1)
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart6],eax

 mov ecx,(ToAdd_END - offset CRC_Block1)
 mov esi,offset CRC_Block1
 mov edi,dword ptr [MemStart6]
 rep movsb
 popa

 push offset SEH_Handler  ; push the new SEH handler
 push dword ptr fs:[0]    ; push the previous one
 mov dword ptr fs:[0],esp ; save the new handler (install it)


	call    GetModuleHandle, 0         ; get hmod (in eax)
	mov     hInst, eax            ; hInstance is same as HMODULE in the Win32 world

        call InitCommonControls

;	mov	dword ptr muttafick, offset FakeProc
;	mov	dword ptr lpszClassName, offset szClassKI
;	call	RegisterClass, offset bla
;	call	CreateWindowEx,0, offset szClassKI, offset szClassKI, 0, 0, 0, 0, 0, 0, 0, hInst, 0
;	mov	dword ptr lpszClassName, offset szClassRA
;	call	RegisterClass, offset bla
;	call	CreateWindowEx,0, offset szClassRA, offset szClassRA, 0, 0, 0, 0, 0, 0, 0, hInst, 0
;	mov	dword ptr lpszClassName, offset szClassPE
;	call	RegisterClass, offset bla
;	call	CreateWindowEx,0, offset szClassPE, offset szClassPE, 0, 0, 0, 0, 0, 0, 0, hInst, 0


Splash:
	call    DialogBoxParamA, hInst , DLG_SPLASH, NULL , offset SplashProc, 0

Splash_End:
	call	GetCommandLine
; parse the command line - we want just the parameters
	mov	edi, eax
; Resolution of "can't open file pb" Command fucked up ;)
; Start of modification - G-RoM 08/07/98
	mov	COMMANDLINE, 0  ; Never forget it, NT dislike ;)
	xor	eax, eax
	xor     ecx, ecx
	dec	ecx
	push	edi
	cld
	repnz	scasb
	pop	edi
	not	ecx
	mov 	al,20h
	repnz 	scasb
	repz 	scasb
	test    ecx, ecx
	jz	EndCL
	dec 	edi
; End of modification - G-RoM 08/07/98
EndGCL:
	mov	COMMANDLINE, 1
	mov	esi, edi
	lea	edi, FileName2
	call	lstrlen, esi
	mov	ecx, eax
	repz	movsb
	lea	esi, FileName2
	lea	edi, CryptFile
	call	lstrlen, esi
	mov	ecx, eax
	repz	movsb
EndCL:

; initialize the WndClass (Window Class) structure
; Actually, we'll get the window class from a DIALOG resource (with CLASS directive)
;int 3
	mov	wc.wc_cbSize, WNDCLASSEX_
	mov	wc.wc_style, CS_HREDRAW + CS_VREDRAW
	mov	wc.wc_lpfnWndProc, offset DlgProc
	mov	wc.wc_cbClsExtra, 0
	mov	wc.wc_cbWndExtra, DLGWINDOWEXTRA	; necessary to use a DialogBox as
							; an window class
	mov	eax, hInst
	mov	wc.wc_hInstance, eax

; load main icon from resource
	call 	LoadIcon, hInst, ICON_MAIN
	mov	wc.wc_hIcon, eax
	mov	wc.wc_hIconSm, eax
; load a default cursor
  	call 	LoadCursor,NULL, IDC_ARROW
	mov	wc.wc_hCursor, eax

	mov	wc.wc_hbrBackground, COLOR_WINDOW
	mov	wc.wc_lpszMenuName, MENU_MENU
	mov	wc.wc_lpszClassName, offset szClassPE
;int 3
  	call 	RegisterClassEx, offset wc

; create main window
	call	CreateDialogParam, hInst, offset szClassPE, 0, NULL, 0
	mov	[hMain], eax		; We have now owner

	call	CreateToolbarEx, hMain, TBSTYLE_TOOLTIPS+WS_CHILD, 0, 8, hInst, 110, offset tdbutton, 8, 16, 16, 16, 16, 18
	mov	hToolBar, eax
	call	ShowWindow, eax, TRUE
	call	SendMessageA, hToolBar, TB_ENABLEBUTTON , ITEM_PROT, FALSE
	call	ListViewIni, hMain, 1015
	call	ListViewAddCol,60,offset SecName
	call	ListViewAddCol,75,offset SecVadd
	call	ListViewAddCol,85, offset SecVsize
	call	ListViewAddCol,75, offset SecRoff
	call	ListViewAddCol,85, offset SecRsize
	call	ListViewAddCol,90, offset SecRchar
	call	ListViewAddCol,60, offset SecRstate

        	call    TextBoxIni, [hMain], CTL_EDBOX		; EditBox Identifier given to Routine
	call	GetDlgItem, [hMain], CTL_PROGBAR	; Handle for progressbar
	mov	hPrgrs, eax
	cmp	COMMANDLINE, 1
	jnz	msg_loop
	mov	COMMANDLINE2, 1
	mov	COMMANDLINE, 0
msg_loop:
    	call 	GetMessage, offset msg, 0,0,0
	cmp	ax, 0
        	je      end_loop
	call	IsDialogMessage, [hMain], offset msg	; put this if you want to let the
	cmp	eax, TRUE				; system handle TAB, ENTER, etc
	jz	msg_loop

    	call 	TranslateMessage, offset msg
    	call 	DispatchMessage, offset msg
	jmp	msg_loop

end_loop:


 Push 2
 push (ToAdd_END - offset CRC_Block1)
 Push DWord Ptr [MemStart6]
 Call VirtualFree
 or eax,eax
 jne dealloc_error

Already_Open:

 call    SetForegroundWindow, eax
 call    ExitProcess, msg.ms_wParam


GeouttaHere:
 Push LARGE-1
 Call ExitProcess
CryptIT:

FakeProc proc uses ebx edi esi, hwnd:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD
xor eax, eax
ret
FakeProc	endp
PeCryptAsm_End:

Pecrypt_End:
 include r-seh.inc
End Main
