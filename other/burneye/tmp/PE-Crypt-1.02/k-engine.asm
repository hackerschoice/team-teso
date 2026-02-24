; Changes since i sorted the source:
;- Tooltips finally in
;- pseudo - Statusbar
;- more Warnings
;- Size now in dec
;- Updated Strings
;- Commandline implemented again (without parameters)
;- Confirmation prompts on exiting & canceling
;- Cancel Button while protecting
;- Protection now got own thread -> handling of window still possible while protecting
;- Fixed TLINK parameter ('MAKEFILE') -> Real Win32 Exe (Mainwindow now Thin with icon and 3D, no more hooling of wm.. needed)
;- Splash Screen on beginning
;- Fixed Randoms gemecker (Working Section read routine implemented)
;- Program can only be started once now
;- Mainwindow now opened using a windows class (mainwnd now named 'PE-CRYPT32')
;- Fixed that NT problem 100% (thx g-rom for help) - init now with WM_CREATE and after Creation
;- Mainwindow now 'Resizing' with nice icon, but still unsizable cuz of hooking wm_sizing and wm_setcursor
;- Nicer Toolbar, Protect button only enabled if file selected


include K-Commctrl.inc

.CODE

start:
kEngineAsm_Start:

;********************************************************
;***************** DLGPROC - FUNCTION *******************
;********************************************************


DlgProc proc uses ebx edi esi, hwnd:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD

	cmp	wmsg, WM_CREATE		; Startup
	jz	wmcreate
	cmp	wmsg, WM_DESTROY	; Window closed ?
	jz	wmdestroy
	cmp	wmsg, WM_CLOSE		; Window closed ?
	jz	id_cancel
        cmp     wmsg, WM_COMMAND  	; Control used ?
        jz      wmcommand
	cmp	wmsg, WM_INITMENU
	jz	wminitmenu
	cmp	wmsg, WM_CONTEXTMENU
	jz	wmcontext
        cmp     wmsg,WM_NOTIFY
        je      wmnotify
	cmp	GetOpen, 1
	jz	CenterOpen
	cmp	COMMANDLINE2, 1
	jz	OpenCL
	call 	DefWindowProc, hwnd,wmsg,wparam,lparam
	jmp	finish

wmnotify:

        mov     ebx,[lparam]    ;get pointer to NMHDR
        cmp     [(NMHDR ptr ebx).code],TTN_NEEDTEXT
        jne     defwndproc
        mov     eax,[(NMHDR ptr ebx).idFrom] ;resource id
        push    szBufl          ;size of our buffer
        push    offset szBuf    ;buffer to load string into
        push    eax             ;resource extracted from TOOLTIPTEXT
        push    [hInst]         ;Instance
        call    LoadString      ;Load the tip from STRINGTABLE
        mov     ebx,[lparam]    ;now just give him our buffer addr.
        mov     [(TOOLTIPTEXT ptr ebx).lpszText],offset szBuf
	xor	eax, eax
	jmp	finish

wminitmenu:
	jmp	finish

CenterOpen:

	call	FindWindow, offset Dialogstr, offset strTitle
	call	CenterWindow, eax
	mov	GetOpen, 0
	jmp	finish

wmcontext:

	call	SendMessageA, wparam, LVM_GETSELECTEDCOUNT, 0, 0	
	test	eax, eax
	jz	finish
	Call	LoadMenuA, hInst, 101
	call	GetSubMenu, eax, 0
	push	eax
	mov	ebx, lparam
	movzx	ebx, bx
	mov	ecx, lparam
	shr	ecx, 16
	mov	eax, wparam
	mov	hListV, eax
;	call	LVGetSelected, hListV
;	movzx	ebx, byte ptr SectionStates+eax
;	add	ebx, PITEM_NONE
;	pop	eax
;	push	eax
;	mov	hSubMenu, eax
;	call	SetMenuItemInfoA, eax, ebx, 0, offset Menuiteminfo
	pop	eax
	call	TrackPopupMenu, eax, TPM_LEFTALIGN, ebx, ecx, 0, hwnd, 0
	jmp	finish



wmcreate:

        call	SetWindowTextA, [hwnd], offset DialogTitle	; Set Title
	mov	eax, 0
	jmp	finish
	
wmcommand:
        cmp     [wparam], IDCANCEL    	; Window closed ?
        je      id_cancel
	cmp	[wparam], ITEM_OPEN     ; Open
	je	Openbox
	cmp	[wparam], ACC_OPEN     ; Open
	je	Openbox
        cmp     [wparam], ITEM_EXIT	; Exit
        je      id_cancel
        cmp     [wparam], ACC_EXIT	; Exit
        je      id_cancel
        cmp     [wparam], ITEM_ABOUT	; About
        je      about
        cmp     [wparam], ITEM_PROT	; Protect
        je      bt_protect
        cmp     [wparam], ACC_PROT	; Protect
        je      bt_protect
        cmp     [wparam], ITEM_OPTION	; Options
        je      bt_options
        cmp     [wparam], ACC_OPTION	; Options
        je      bt_options
        cmp     [wparam], PITEM_NONE
        je      bt_none
        cmp     [wparam], PITEM_ENC
        je      bt_enc
        cmp     [wparam], PITEM_COM
        je      bt_com
        cmp     [wparam], BS_CANCEL
        je      bt_cancel
	jmp	finish

bt_cancel:

	call	CheckAbort
	test	eax, eax
	jz	finish
	call	TerminateThread, NThread_Handle, 0

	mov	esi,dword ptr [MemStart7]
	mov	ecx,(ToAdd_END - offset CRC_Block1)
	mov	edi,offset CRC_Block1
	rep	movsb

	mov	edi,offset Fhandle
	mov	ecx,(offset FICK - offset Fhandle)
	xor	al,al
	rep	stosb
	Call	Memory_DeAlloc

	jmp	EncryptionFinishedReturn

bt_none:
	mov	eax, 0
	lea	esi, SecNone
	jmp	bt_context
bt_enc:

	mov	eax, 1
	lea	esi, SecEnc
	jmp	bt_context
bt_com:
	mov	eax, 2
	lea	esi, SecComp
	jmp	bt_context

bt_context:
	push	eax
	call	LVGetSelected, hListV
	mov	edi, eax
	pop	eax
	mov	bl, byte ptr SectionStates+edi
	cmp	bl, 0
	jnz	Notnone
	push	eax
	Call	MessageBoxA, hMain, offset NoneMSG, offset DialogTitle, MB_YESNO + MB_ICONQUESTION
	cmp	eax, IDNO
	pop	eax
	jz	finish
  Notnone:
	mov	byte ptr SectionStates+edi, al
	call	ListViewSubAdd, edi, 6, esi
	jmp	finish
about:
       
	call    DialogBoxParamA, hInst, DLG_ABOUT, hMain , offset AboutProc, 0
	jmp	finish

id_cancel:

	call	MessageBoxA, hMain, offset QuitMSG, offset DialogTitle, MB_YESNO + MB_ICONQUESTION
	cmp	eax, IDNO
	jz	finish
       	call    EndDialog, [hwnd], 0
	Call	ExitProcess, 0
	jmp	finish		; unusefull ? ;)

Openbox:

	mov	GetOpen, 1
	call	GetOpenFileNameA, offset lStructSize
	test	eax, eax
	jz	finish
 OpenCL:

	mov	COMMANDLINE2, 0
	call	lstrlen, offset CryptFile
	test	eax, eax
	jz	finish
	mov	[FileNLength], eax
	mov	[FCpassd], 1

        call    ImportIniInfo                           ; really needed
        call	ReadSectionData                            ; read that section stuff into the buffer
	call	ListViewReset
        call	ImportSectionData
        call	TextBoxWrite, offset Seperator, 1
	call	TextBoxWrite, offset CryptFile, 0
	call	TextBoxWrite, offset OpenOK, 1
	call	GetMenu, [hwnd]
	call	EnableMenuItem, eax, 40004, MF_ENABLED
	call	SendMessageA, hToolBar, TB_ENABLEBUTTON , ITEM_PROT, TRUE

	call	CreateFile, offset CryptFile, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0
	mov	Fhandle, eax
	call	GetFileSize, Fhandle, NULL
	mov	OFileSize, eax
	call	_wsprintfA, offset SizeBuf, offset Fmt1, offset FileSizeStr, eax
	add	esp, 16
	call	CloseHandle, Fhandle
	call	SetDlgItemText, hMain, 2001, offset SizeBuf
	call	SetDlgItemText, hMain, 2000, offset ProtectStr
	jmp	finish

bt_protect:

	cmp	[FileNLength], 0
	jz	finish
	call	ImportIniInfo				; Import ini data
	call	GetCurrentProcessId          ; get current process id

	push	eax                          ; push processid
	push	0
	push	PROCESS_SET_INFORMATION+DEBUG_ONLY_THIS_PROCESS  ; enable set information flag & debug flag 
	call	OpenProcess                  ; open process and receive handle

	push	THREAD_PRIORITY_NORMAL
	push	eax                          ; push process handle
	call	SetPriorityClass             ; set the priority class of this thread

	push	offset NThread_ID             ; for later save of the thread id
	push	CREATE_SUSPENDED             ; create a thread which runs after resumethread
	push	0
	push	offset Cryptor_Start	; thread entrypoint
	push	0
	push	0
	Call	CreateThread                 ; create a new funny thread
	mov	dword ptr [NThread_Handle],eax ; save thread handle

	push	THREAD_PRIORITY_NORMAL
	push	dword ptr [NThread_Handle]    ; push thread id
	call	SetThreadPriority            ; set thread priority

	push	dword ptr [NThread_Handle]    ; push thread handle
	call	ResumeThread                 ; resume the suspended thread
	jmp	EndCrypt

EncryptionFinishedReturn:
	call 	SendMessageA, [hPrgrs], WM_USER+2, 0,0	; WM_USER+2 == PBM_SETPOS => clear Progressbar
	call	TextBoxWrite, offset SemiSep, 1
	call	TextBoxWrite, offset Unload, 1
	call	GetMenu, [hMain]
	call	EnableMenuItem, eax, ITEM_OPEN, MF_ENABLED
	call	GetMenu, [hMain]
	call	EnableMenuItem, eax, ITEM_EXIT, MF_ENABLED
	call	GetMenu, [hMain]
	call	EnableMenuItem, eax, ITEM_OPTION, MF_ENABLED
	call	SendMessageA, hToolBar, TB_ENABLEBUTTON , ITEM_OPEN, TRUE
	call	ListViewReset
	call	GetDlgItem, hMain, BS_CANCEL
	call	ShowWindow, eax, FALSE
	call	ShowWindow, hToolBar, TRUE

	call	CreateFile, offset CryptFile, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0
	mov	Fhandle, eax
	call	GetFileSize, Fhandle, NULL
	mov	NFileSize, eax
	call	_wsprintfA, offset SizeBuf, offset Fmt2, offset OFileSizeStr, OFileSize, offset NFileSizeStr, NFileSize
	add	esp, 24
	call	CloseHandle, Fhandle
	call	SetDlgItemText, hMain, 2001, offset SizeBuf
	call	SetDlgItemText, hMain, 2000, offset DoneStr
	cmp	byte ptr [BACKUPMODE],0     ; are we allowed to generate a backup?
	jnz	finish
	call	DeleteFileA, offset BackupFile
	jmp	finish
EndCrypt:
	call	ShowWindow, hToolBar, FALSE
	call	GetDlgItem, hMain, BS_CANCEL
	call	ShowWindow, eax, TRUE
	call	GetMenu, [hwnd]
	call	EnableMenuItem, eax, ITEM_PROT, MF_GRAYED
	call	GetMenu, [hwnd]
	call	EnableMenuItem, eax, ITEM_OPEN, MF_GRAYED
	call	GetMenu, [hwnd]
	call	EnableMenuItem, eax, ITEM_EXIT, MF_GRAYED
	call	GetMenu, [hwnd]
	call	EnableMenuItem, eax, ITEM_OPTION, MF_GRAYED
	call	SendMessageA, hToolBar, TB_ENABLEBUTTON , ITEM_PROT, FALSE
	call	SendMessageA, hToolBar, TB_ENABLEBUTTON , ITEM_OPEN, FALSE
	jmp	finish

bt_options:

       	call    DialogBoxParamA, [hInst], DLG_OPTION, [hMain], offset OptionsProc, 0
	cmp	[FileNLength], 0
	jz	finish
        call    ImportIniInfo                           ; really needed
        call	ReadSectionData                            ; read that section stuff into the buffer
	call	ListViewReset
        call	ImportSectionData
	jmp	finish

wmdestroy:

	call	PostQuitMessage, 0
	xor	eax, eax
defwndproc:
         push    [lparam]
         push    [wparam]
         push    [wmsg]
         push    [hwnd]
         call    DefWindowProc
         jmp     finish

finish:

       	ret

DlgProc        endp

;********************************************************
;*************** OPTIONSPROC - FUNCTION *****************
;********************************************************

OptionsProc	proc uses ebx edi esi, hOpt:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD

	cmp     [wmsg], WM_COMMAND 	; Control used ?
        je      op_wmcommand
        cmp     [wmsg], WM_INITDIALOG	; Startup
        je      op_wmcreate
	mov	eax, FALSE
	jmp	op_finish	; Same as ABOVE !!! jmp to end of PROC

op_wmcreate:

	call 	CheckRadioButton, hOpt, 1008, 1009, 1008
	call 	CheckRadioButton, hOpt, 1001, 1003, 1001	; Initialize Radiobuttons if no Inifile
	call 	CheckRadioButton, hOpt, 1101, 1103, 1101

	call	LoadIniData
	jmp	op_finish

op_wmcommand:
	cmp	[wparam], 1
	je	op_OK
	cmp	[wparam], IDCANCEL
	je	op_CANCEL
	cmp	[wparam], 1013	 ; CRC Box
       	je      op_crcbox
	jmp	op_finish

op_crcbox:
	call	IsDlgButtonChecked, hOpt, 1013	; crcchecked
	test	eax, eax
	jnz	crcchecked
	call	GetDlgItem, hOpt, 1008
	call	EnableWindow, eax, FALSE
	call	GetDlgItem, hOpt, 1009
	call	EnableWindow, eax, FALSE
	jmp	finish

crcchecked:
	call	GetDlgItem, hOpt, 1008
	call	EnableWindow, eax, TRUE
	call	GetDlgItem, hOpt, 1009
	call	EnableWindow, eax, TRUE
	jmp	finish

op_OK:

	call	SaveIniData
	jmp	op_CANCEL

op_CANCEL:
       	
	call    EndDialog, [hOpt], 1
	jmp	op_finish

op_finish:

	ret
OptionsProc	endp

;********************************************************
;************** ABOUTPROC - FUNCTION ********************
;********************************************************

AboutProc proc    hAbout:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD

	cmp	wmsg, WM_INITDIALOG
	mov 	eax, TRUE
	jz	AboutCreate
	cmp	wmsg, WM_COMMAND
	jnz	Default
	cmp	word ptr [wparam], IDOK
	jz 	AboutEnd
	cmp	word ptr [wparam], IDCANCEL
	jnz 	Default
AboutEnd:
	call	EndDialog, hAbout, TRUE
	mov	eax, TRUE
	jmp	Return
AboutCreate:
;	call	CenterWindow, hwnd
	jmp	Return
Default:
      	mov     eax, FALSE
Return:
      	ret
AboutProc endp

SplashProc proc    hAbout:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD

	cmp	wmsg, WM_INITDIALOG
	jz	SplashIni
	cmp	wmsg, WM_LBUTTONDOWN
	jz 	SplashEnd
	cmp	wmsg, WM_RBUTTONDOWN
	jz 	SplashEnd
	cmp	wmsg, WM_COMMAND
	jz 	SplashEnd
	cmp	wmsg, 113h
	jz 	TimerEnd
	jmp	SplashDefault

SplashIni:
	call	SetTimer, hAbout, 34, 2000, NULL
	jmp 	SplashDefault

TimerEnd:
	cmp	wparam, 34
	jnz	SplashDefault

SplashEnd:
	call	EndDialog, hAbout, TRUE
	mov	eax, TRUE
	jmp	SplashReturn

SplashDefault:
      	mov     eax, FALSE

SplashReturn:
      	ret
SplashProc endp

GetOpenFunc	proc uses ebx edi esi, hwnd:DWORD, wmsg:DWORD, wparam:DWORD, lparam:DWORD

        cmp     [wmsg], WM_INITDIALOG	; Startup
        je      go_wmcreate
	jmp	go_finish
go_wmcreate:
	call	CenterWindow, hwnd
go_finish:
	ret
GetOpenFunc	endp

;********************************************************
;************* SaveIniData - SUBFUNCTION ****************
;********************************************************

SaveIniData	proc uses eax ebx edi esi

	call IsDlgButtonChecked, hOpt, 1001 ; reloc12
	test	eax, eax
	jz	op_RE12
	call	WritePrivateProfileStringA, offset Section, offset KeyReloc, offset Reloc12, offset IniFile
op_RE12:
	call IsDlgButtonChecked, hOpt, 1002 ; reloc16
	test	eax, eax
	jz	op_RE16
	call	WritePrivateProfileStringA, offset Section, offset KeyReloc, offset Reloc16, offset IniFile
op_RE16:
	call IsDlgButtonChecked, hOpt, 1003 ; reloc16
	test	eax, eax
	jz	op_REC
	call	WritePrivateProfileStringA, offset Section, offset KeyReloc, offset RelocC, offset IniFile
op_REC:
	call	WritePrivateProfileStringA, offset Section, offset KeyGC, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1004 ; GC
	test	eax, eax
	jz	op_GC
	call	WritePrivateProfileStringA, offset Section, offset KeyGC, offset StrTrue, offset IniFile
op_GC:
	call	WritePrivateProfileStringA, offset Section, offset KeyRC, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1101 ; RC
	test	eax, eax
	jz	op_RC
	call	WritePrivateProfileStringA, offset Section, offset KeyRC, offset ResC, offset IniFile
op_RC:
	call IsDlgButtonChecked, hOpt, 1102 ; RC
	test	eax, eax
	jz	op_RE
	call	WritePrivateProfileStringA, offset Section, offset KeyRC, offset ResE, offset IniFile
op_RE:
	call IsDlgButtonChecked, hOpt, 1103 ; RC
	test	eax, eax
	jz	op_RN
	call	WritePrivateProfileStringA, offset Section, offset KeyRC, offset StrFalse, offset IniFile
op_RN:
	call	WritePrivateProfileStringA, offset Section, offset KeyAntiDebug, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1006 ; antidebug
	test	eax, eax
	jz	op_AD
	call	WritePrivateProfileStringA, offset Section, offset KeyAntiDebug, offset StrTrue, offset IniFile
op_AD:
	call	WritePrivateProfileStringA, offset Section, offset KeyVirus, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1007 ; Virus
	test	eax, eax
	jz	op_VH
	call	WritePrivateProfileStringA, offset Section, offset KeyVirus, offset StrTrue, offset IniFile
op_VH:
	call	WritePrivateProfileStringA, offset Section, offset KeyChecksums, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1013 ; Checksums
	test	eax, eax
	jnz	op_crc
	call	WritePrivateProfileStringA, offset Section, offset KeyChecksums, offset StrFalse, offset IniFile
	jmp	op_CH
op_crc:
	call IsDlgButtonChecked, hOpt, 1008 ; CRCWin
	test	eax, eax
	jz	op_CW
	call	WritePrivateProfileStringA, offset Section, offset KeyChecksums, offset CSWin, offset IniFile
op_CW:
	call IsDlgButtonChecked, hOpt, 1009 ; CRCHang
	test	eax, eax
	jz	op_CH
	call	WritePrivateProfileStringA, offset Section, offset KeyChecksums, offset CSHang, offset IniFile
op_CH:
	call	WritePrivateProfileStringA, offset Section, offset KeyHooking, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1010 ; Hooking
	test	eax, eax
	jz	op_AH
	call	WritePrivateProfileStringA, offset Section, offset KeyHooking, offset StrTrue, offset IniFile
op_AH:
	call	WritePrivateProfileStringA, offset Section, offset KeyPE, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1011 ; PEheader
	test	eax, eax
	jz	op_PE
	call	WritePrivateProfileStringA, offset Section, offset KeyPE, offset StrTrue, offset IniFile
op_PE:
	call	WritePrivateProfileStringA, offset Section, offset KeyBackup, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1014 ; Backup
	test	eax, eax
	jz	op_BA
	call	WritePrivateProfileStringA, offset Section, offset KeyBackup, offset StrTrue, offset IniFile
op_BA:
	call	WritePrivateProfileStringA, offset Section, offset KeyIH, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1005 ; ImportHiding
	test	eax, eax
	jz	op_IM
	call	WritePrivateProfileStringA, offset Section, offset KeyIH, offset StrTrue, offset IniFile
op_IM:
	call	WritePrivateProfileStringA, offset Section, offset KeyAntiL, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1012 ; AntiLoader
	test	eax, eax
	jz	op_AL
	call	WritePrivateProfileStringA, offset Section, offset KeyAntiL, offset StrTrue, offset IniFile
op_AL:
	call	WritePrivateProfileStringA, offset Section, offset KeyAntiBPX, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1015 ; AntiBPX
	test	eax, eax
	jz	op_AB
	call	WritePrivateProfileStringA, offset Section, offset KeyAntiBPX, offset StrTrue, offset IniFile
op_AB:
	call	WritePrivateProfileStringA, offset Section, offset KeyComp, offset StrFalse, offset IniFile
	call IsDlgButtonChecked, hOpt, 1000 ; InfoMode
	test	eax, eax
	jz	op_CM
	call	WritePrivateProfileStringA, offset Section, offset KeyComp, offset StrTrue, offset IniFile
op_CM:
	ret
SaveIniData	endp

;********************************************************
;************* LoadIniData - SUBFUNCTION ****************
;********************************************************

LoadIniData	proc uses eax ebx esi edi

	call	GetPrivateProfileStringA, offset Section, offset KeyReloc, offset Reloc12, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset Reloc12
	test	eax, eax
	jnz	op2_RE12
	call	CheckRadioButton, hOpt, 1001, 1003, 1001; reloc12
op2_RE12:
	call	lstrcmp, offset TmpStrBuf, offset Reloc16
	test	eax, eax
	jnz	op2_RE16
	call	CheckRadioButton, hOpt, 1001, 1003, 1002; reloc16
op2_RE16:
	call	lstrcmp, offset TmpStrBuf, offset RelocC
	test	eax, eax
	jnz	op2_REC
	call	CheckRadioButton, hOpt, 1001, 1003, 1003; reloc16
op2_REC:
	call	GetPrivateProfileStringA, offset Section, offset KeyGC, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_GC
	call 	CheckDlgButton, hOpt, 1004 ; GC
	sub	esp, 4
op2_GC:
	call	GetPrivateProfileStringA, offset Section, offset KeyRC, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset ResC
	test	eax, eax
	jnz	op2_RC
	call	CheckRadioButton, hOpt, 1101 , 1103, 1101; RC
op2_RC:
	call	lstrcmp, offset TmpStrBuf, offset ResE
	test	eax, eax
	jnz	op2_RE
	call	CheckRadioButton, hOpt, 1101, 1103, 1102 ; RC
op2_RE:
	call	lstrcmp, offset TmpStrBuf, offset StrFalse
	test	eax, eax
	jnz	op2_RN
	call	CheckRadioButton, hOpt, 1101, 1103, 1103 ; RC
op2_RN:
	call	GetPrivateProfileStringA, offset Section, offset KeyAntiDebug, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_AD
	call	CheckDlgButton, hOpt, 1006 ; antidebug
	sub	esp, 4
op2_AD:
	call	GetPrivateProfileStringA, offset Section, offset KeyVirus, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_VH
	call 	CheckDlgButton, hOpt, 1007 ; Virus
	sub	esp, 4
op2_VH:
	call	GetPrivateProfileStringA, offset Section, offset KeyChecksums, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrFalse
	test	eax, eax
	jz	op2_CH
	call	CheckDlgButton, hOpt, 1013 ; CRC
	sub	esp, 4
	call	GetDlgItem, hOpt, 1008
	call	EnableWindow, eax, TRUE
	call	GetDlgItem, hOpt, 1009
	call	EnableWindow, eax, TRUE
	call	lstrcmp, offset TmpStrBuf, offset CSWin
	test	eax, eax
	jnz	op2_CW
	call	CheckRadioButton, hOpt, 1008, 1009, 1008
op2_CW:
	call	lstrcmp, offset TmpStrBuf, offset CSHang
	test	eax, eax
	jnz	op2_CH
	call	CheckRadioButton, hOpt, 1008, 1009, 1009

op2_CH:
	call	GetPrivateProfileStringA, offset Section, offset KeyHooking, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_AH
	call	CheckDlgButton, hOpt, 1010 ; Hooking
	sub	esp, 4
op2_AH:
	call	GetPrivateProfileStringA, offset Section, offset KeyPE, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_PE
	call	CheckDlgButton, hOpt, 1011 ; PEheader
	sub	esp, 4
op2_PE:
	call	GetPrivateProfileStringA, offset Section, offset KeyIH, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_IM
	call	CheckDlgButton, hOpt, 1005 ; TmportHiding
	sub	esp, 4
op2_IM:
	call	GetPrivateProfileStringA, offset Section, offset KeyAntiL, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_AL
	call	CheckDlgButton, hOpt, 1012 ; AntiLoader
	sub	esp, 4
op2_AL:
	call	GetPrivateProfileStringA, offset Section, offset KeyAntiBPX, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_AB
	call	CheckDlgButton, hOpt, 1015 ; Antibpx
	sub	esp, 4
op2_AB:
	call	GetPrivateProfileStringA, offset Section, offset KeyBackup, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_BA
	call	CheckDlgButton, hOpt, 1014 ; Backup
	sub	esp, 4
op2_BA:
	call	GetPrivateProfileStringA, offset Section, offset KeyComp, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	op2_CM
	call	CheckDlgButton, hOpt, 1000 ; Backup
	sub	esp, 4
op2_CM:
	ret

LoadIniData	endp

;********************************************************
;************ ImportIniInfo - SUBFUNCTION ***************
;********************************************************

ImportIniInfo	proc uses eax ebx edi esi

	call	GetPrivateProfileStringA, offset Section, offset KeyReloc, offset Reloc12, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset Reloc12
	test	eax, eax
	jnz	iii_RE12
	mov	ARTOFRELOC, 0
iii_RE12:
	call	lstrcmp, offset TmpStrBuf, offset Reloc16
	test	eax, eax
	jnz	iii_RE16
	mov	ARTOFRELOC, 1
iii_RE16:
	mov	RELOCCOMP, 0
	call	lstrcmp, offset TmpStrBuf, offset RelocC
	test	eax, eax
	jnz	iii_REC
	mov	RELOCCOMP, 1
iii_REC:
	mov	COMPRESSION, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyGC, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_GC
	mov	COMPRESSION, 1
iii_GC:
	call	GetPrivateProfileStringA, offset Section, offset KeyRC, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset ResC
	test	eax, eax
	jnz	iii_RC
	mov	RESOURCECOMP, 1
iii_RC:
	call	lstrcmp, offset TmpStrBuf, offset ResE
	test	eax, eax
	jnz	iii_RE
	mov	RESOURCECOMP, 0
iii_RE:
	call	lstrcmp, offset TmpStrBuf, offset StrFalse
	test	eax, eax
	jnz	iii_RN
	mov	RESOURCECOMP, 2
iii_RN:
	mov	ANTID, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyAntiDebug, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_AD
	mov	ANTID, 1
iii_AD:
	mov	VHEURISTIC, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyVirus, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_VH
	mov	VHEURISTIC, 1
iii_VH:
	mov	CRCM, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyChecksums, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrFalse
	test	eax, eax
	jz	iii_CH
	call	lstrcmp, offset TmpStrBuf, offset CSWin
	test	eax, eax
	jnz	iii_CW
	mov	CRCM, 2
iii_CW:
	call	lstrcmp, offset TmpStrBuf, offset CSHang
	test	eax, eax
	jnz	iii_CH
	mov	CRCM, 1

iii_CH:
	mov	HOOKFUNC, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyHooking, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_AH
	mov	HOOKFUNC, 1
iii_AH:
	mov	KILLH, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyPE, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_PE
	mov	KILLH, 1
iii_PE:
	mov	IMPORTD, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyIH, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_IM
	mov	IMPORTD, 1
iii_IM:
	mov	ANTILOADER, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyAntiL, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_AL
	mov	ANTILOADER, 1
iii_AL:
	mov	ANTIBPX, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyAntiBPX, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_AB
	mov	ANTIBPX, 1
iii_AB:
	mov	BACKUPMODE, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyBackup, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_BA
	mov	BACKUPMODE, 1
iii_BA:
	mov	COMPATIBLE, 0
	call	GetPrivateProfileStringA, offset Section, offset KeyComp, offset StrFalse, offset TmpStrBuf, 30 , offset IniFile
	call	lstrcmp, offset TmpStrBuf, offset StrTrue
	test	eax, eax
	jnz	iii_CM
	mov	COMPATIBLE, 1
iii_CM:
	ret

ImportIniInfo	endp

;********************************************************
;********** ImportSectionData - SUBFUNCTION *************
;********************************************************

ImportSectionData	proc uses eax ebx ecx edx edi esi ebp

	lea	edi, SectionData
	
ISD_Start:
	mov	ebp, edi		; save edi
	lea	edi, Sectmp
	mov	eax, 0
	mov	ecx, 12
	repz	stosb			; clean tmpbuf
	lea	edi, Sectmp
	mov	esi, ebp
	mov	ecx, 8
	repz	movsb			; copy sectionname
	mov	edi, ebp
	call	ListViewAdd, offset Sectmp
	add	edi, 8
	call	_wsprintfA, offset Sectmp, offset HexFmt, dword ptr [edi]
	add	esp, 12
	call	ListViewSubAdd, Seccnt, 1, offset Sectmp
	add	edi, 4
	call	_wsprintfA, offset Bytetmp, offset ByteFmt, dword ptr [edi]
	add	esp, 12
	call	ListViewSubAdd, Seccnt, 2, offset Bytetmp
	add	edi, 4
	call	_wsprintfA, offset Sectmp, offset HexFmt, dword ptr [edi]
	add	esp, 12
	call	ListViewSubAdd, Seccnt, 3, offset Sectmp
	add	edi, 4
	call	_wsprintfA, offset Bytetmp, offset ByteFmt, dword ptr [edi]
	add	esp, 12
	call	ListViewSubAdd, Seccnt, 4, offset Bytetmp
	add	edi, 4
	call	_wsprintfA, offset Sectmp, offset HexFmt, dword ptr [edi]
	add	esp, 12
	call	ListViewSubAdd, Seccnt, 5, offset Sectmp
	add	edi, 4

	mov	eax, Seccnt
	movzx	eax, byte ptr SectionStates+eax
	imul	eax, 4
	lea	esi, SecOff
	add	esi, eax
	call	ListViewSubAdd, Seccnt, 6, dword ptr [esi]
	inc	Seccnt
	cmp	dword ptr [edi], 0
	jnz	ISD_Start
	mov	Seccnt, 0
	ret

ImportSectionData	endp

;********************************************************
;************ LVGetSelected - SUBFUNCTION ***************
;********************************************************

LVGetSelected	proc uses ebx ecx edx edi esi, hwnd:DWORD

	call	SendMessageA, hwnd, LVM_GETITEMCOUNT, 0, 0
	mov	ebx, eax
	xor	edi, edi
  NextItem:
	call	SendMessageA, hwnd, LVM_GETITEMSTATE, edi, LVIS_SELECTED
	test	eax, eax
	jnz	SelItem
	inc	edi
	cmp	ebx, edi
	jnz	NextItem
	mov	edi, -1
  SelItem:
	mov	eax, edi
	ret

LVGetSelected	endp

;********************************************************
;************ CenterWindow - SUBFUNCTION ****************
;********************************************************

CenterWindow	proc uses eax ebx ecx edx edi esi, hwnd:DWORD

	call	GetDesktopWindow
	call	GetWindowRect, eax, offset RectData 
	mov	edx, rd_right
	mov	ecx, rd_bottom	
	push	edx
	push	ecx
	call	GetWindowRect, hwnd, offset RectData 
	mov	eax, rd_bottom
	sub	eax, rd_top
	pop	ecx
	sub	ecx, eax
	xchg	ecx, eax
	push	ecx
	mov	ebx, 2
	cdq
	div	bx
	mov	ebx, rd_right
	sub	ebx, rd_left
	pop	ecx
	pop	edx
	sub	edx, ebx
	push	eax
	mov	eax, edx
	mov	edx, ebx
	push	edx
	mov	ebx, 2
	cdq
	div	bx
	pop	edx
	pop	ebx
	call	MoveWindow, hwnd, eax, ebx, edx, ecx, TRUE
	
	ret
CenterWindow	endp

;********************************************************
;************** CheckAbort - SUBFUNCTION ****************
;********************************************************

CheckAbort	proc uses ebx ecx edx esi edi ebp

	call	SuspendThread, NThread_Handle
	call	MessageBoxA, hMain, offset CancelMSG, offset DialogTitle, MB_YESNO + MB_ICONQUESTION
	cmp	eax, IDNO
	mov	eax, 0
	jz	CA_End
	call	CloseHandle, Fhandle
	call	CopyFileA, offset BackupFile, offset CryptFile, FALSE
	call	DeleteFileA, offset BackupFile
	mov	eax, 1
	
CA_End:
	push	eax
	call	SetThreadPriority, NThread_Handle, THREAD_PRIORITY_NORMAL            ; set thread priority
	call	ResumeThread, NThread_Handle
	pop	eax
	ret

CheckAbort	endp

;********************************************************
;************** CheckAbort - SUBFUNCTION ****************
;********************************************************

AddPoints	proc	uses ebx ecx edx esi edi ebp, Str:DWORD

	mov	eax, 20h
	mov	ecx, -1
	mov	edi, Str
	repnz	scasb
	not	ecx
	
	mov	esi, edi
	lea	edi, PointBuf
	
AddPoints	endp
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴
;some procs (now located in this file, cause i had some problems with compiling)
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴

;display resource informations
;
DisplayResourceInformation proc
 pushad
 WriteConsole2 <offset Baukasten12>
 WriteConsole2 <offset Baukasten15> <Baukasten15L
 cmp byte ptr [RCompress],0 ; any previous compression try?
 jz NoPreviousTryResources  ; no? then jump
 WriteConsole2 <offset Baukasten16>
NoPreviousTryResources:
 cmp byte ptr [RESOURCECOMP],1
 jz DisplayRcompression
 WriteConsole2 <offset Baukasten13>
Tittenkosten5mark90:
 popad
 ret
DisplayRcompression:
 WriteConsole2 <offset Baukasten14>
 popad
 ret
DisplayResourceInformation endp


;display new informations
;like packing ratio
;
DisplayStatistic proc
 pushad
 cmp byte ptr [INFOMODE],0                ; check if infomode is enabled
 jz NoAnnoyingStatistic                   ; if yes, then goto ret

 mov eax,CurrentPhysS                     ; get current physicalsize
 cmp dword ptr [NewPhysS],eax             ; get the new size
 jae NoCompressionused                     ; if equal then no compression
                                          ; was used
 cmp dword ptr [NewPhysS],0               ; compression is off
 jz NoCompressionused2                    ; jump and display crap ;)

 WriteConsole2 <offset Baukasten5>
 WriteConsole2 <offset Baukasten7>
 mov esi,dword ptr [CurrentPhysS]
 mov edi,offset PhysString
 call dword2hex ; convert to hexadecimal string
 WriteConsole2 <offset PhysString> ; <10>   ; display the old physicalsize

 WriteConsole2 <offset Baukasten8>
 mov esi,dword ptr [NewPhysS]
 mov edi,offset NewPhysString
 call dword2hex ; convert to hexadecimal string
 WriteConsole2 <offset NewPhysString> ; <10>   ; display the old physicalsize

 ;Prozentberechnung
 ;% = 100 - (NewPhysS*100/CurrentPhysS) :)
 mov eax,100
 mov ecx,dword ptr [NewPhysS]
 mul ecx

 mov ecx,dword ptr [CurrentPhysS]
 xor edx,edx
 div ecx
 mov ebx,100
 sub ebx,eax
 xchg ebx,eax

 mov esi,offset PercentString+4
 call Hex2DecimalString
 mov esi,offset PercentString
 mov edi,offset NewStringi
 mov ecx,4
Parsethem:
 lodsb
 cmp al,20h
 jz nowaysuckaahh
 stosb
nowaysuckaahh:
 dec ecx
 jnz Parsethem
 mov al,"%"
 stosb
 xor al,al
 stosb

 WriteConsole2 <offset Baukasten9>
 WriteConsole2 <offset NewStringi>

 WriteConsole2 <offset ReturnChars>
NoAnnoyingStatistic:
 popad
 ret

NoCompressionused:
 WriteConsole2 <offset Baukasten11>
 WriteConsole2 <offset ReturnChars>
 popad
 ret

NoCompressionused2:
 WriteConsole2 <offset Baukasten10>
 WriteConsole2 <offset ReturnChars>
 popad
 ret


DisplayStatistic endp

Hex2DecimalString proc
 mov cx,0Ah                  ; divide by 10 to get decimal values
CalculateAgain:
 xor dx,dx
 div cx
 add dl,30h
Label9:
 dec esi
 mov [esi],dl
 or ax,ax
 jnz CalculateAgain
 ret
Hex2DecimalString endp


;display routine for the object process counter
;another damn design crap ;)
;
DisplayCounter proc
 pushad
 cmp byte ptr [INFOMODE],0                ; check if infomode is enabled
 jz NoAnnoyingStatistic2                  ; if yes, then goto ret

 mov ax,word ptr [OBJnumber] ; get the current obj number
 mov esi,offset Displaystring+3
 call Hex2DecimalString

 WriteConsole2 <offset Baukasten>
 WriteConsole2 <offset Displaystring>

 WriteConsole2 <offset Baukasten2>

 mov esi,dword ptr [CurrentRVA] ; get the current rva (only 1 word)
 mov edi,offset RVAString
 call dword2hex                        ; convert to hexadecimal string
 WriteConsole2 <offset RVAString>      ; display the rva value
 WriteConsole2 <offset Baukasten3>
 mov esi,dword ptr [CurrentVSIZE]
 mov edi,offset VsizeString
 call dword2hex ; convert to hexadecimal string
 WriteConsole2 <offset VsizeString> ; <10>   ; display the current vsize value

 WriteConsole2 <offset Baukasten4>

 mov esi,dword ptr [CurrentFLAGS]
 mov edi,offset FlagString
 call dword2hex ; convert to hexadecimal string
 WriteConsole2 <offset FlagString> ;<11>   ; display the current vsize value

NoAnnoyingStatistic2:
 popad
 ret
DisplayCounter endp



dword2hex proc
 mov eax,esi
 mov ecx,4
 xor ebx,ebx
Convert_it:
 rol eax,8      ; rotate 8 bits
 push eax
 xor bh,bh
 mov bl,al
 mov dl,al
 shr bl,4
 mov al,[ebx+HTable]
 stosb
 mov bl,dl
 and bl,0Fh
 mov al,[ebx+HTable]
 stosb
 pop eax
 dec ecx
 jnz Convert_it
 ret
dword2hex endp

kEngineAsm_End:

 Include r-Cryptor.asm                           ; the main encryption routine...
 include r-sread.inc                             ; include the section stat crap

