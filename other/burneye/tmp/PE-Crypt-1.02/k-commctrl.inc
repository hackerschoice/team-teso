
LVCF_FMT                EQU	0001
LVCF_WIDTH              EQU	0002
LVCF_TEXT               EQU	0004
LVCF_SUBITEM            EQU	0008

LVIF_TEXT               EQU	0001
LVIF_IMAGE              EQU	0002
LVIF_PARAM              EQU	0004
LVIF_STATE              EQU	0008

TTS_ALWAYSTIP           EQU	01

LVCFMT_RIGHT            EQU	0001
.data
;List Box Variables:

hList		dd	0

;List View Variables:

lv_item:
lvmask		dd	LVIF_TEXT
lvitem		dd	0
lvsubitem	dd	0
lvstate		dd	0
lvstatemask	dd	0
lvtext		dd	0
lvtextmax	dd	12
lvimage		dd	0
lvparam		dd	0

lv_col:
clmask		dd	LVCF_SUBITEM+LVCF_TEXT+LVCF_WIDTH+LVCF_FMT
clfmt		dd	LVCFMT_RIGHT
clcx		dd	0
cltext		dd	0
cltextmax	dd	20
clsubitem	dd	0

hLV	dd	0
itcnt	dd	0
colcnt	dd	0

;Text Box Variables:

hBox		dd	0
TmpHex		db	11 dup (0)
TmpDec		db	20 dup (0)
HexFmt		db	'%#08lx',0
DecFmt		db	'%0lu',0
CR_BLA		db	0dh, 0ah, 0

TOOLTIPS_CLASSA db	"tooltips_class32"

.code


KcommctrlInc_Start:

;================================================================================
;================ ListBox Functions =============================================

ListBoxIni	proc uses eax ebx ecx edx edi esi, handle:DWORD, identifier:DWORD

	pushf
	call	GetDlgItem, handle, identifier
	mov	hList, eax
	popf
	ret

ListBoxIni	endp

ListBoxGetSel	proc uses eax ebx ecx edx edi esi, buffer:DWORD

	ret
ListBoxGetSel	endp


ListBoxAdd	proc uses eax ebx ecx edx edi esi, string:DWORD

	pushf
	call	SendMessageA, hList, LB_ADDSTRING, 0, string
	popf
	ret

ListBoxAdd	endp

;================================================================================
;================ ListView Functions ============================================

ListViewIni	proc uses eax ebx ecx edx edi esi ebp, handle:DWORD, idListView:DWORD

	call	GetDlgItem, handle, idListView
	mov	hLV, eax
	ret
ListViewIni	endp

ListViewReset	proc uses eax ebx ecx edx edi esi ebp

	call	SendMessageA, hLV, LVM_DELETEALLITEMS, 0, 0
	mov	itcnt, 0
	ret

ListViewReset	endp

ListViewAddCol	proc uses eax ebx ecx edx edi esi ebp, width:DWORD, pstr:DWORD

	mov	eax, colcnt
	mov	clsubitem, eax
	mov	eax, width
	mov	clcx, eax
	mov	eax, pstr
	mov	dword ptr cltext, eax
	call	SendMessageA, hLV, LVM_INSERTCOLUMN, colcnt, offset lv_col
	inc	colcnt
	ret
ListViewAddCol	endp

ListViewAdd	proc uses eax ebx ecx edx edi esi ebp, pstr:DWORD

	mov	eax, itcnt
	mov	lvitem, eax
	mov	eax, pstr
	mov	dword ptr lvtext, eax
	call	SendMessageA, hLV, LVM_INSERTITEM, 0, offset lv_item
	mov	lvitem, 0
	inc	itcnt
	ret
ListViewAdd	endp

ListViewSubAdd	proc uses eax ebx ecx edx edi esi ebp, item:DWORD, place:DWORD, pstr:DWORD

	mov	eax, item
	mov	lvitem, eax
	mov	eax, place
	mov	lvsubitem, eax
	mov	eax, pstr
	mov	dword ptr lvtext, eax
	call	SendMessageA, hLV, LVM_SETITEM, 0, offset lv_item
	mov	lvitem, 0
	mov	lvsubitem, 0
	ret
ListViewSubAdd	endp

;================================================================================
;================ TextBox Functions =============================================

TextBoxIni	proc uses eax ebx ecx edx edi esi, hwnd:DWORD, ID:DWORD

	pushf
	call	GetDlgItem, [hwnd], ID
	mov	hBox, eax
	popf
	ret

TextBoxIni	endp


TextBoxHexWrite	proc uses eax ebx ecx edx edi esi, Hex:DWORD, Newline:DWORD
	
	pushf
	call	_wsprintfA, offset TmpHex, offset HexFmt, Hex
	add	esp, 12
	call	TextBoxWrite, offset TmpHex, Newline
	popf
	ret

TextBoxHexWrite	endp


TextBoxDecWrite	proc uses eax ebx ecx edx edi esi, Dec:DWORD, Newline:DWORD

	pushf
	call	_wsprintfA, offset TmpDec, offset DecFmt, Dec
	add	esp, 12
	call	TextBoxWrite, offset TmpDec, Newline
	popf
	ret

TextBoxDecWrite	endp


TextBoxWrite	proc uses eax ebx ecx edx edi esi, Str:DWORD, Newline:DWORD

	pushf
	call	GetWindowTextLengthA, hBox	; Get edit text length

	push	eax
	push    eax
	push    EM_SETSEL
	push    hBox           
	call    SendMessageA		; Set Caret to last char

	push    Str
	push    FALSE
	push    EM_REPLACESEL
	push    hBox
	call    SendMessageA		; Append new text

	call	SetFocus, hBox		; Set Focus to Edit Child

	cmp	Newline, 1		; Add Return chars ?
	jnz	WRITE
	call	TextBoxWrite, offset CR_BLA, 0

WRITE:
	popf
	ret

TextBoxWrite	endp

;================================================================================
;================ ToolTip Functions =============================================

ToolTipIni	proc uses eax ebx ecx edx edi esi

	Call	CreateWindowEx, NULL, offset TOOLTIPS_CLASSA, NULL, TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInst, NULL
	ret
ToolTipIni	endp
KcommctrlInc_End:
