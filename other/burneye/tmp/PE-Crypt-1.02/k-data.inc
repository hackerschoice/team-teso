
UNICODE=0
;============================================================
;===== External Functions ===================================

extrn WritePrivateProfileStringA:PROC
extrn GetPrivateProfileStringA:PROC
extrn IsDlgButtonChecked:PROC
extrn CheckRadioButton:PROC
extrn CheckDlgButton:PROC
extrn lstrcmp:PROC
extrn EnumDisplaySettingsA:proc
extrn GetMenu:proc
extrn EnableMenuItem:proc
extrn SetWindowLongA:proc
extrn LoadMenuA:proc
extrn TrackPopupMenu:proc
extrn GetSubMenu:proc
extrn SetMenuItemInfoA:proc
extrn _wsprintfA:PROC
extrn GetWindowTextLengthA:PROC
extrn AppendMenuA:PROC
extrn GetSystemMenu:PROC
extrn TerminateThread:PROC
;============================================================
;===== Resource Constants ===================================

DLG_SPLASH          EQU     101
DLG_ABOUT           EQU     102
DLG_OPTION          EQU     103
DLG_LIST            EQU     104
DLG_MAIN            EQU     "PE-CRYPT32"

MENU_MENU           EQU     105

ITEM_OPEN           EQU     40001
ITEM_SAVE           EQU     40002
ITEM_EXIT           EQU     40003
ITEM_PROT           EQU     40004
ITEM_OPTION         EQU     40005
ITEM_ABOUT          EQU     40006

PITEM_NONE          EQU     40011
PITEM_ENC           EQU     40012
PITEM_COM           EQU     40013

ACC_OPEN            EQU     50001
ACC_EXIT            EQU     50003
ACC_PROT            EQU     50004
ACC_OPTION          EQU     50005

ICON_MAIN           EQU     106

CTL_PROGBAR         EQU     1001
CTL_EDBOX           EQU     1000
CTL_LISTVIEW        EQU     1015

BS_CANCEL           EQU     1002
;============================================================
;===== Win32 Constants ======================================

LVIS_FOCUSED            EQU	0001
LVIS_SELECTED           EQU	0002
LVIS_CUT                EQU	0004
LVIS_DROPHILITED        EQU	0008

LVIS_OVERLAYMASK        EQU	0F00
LVIS_STATEIMAGEMASK     EQU	F000

TPM_LEFTALIGN   	EQU	0000
TPM_CENTERALIGN 	EQU	0004
TPM_RIGHTALIGN  	EQU	0008

CCS_ADJUSTABLE     =     00000020h

;============================================================
;===== Variables ============================================
.DATA
     NThread_ID dd 0 ; identifier of the created thread
 NThread_Handle dd 0 ; handle of the created thread
ByteFmt		db	'%0lu Bytes',0
Bytetmp		db	30 dup (0)
PointBuf	db	30 dup (0)
FileSizeStr	db	'Filesize: ',0
NFileSizeStr	db	'New: ',0
OFileSizeStr	db	'Old: ',0
ProtectStr	db	'Press protect button',0
DoneStr		db	'All done, choose new file',0
SizeBuf		db	50 dup (0)
NFileSize	dd	0
OFileSize	dd	0
Fmt1		db	'%s %0lu Bytes',0
Fmt2		db	'%s %0lu Bytes - %s %0lu Bytes',0
szBuf		db	20 dup (0)
szBufl		equ	($-szBuf)
;General:

CancelMSG		DB	'Are you sure you want to cancel the progress ?',0
QuitMSG			DB	'Are you sure you want to quit PE-Crypt32 ?',0
NoneMSG			DB	'Are you sure you want to change the status of this section?'

			DB	0dh, 0ah,'The file may not work.',0
DialogTitle		DB 	'PE-Crypt 1.02',0
Seperator		DB	'=========================',0
SemiSep			DB	0dh, 0ah, '- - - - - - - - - - - - - - - - - - - - - - - - - -',0
OpenOK			DB	' successfully opened ..',0dh, 0ah,0
Unload			DB	'File successfully unloaded ..',0
Dialogstr		DB	'#32770',0	; standart dialog class name
Break			DB 	0dh, 0ah,0	; Return
msg			MSG	<0>
FileName2		DB	30 dup (0)
FileName		DB	260 dup (0)
TmpStrBuf		DB	30 dup (0)
GetOpen			DD	0		; Boolean: TRUE if GetOpenFile dialog is opened

lpszClassName		DD	0
szClassPE		DB	'PE-CRYPT32',0			; String for FakeWindow
szTemp			DB	20 dup (0)
szClassKI		DB	'KILLA 0000WNEZZZ',0		; String for FakeWindow
szClassRA		DB	'RANDOM RUUULEZZZ',0		; String for FakeWindow
COMMANDLINE		DD	0
COMMANDLINE2		DD	0

;Handles:

hInst			DD 	0		; Module Instance
hMain			DD	0
hPrgrs			DD	0		; Progressbar handle
hListV			DD	0		; ListView handle
hToolBar		DD	0
hOwn			DD	0

;GetOpenFileName Refs:

lStructSize		DD	4ch
hwndOwner		DD	0
hInstance		DD	0
lpstrFilter		DD	[strFilter]
lpstrCustomFilter	DD	0
nMaxCustFilter		DD	0
nFilterIndex		DD	0
lpstrFile		DD	[CryptFile]
nMaxFile		DD	128
lpstrFileTitle		DD	[FileName2] ; filebuffer
nMaxFileTitle		DD	0
lpstrInitialDir		DD	0
lpstrTitle		DD	[strTitle]
Flags			DD	OFN_HIDEREADONLY
nFileOffset		DW	0
nFileExtension		DW	0
lpstrDefExt		DD	[strDefExt]
lCustData		DD	0
lpfnHook		DD	0;offset GetOpenFunc
lpTemplateName		DD	0

strFilter		DB	'Executable Files (*.exe, *.dll)',0,'*.exe;*.dll',0,'All files (*.*)',0,'*.*',0,0
strTitle		DB	'Choose Executable..',0
strDefExt		DB	'*.exe',0

;Inifile Strings:

Section			DB	'OPTIONS',0
KeyAntiDebug		DB	'Antidebug',0
KeyVirus		DB	'Virus',0
KeyHooking		DB	'Hooking',0
KeyPE			DB	'PEHeader',0
KeyChecksums 		DB	'Checksum',0
KeyReloc		DB	'Relocation',0
KeyGC			DB	'Compression',0
KeyRC			DB	'Resource',0
KeyRelocC		DB	'RelocCompression',0
KeyBackup		DB	'Backup',0
KeyIH			DB	'ImportHiding',0
KeyAntiL		DB	'AntiMemPatch',0
KeyAntiBPX		DB	'AntiBPX',0
KeyComp			DB	'CompatibleMode',0

CSWin			DB	'Window',0
CSHang			DB	'Hang',0
Reloc12			DB	'12bit',0
Reloc16			DB	'16bit',0
RelocC			DB	'Compression',0
ResC			DB	'Compression',0
ResE			DB	'Encryption',0
IniFile			DB	'pe-crypt.ini',0
StrTrue			DB	'ON',0
StrFalse		DB	'OFF',0

;List View Strings:

SecName			DB	'Name',0
SecVadd			DB	'Virtual Offset',0
SecVsize		DB	'Virtual Size',0
SecRoff			DB	'Raw Offset',0
SecRsize		DB	'Raw Size',0
SecRchar		DB	'Characteristics',0
SecRstate		DB	'Status',0
SecNone			DB	'None',0
SecEnc			DB	'Encrypt',0
SecComp			DB	'Compress',0
SecOff			DD	[SecNone]
			DD	[SecEnc]
			DD	[SecComp]
Sectmp			DB	12 dup (0)
Seccnt			DD	0

SectionData             DB      (28*50) dup (0) ; space for 50 sections
SectionStates           DB      50 dup (0)

;Structures:

wc		WNDCLASSEX		<0>

RectData:
rd_left			DD	0
rd_top			DD	0
rd_right		DD	0
rd_bottom		DD	0

DevData:
			DB	42 dup (0ffh)
dmBitsPerPel		DD	0
dmPelsWidth		DD	0
dmPelsHeight		DD	0
dmDisplayFlags		DD	0
dmDisplayFrequency	DD	0

Menuiteminfo:
cbsize			DD	2ch
fMask			DD	11h	;MIIM_CHECKMARKS
fType			DD	200h	;MFT_RADIOCHECK
fState			DD	8	;MFS_CHECKED
wID			DD	0
hSubMenu		DD	0
			DD	0, 0, 0, 0,0 

BOpenLabel		DB	'Open',0
BExitLabel		DB	'Exit',0
BProtectLabel		DB	'Protect',0
BOptionsLabel		DB	'Options',0
BAboutLabel		DB	'About',0

tdbutton:
i0Bitmap		DD	2
i0dCommand		DD	0
f0sState		DB	TBSTATE_ENABLED
f0sStyle		DB	TBSTYLE_SEP
d0wData			DD	0
i0String		DD	[BOpenLabel]

i1Bitmap		DD	1
i1dCommand		DD	ITEM_OPEN
f1sState		DB	TBSTATE_ENABLED	
f1sStyle		DB	0
d1wData			DD	0
i1String		DD	[BOpenLabel]

i2Bitmap		DD	0
i2dCommand		DD	0
f2sState		DB	TBSTATE_ENABLED
f2sStyle		DB	TBSTYLE_SEP
d2wData			DD	0
i2String		DD	0

i3Bitmap		DD	3
i3dCommand		DD	ITEM_PROT
f3sState		DB	TBSTATE_ENABLED
f3sStyle		DB	0
d3wData			DD	0
i3String		DD	[BProtectLabel]

i4Bitmap		DD	4
i4dCommand		DD	ITEM_OPTION
f4sState		DB	TBSTATE_ENABLED
f4sStyle		DB	0
d4wData			DD	0
i4String		DD	[BOptionsLabel]

i5Bitmap		DD	0
i5dCommand		DD	0
f5sState		DB	TBSTATE_ENABLED
f5sStyle		DB	TBSTYLE_SEP
d5wData			DD	0
i5String		DD	0

i6Bitmap		DD	6
i6dCommand		DD	ITEM_ABOUT
f6sState		DB	TBSTATE_ENABLED
f6sStyle		DB	0
d6wData			DD	0
i6String		DD	[BAboutLabel]

i7Bitmap		DD	7
i7dCommand		DD	ITEM_EXIT
f7sState		DB	TBSTATE_ENABLED
f7sStyle		DB	0
d7wData			DD	0
i7String		DD	[BExitLabel]

TOOLINFO:
ti_cbSize		DD	28
ti_uFlags		DD	1;TTF_IDISHWND
ti_hwnd			DD	0
ti_uId			DD	0
ti_rect			DD	0
ti_hinst		DD	0
blatext			DD	[BExitLabel]