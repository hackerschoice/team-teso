;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
;Structured Exception Handling for PECRYPT32 1.02
;(c) by random in 1998 
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�


SEH_Handler:
; int 3
 mov ebp,esp
 mov eax,[ebp+4]                     ; get the buffer to the exception_code
 mov esi,[eax]                       ; get the EXCEPTION CODE
 mov edi,offset EXP_Code
 call dword2hex
 mov al,"h"
 stosb
 mov ax,0D0Ah
 stosw

 mov eax,[ebp+10h - 4]               ; get the offset of another information buffer                
 mov esi,[eax+0B8h]                  ; get the EIP where the exception obcurred
 mov dword ptr [EIPDword],esi        ; save it for later use
 mov edi,offset EIP_Text
 call dword2hex                      ; convert the eip dword to a string
 mov al,"h"
 stosb
 mov ax,0D0Ah                   
 stosw

 movzx ecx,byte ptr [Module_Amount]  ; get the amount of modules in this pecrypt version
Locate_Module:
 movzx eax,byte ptr [Module_Amount]  ; get the current module
 sub eax,ecx

 shl eax,3                           ; multiply it by 8 (each module entry is 8 bytes)
 add eax,offset Module_Offsets_Sizes ; add the module buffer start
 mov ebx,[eax]                       ; get the module start (offset)

 cmp ebx,dword ptr [EIPDword]        ; compare it with the exception offset
 ja NoException_in_this_Module       ; jump if below (no exp in this module)
 add ebx,[eax+4]                     ; add the module size
 cmp ebx,dword ptr [EIPDword]        ; compare it with the exception offset
 jl NoException_in_this_Module       ; jump if above (exp not in this module)
 movzx esi,byte ptr [Module_Amount]  ; get the amount of modules in this pecrypt version        
 sub esi,ecx                         ; subtract to get the module number
 shl esi,4                           ; multiply it by 16
 add esi,offset Module_Names         ; add the module name buffer
 mov ecx,16                          ; every module name size is 16
 mov edi,offset Module_Name          ; buffer it needs to copy the name to
 rep movsb
 jmp Output_Start
NoException_in_this_Module:
 dec ecx
 jnz Locate_Module

Output_Start:
 push 30h
 push offset Exception_Topic
 push offset Exception_Code
 push 0
 call MessageBoxA


 call ExitProcess               ; exit! SEH handler finished

.Data


 Exception_Topic db "-= PECRYPT32 SEH HANDLER =-",0
  Exception_Code db "EXCEPTION CODE            : "
        EXP_Code db "           "
Exception_Module db "EXCEPTION IN MODULE  : "
     Module_Name db "                "
  Exception_Proc db "EXCEPTION IN ROUTINE : "
   Exception_EIP db "EXCEPTION ADDRESS    : "
        EIP_Text db "             "

   Module_Amount db (Module_Offsets_Sizes_End - Module_Offsets_Sizes) / 8  ; amount of all modules
        EIPDword dd 0    ; contains address where exception obcurred


Module_Names:
 db "k-commctrl.inc",CR_LF
 db "k-engine.asm  ",CR_LF
 db "k-menu.inc    ",CR_LF
 db "pe-crypt.asm  ",CR_LF
 db "r-aplib.asm   ",CR_LF
 db "r-cryptor.asm ",CR_LF
 db "r-ieh.inc     ",CR_LF
 db "r-loader.inc  ",CR_LF
 db "r-relocc.inc  ",CR_LF
 db "r-slowmte.inc ",CR_LF
 db "r-sread.inc   ",CR_LF

Module_Offsets_Sizes:
 dd offset KcommctrlInc_Start                           ; start of this inc file
 dd (offset KcommctrlInc_End - offset KcommctrlInc_Start)   ; size of this inc file
 dd offset kEngineAsm_Start                             ; start of k-engine.asm
 dd (offset kEngineAsm_End - offset kEngineAsm_Start)   ; size of it
 dd offset KMenuInc_Start                               ; start of k-menu.inc
 dd (offset KMenuInc_End - offset KMenuInc_Start)       ; size of it
 dd offset PeCryptAsm_Start                             ; start of pe-crypt.asm
 dd (offset PeCryptAsm_End - offset PeCryptAsm_Start)   ; size of it
 dd 0
 dd 0
; dd offset RAplibAsm_Start                              ; start of r-aplib.asm
; dd (offset RAplibAsm_End - offset RAplibAsm_Start)     ; size of it
 dd offset Cryptor_Start                                ; start of r-cryptor.asm
 dd (offset End_Of_Cryptor - offset Cryptor_Start)      ; size of it
 dd offset RIEHInc_Start                                ; start of r-ieh.inc
 dd (offset RIEHInc_End - offset RIEHInc_Start)         ; size of it
 dd offset CRC_Block1                                   ; start of r-loader.inc
 dd (offset ToAdd_END - offset CRC_Block1)              ; size of it
 dd offset RReloccInc_Start                             ; start of r-relocc.inc
 dd (offset RReloccInc_End - offset RReloccInc_Start)   ; size of it
 dd offset RSlowMteInc_Start                            ; start of r-slowmte.inc
 dd (offset RSlowMteInc_End - offset RSlowMteInc_Start) ; size of it
 dd offset RSreadIncStart                               ; start of r-sread.inc
 dd (offset RSreadIncEnd - offset RSreadIncStart)       ; size of it

Module_Offsets_Sizes_End:
