;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;               PECRYPT32 1.02 (c) in 1998 by random and killa 
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;THIS PROGRAM IS COPYRIGHT (c) BY RANDOM TECHNOLOGIES IN 1997/1998
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
 THREAD_MAX_PRIORITY   equ 02h       ; dunno why it need it again


CRC_Block1:
ToAdd:
 call $+5
 pop ebx
 sub ebx,5
 jmp JumpAboveSignature
PESignature:
 db "RND!"                                         ; signature for
JumpAboveSignature:                                ; the heuristic PE Virus
 F1CKEN5
 F1CKEN4 0EAh

 push esi                                          ; detection
 push edi
 push ebp
 F1CKEN4 0ECh
 mov dword ptr [(SAVEESP2 - offset ToAdd) + ebx],esp
 mov ebp,ebx
 CONFUSE2 02H
 
 cmp byte ptr [(EXEFLAGS - offset ToAdd) + ebx],0
 jz NoDll_File
 cmp byte ptr [ALDONE - offset ToAdd + ebx],1
 jz DllExitCode_Execution
 mov byte ptr [ALDONE - offset ToAdd + ebx],1

NoDll_File:
 cmp byte ptr [(TEMPVARI - offset ToAdd + ebx)],0
 jnz DontCalcNew
 mov eax,dword ptr [NEWIBASE - offset ToAdd + ebx]  ; get the imagebasevalue
 push ebx
 sub ebx,eax                         ; subtract it from the current adress!

 F1CKEN2 0FFh
 mov dword ptr [NEWIBASE - offset ToAdd + ebp],ebx  ; save it
 mov byte ptr [(TEMPVARI - offset ToAdd + ebp)],0190
 pop ebx
 CONFUSE 01h                                       ; Confusing jump crap

DontCalcNew:
 jmp StartwithEncryption

DllError2:
 F1CKEN3 0EAh
 push 30h
 F1CKEN5
 mov eax,(offset ERRORMH - offset ToAdd)
 add eax,ebx
 push eax
 F1CKEN2 0EAh

 mov eax,(offset ERRORM - offset ToAdd)
 add eax,ebx
 push eax
 push 0

 F1CKEN4 0EAh
 mov edx,(offset _USER32 - offset ToAdd)    ; offset of the USER32.DLL
 add edx,ebx

 F1CKEN2 0EAh

 push edx
 push edx
 call dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx] ; call "GetmoduleHandle"
 or eax,eax
 jnz ALreadyLoaded
 pop edx
 push edx
 call dword [(offset Thunktable+4+4-4 - offset ToAdd)+ebx]
ALreadyLoaded:

 F1CKEN3 0EAh
 mov edx,(offset f_MessageBoxA - offset ToAdd)
 add edx,ebx

 F1CKEN2 0EAh

 push edx
 push eax
 call dword ptr [(Thunktable - offset ToAdd)+ebx]   ; call "GetProcAddress"
 call eax

 F1CKEN4 0EAh

 mov edx,(offset ModuleDLL - offset ToAdd)    ; offset of the _KERNEL32
 add edx,ebx
 F1CKEN5
 push edx
 call dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx] ; call "GetmoduleHandle"

 F1CKEN 0FFh
 mov esi,(offset f_ExitProcess - offset ToAdd)  ; offset of the function
 add esi,ebx
 push esi
 push eax
 call dword ptr [(Thunktable - offset ToAdd)+ebx]   ; call "GetProcAddress"
 F1CKEN2 0EAh

 push 0FFh
 call eax                                   ; quit

StartwithEncryption:

 F1CKEN5
 mov edx,(offset ModuleDLL - offset ToAdd)                         ; offset of the _KERNEL32
 add edx,ebx
 CONFUSE 08h                                                       ; Confusing jump crap

 push edx
 F1CKEN4 0EAh
 push edx
 call dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx]
 mov dword ptr [(Kernel32RVA - offset ToAdd) + ebx],eax            ; save kernel32.dll rva

 F1CKEN4 0EAh
 mov esi,(offset Open_Process - offset ToAdd)
 add esi,ebx
 CONFUSE 03h                                                       ; Confusing jump crap
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0EAh
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(OpenProcessRVA - offset ToAdd) + ebx],eax         ; save 'OpenProcess' RVA
 CONFUSE 09h                                                       ; Confusing jump crap

 F1CKEN4 0EAh
 mov esi,(offset GetTickCountFunction - offset ToAdd)
 add esi,ebx
 push esi
 F1CKEN4 0F7h
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(GetTickCountRVA - offset ToAdd) + ebx],eax        ; save it

 F1CKEN5

 mov esi,(offset GetTickCountFunction - offset ToAdd)
 add esi,ebx
 F1CKEN4 0E8h
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0EAh
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(GetTickCountRVA - offset ToAdd) + ebx],eax        ; save it

 mov esi,(offset f_CreateFileA - offset ToAdd)
 add esi,ebx
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0EAh
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 F1CKEN5
 mov dword ptr [(FunctionRVA - offset ToAdd) + ebx],eax

 F1CKEN4 0E9h
 cmp byte ptr [(EXEFLAGS - offset ToAdd) + ebx],1
 jz Encrypted_Thread_Block

 mov esi,(offset SetPriority_Class - offset ToAdd)
 add esi,ebx
 push esi
 F1CKEN4 0EAh
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(SetPriorityClassRVA - offset ToAdd) + ebx],eax    ; save 'SetPriorityClass' RVA

 F1CKEN5
 mov esi,(offset Create_Thread - offset ToAdd)
 add esi,ebx
 F1CKEN4 0EAh
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(CreateThreadRVA - offset ToAdd) + ebx],eax        ; save 'CreateThread' RVA

 F1CKEN4 0EAh
 mov esi,(offset SetThread_Priority - offset ToAdd)
 add esi,ebx
 F1CKEN4 0EFh
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0EAh
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(SetThreadPriorityRVA - offset ToAdd) + ebx],eax   ; save 'SetThreadPriority' RVA

 F1CKEN5
 mov esi,(offset Terminate_Thread - offset ToAdd)
 add esi,ebx
 F1CKEN4 0F7h
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(TerminateThreadRVA - offset ToAdd) + ebx],eax      ; save 'TerminateThread' RVA

 F1CKEN5
 mov esi,(offset CreateEvent_A - offset ToAdd)
 F1CKEN4 0EAh
 add esi,ebx
 push esi
 F1CKEN4 0EAh
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(CreateEventARVA - offset ToAdd) + ebx],eax        ; save 'CreateEvent' RVA

 CONFUSE 04h                                                       ; Confusing jump crap

 F1CKEN5
 mov esi,(offset WaitForSingle_Object - offset ToAdd)
 add esi,ebx
 F1CKEN4 0F7h
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0EAh
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(WaitForSingleObjectRVA - offset ToAdd) + ebx],eax ; save 'WaitForSingleObject' RVA

 F1CKEN5
 mov esi,(offset Set_Event - offset ToAdd)
 add esi,ebx
 push esi
 F1CKEN4 0F7h
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(SetEventRVA - offset ToAdd) + ebx],eax            ; save 'SetEvent' RVA

 mov esi,(offset Reset_Event - offset ToAdd)
 F1CKEN4 0EAh
 add esi,ebx
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0EAh
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(ResetEventRVA - offset ToAdd) + ebx],eax          ; save 'ResetEvent' RVA

 F1CKEN5
 mov esi,(offset Suspend_Thread - offset ToAdd)
 add esi,ebx
 push esi
 F1CKEN4 0E8h
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(SuspendThreadRVA - offset ToAdd) + ebx],eax       ; save 'SuspendThread' RVA

 mov esi,(offset Resume_Thread - offset ToAdd)
 add esi,ebx
 push esi
 F1CKEN4 0E8h
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 F1CKEN4 0EAh
 mov dword ptr [(ResumeThreadRVA - offset ToAdd) + ebx],eax        ; save 'ResumeThread' RVA

 mov esi,(offset GetCurrentProcess_Id - offset ToAdd)
 add esi,ebx
 push esi
 F1CKEN4 0E8h
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"

 F1CKEN4 0EAh
 call eax                                                          ; call GetCurrentProcessId

 F1CKEN5
 push eax                                                          ; push processid
 F1CKEN4 0E8h
 push 0
 push PROCESS_SET_INFORMATION+DEBUG_ONLY_THIS_PROCESS              ; enable set information flag & debug flag
 call dword ptr [(OpenProcessRVA - offset ToAdd) + ebx]
 mov dword ptr [(PROCESSHANDLE - offset ToAdd) + ebx],eax          ; save the process handle

 push REALTIME_PRIORITY_CLASS
 F1CKEN4 0EAh
 push eax                                                          ; push process handle
 call dword ptr [(SetPriorityClassRVA - offset ToAdd) + ebx]

 mov edx,(offset Thread_ID2 - offset ToAdd)
 add edx,ebx
 push edx
 F1CKEN4 0EAh
 push CREATE_SUSPENDED                                             ; create a thread which runs after resumethread
 push 0
 mov edx,(offset Thread_Handler_2 - offset ToAdd)
 add edx,ebx
 F1CKEN4 0E8h
 push edx
 push 0
 push 0
 F1CKEN4 0EAh
 call dword ptr [(CreateThreadRVA - offset ToAdd) + ebx]
 mov dword ptr [(Thread_Handle2 - offset ToAdd) + ebx],eax         ; save thread handle

 push THREAD_MAX_PRIORITY
 F1CKEN4 0E8h
 push dword ptr [(Thread_Handle2 - offset ToAdd) + ebx]            ; push thread id
 call dword ptr [(SetThreadPriorityRVA - offset ToAdd) + ebx]

 push 0                                                            ; no event name needed niggaz
 push 0                                                            ; initial state = non signaled
 F1CKEN4 0E8h
 push 0                                                            ; wtf??
 push 0                                                            ; default security descriptor is enough
 call dword ptr [(CreateEventARVA - offset ToAdd) + ebx]           ; create the event
 mov dword ptr [(EventO_Handle2 - offset ToAdd) + ebx],eax         ; save the handle of the created event object

 F1CKEN5
 push 0                                                            ; no event name needed niggaz
 push 0                                                            ; initial state = non signaled
 F1CKEN4 0E8h
 push 0                                                            ; wtf??
 push 0                                                            ; default security descriptor is enough
 F1CKEN4 0E8h
 call dword ptr [(CreateEventARVA - offset ToAdd) + ebx]
 mov dword ptr [(EventO_Handle22 - offset ToAdd) + ebx],eax        ; save the handle of the created event object

 F1CKEN4 0E8h
 push dword ptr [(Thread_Handle2 - offset ToAdd) + ebx]            ; push thread handle
 F1CKEN4 0E8h
 call dword ptr [(ResumeThreadRVA - offset ToAdd) + ebx]
 mov esi,(offset Encrypted_Thread_Block_End - 4 - offset ToAdd)
 add esi,ebx
 F1CKEN4 0F7h
 mov edi,esi
 mov ecx,(offset Encrypted_Thread_Block_End - Encrypted_Thread_Block) / 4
 F1CKEN4 0EAh
 mov edx,dword ptr [(VALUE_THREAD - offset ToAdd) + ebx]           ; get the initial state
 mov dword ptr [(SaveECX2 - offset ToAdd) + ebx],ecx               ; save ECX initial state
 F1CKEN4 0F7h
 mov dword ptr [(SaveEDX2 - offset ToAdd) + ebx],edx               ; save the initial state of EDX

 std
Encrypt_Block1_2:
 lodsd
 mov dword ptr [(Byte2Encrypt2 - offset ToAdd) + ebx],eax          ; save the byte which needs to get encrypted

 pusha
 mov dword ptr [(SAVEESP3 - offset ToAdd) + ebx],esp
 F1CKEN4 0F7h
 push dword ptr [(EventO_Handle2 - offset ToAdd) + ebx]            ; push event handle
 call dword ptr [(SetEventRVA - offset ToAdd) + ebx]
 push 0FFFFFFFFh                   ; wait forever ;)
 push dword ptr [(EventO_Handle22 - offset ToAdd) + ebx]           ; push the handle of the 2nd event
 F1CKEN4 0F7h
 call dword ptr [(WaitForSingleObjectRVA - offset ToAdd) + ebx]

 push dword ptr [(EventO_Handle22 - offset ToAdd) + ebx]           ; push the handle of the 2nd event
 F1CKEN4 0E9h
 call dword ptr [(ResetEventRVA - offset ToAdd) + ebx]
 mov esp,dword ptr [(SAVEESP3 - offset ToAdd) + ebx]
 popa
 F1CKEN4 0E9h
 mov eax,dword ptr [(Byte2Encrypt2 - offset ToAdd) + ebx]          ; get the encrypted dword
 stosd
 dec ecx
 mov dword ptr [(SaveECX2 - offset ToAdd) + ebx],ecx               ; save the current ECX value
 jnz Encrypt_Block1_2

 cld

 CONFUSE 03h                                                       ; Confusing jump crap
 push 0
 F1CKEN4 0E9h
 push dword ptr [(Thread_Handle2 - offset ToAdd) + ebx]            ; push the thread handle
 call dword ptr [(TerminateThreadRVA - offset ToAdd) + ebx]        ; terminate the thread

 F1CKEN4 0E9h
 push NORMAL_PRIORITY_CLASS
 push dword ptr [(PROCESSHANDLE - offset ToAdd) + ebx]             ; push process handle
 call dword ptr [(SetPriorityClassRVA - offset ToAdd) + ebx]
 jmp Encrypted_Thread_Block

Thread_Handler_2:
Restart_Thread_2:

 pusha
 call $+5
RelocateCode:
 pop ebx
 sub ebx,(RelocateCode - offset ToAdd)

 push 0FFFFFFFFh                   ; wait forever ;)
 F1CKEN4 0E9h
 push dword ptr [(EventO_Handle2 - offset ToAdd) + ebx]            ; event handle is needed
 call dword ptr [(WaitForSingleObjectRVA - offset ToAdd) + ebx]

 push dword ptr [(EventO_Handle2 - offset ToAdd) + ebx]            ; event handle is needed
 F1CKEN4 0E9h
 call dword ptr [(ResetEventRVA - offset ToAdd) + ebx]

 mov edx,dword ptr [(SaveEDX2 - offset ToAdd) + ebx]               ; get the saved EDX value
 F1CKEN4 0E9h
 mov ecx,(offset Encrypted_Thread_Block - offset CRC_Block1) / 4

 mov esi,(offset CRC_Block1 - offset ToAdd)
 F1CKEN4 0E9h
 add esi,ebx

Generate_Thread_CRC_2:
 mov eax,[esi]
 xor edx,eax
 not edx
 xor edx,ecx
 add edx,eax
 add esi,4
 dec ecx
 jnz Generate_Thread_CRC_2

 mov eax,dword ptr [(Byte2Encrypt2 - offset ToAdd) + ebx]
 xor eax,edx

 push edi

 push esi
 push eax
 push ecx
 mov esi,(offset PEText - offset ToAdd)
 add esi,ebx
 mov ecx,(ToAdd_END - offset PEText)
 shr ecx,2
 xor eax,eax
EncryptStuff_1:
 xor eax,[esi]
 not eax
 xor eax,ecx
 add esi,4
 dec ecx
 jnz EncryptStuff_1
 mov edi,eax
 pop ecx
 pop eax
 pop esi

 xor eax,edi
 pop edi

 F1CKEN4 0E9h
 mov dword ptr [(Byte2Encrypt2 - offset ToAdd) + ebx],eax

 xor edx,dword ptr [(SaveECX2 - offset ToAdd) + ebx]
 F1CKEN4 0E9h
 mov dword ptr [(SaveEDX2 - offset ToAdd) + ebx],edx

 push dword ptr [(EventO_Handle22 - offset ToAdd) + ebx]           ; push event handle
 call dword ptr [(SetEventRVA - offset ToAdd) + ebx]
 popa
 jmp Restart_Thread_2

Encrypted_Thread_Block:


Encrypted_Running_Line_Block:

 F1CKEN2 0EAh

 mov edx,(offset ModuleDLL - offset ToAdd)                         ; offset of the _KERNEL32
 add edx,ebx

 call [(GetTickCountRVA - offset ToAdd) + ebx]
 mov dword ptr [(SAVETIME - offset ToAdd) + ebx],eax

 CONFUSE 03h                                                       ; Confusing jump crap

 mov edx,(offset ModuleDLL - offset ToAdd)                        ; offset of the _KERNEL32
 add edx,ebx
 F1CKEN4 0F7h
 mov esi,(offset f_VirtualAlloc - offset ToAdd)                   ; offset of the function
 add esi,ebx

 CONFUSE 03h                                                       ; Confusing jump crap

 F1CKEN4 0F7h
 push edx
 push edx
 call dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx]       ; call "GetmoduleHandle"

 push esi
 F1CKEN4 0F7h
 push eax
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                ; call "GetProcAddress"
 mov dword ptr [(F2RVA - offset ToAdd) + ebx],eax

 F1CKEN5
 push 0
 push 4
 push 1000h
 CONFUSE 03h                                                       ; Confusing jump crap
 push 1024                                         ; 1kb is needed
 push 0                                            ; call the function
 call dword ptr [F2RVA - offset ToAdd + ebx]       ; and allocate memory
 mov dword ptr [(hash_seg - offset ToAdd) + ebx],eax ; save the memory offset

 F1CKEN4 0F7h
 push 0
 push 4
 push 1000h
 F1CKEN4 0F7h
 push 10000                                        ; about 10kb are needed
 push 0                                            ; call the function
 call dword ptr [F2RVA - offset ToAdd + ebx]       ; and allocate memory
 mov dword ptr [(LayerBuffer  - offset ToAdd) + ebx],eax

 F1CKEN5
 push 0
 push 4
 CONFUSE 03h                                                       ; Confusing jump crap
 push 1000h
 push 1024                                         ; 1kb is needed for the rvatable
 CONFUSE 03h                                                       ; Confusing jump crap
 push 0                                            ; call the function
 call dword ptr [F2RVA - offset ToAdd + ebx]       ; and allocate memory
 mov dword ptr [(RVATABLE - offset ToAdd) + ebx],eax ; save the memory offset

 CONFUSE 03h                                                       ; Confusing jump crap
 mov ebx,ebp
 mov esi,(offset Encrypted_Block1_End - offset ToAdd)-1
 F1CKEN3 0EAh
 add esi,ebx
 mov edi,esi

 F1CKEN2 0FFh
 mov ecx,(offset Encrypted_Block1_End - offset Encrypted_Block1) / 4
 mov edx,dword ptr [(START_VALUE - offset ToAdd) + ebx]
 F1CKEN4 0F7h
 std
Decrypt_Block1:

 jmp JumpOva2
MutateCRC2:
 dd 0
JumpOva2:
 push esi
 push ecx
 mov ecx,(offset CRC_Block1_End - offset offset CRC_Block1) / 4
 xor esi,esi
 add esi,ebx
GenerateFirst_CRC:
 mov eax,[esi]
 xor edx,eax
 xor edx,ecx
 add esi,4
 dec ecx
 jnz GenerateFirst_CRC
 pop ecx
 pop esi
 jmp JumpOva
MutateCRC1:
 dd 0
JumpOva:
 lodsd
 xor eax,edx
 stosd
 inc dword ptr [(MutateCRC2 - offset ToAdd) + ebx]
 rol dword ptr [(MutateCRC1 - offset ToAdd) + ebx],cl
 add dh,byte ptr fs:[23h]
 xor edx,ecx
 F1CKEN2 0EAh
 dec ecx
 jnz Decrypt_Block1
CRC_Block1_End:
Encrypted_Thread_Block_End:
Encrypted_Running_Line_Block_End:

Encrypted_Block1:
 cld
; F1CKEN2 0FFh

 mov dword ptr [(MutateCRC2 - offset ToAdd) + ebx],0
; F1CKEN3 0EAh
 mov dword ptr [(MutateCRC1 - offset ToAdd) + ebx],0


;Table for the SlowMutation Engine
;will be filled with decryption layers ;)
;
;

LayerTable:
 db 1400 dup (90h)

Layer_Table_End:
;End of the slow mutating layers
;
;
;
 
 F1CKEN4 0F7h
 mov edx,(offset ModuleDLL - offset ToAdd)
 add edx,ebx
 F1CKEN4 0F7h
 mov edi,10
 call RandomizeValue
 xchg ecx,eax

FakeRVAJumpAgain:
 mov edi,dword ptr [(CODESIZE - offset ToAdd) + ebx]        ; load the maximum size
 sub edi,100
 call RandomizeValue
 xchg eax,edi
 add edi,dword ptr [NEWIBASE - offset ToAdd + ebx]          ; add the calculated imagebase
 F1CKEN4 0F7h
 add edi,dword ptr [CODEBASE - offset ToAdd + ebx]          ; add the codebase

 push edi
 mov edi,3
 F1CKEN4 0F7h
 call RandomizeValue
 pop edi
 cmp eax,1
 ja UseProgramCODESECTION
 mov edi,dword ptr [(hash_seg - offset ToAdd) + ebx]

UseProgramCODESECTION:
 mov dword ptr [(CODEOFS2 - offset ToAdd) + ebx],edi        ; save it
 pusha
 mov esi,edi
 mov edi,dword ptr [(RVATABLE - offset ToAdd) + ebx]
 mov ecx,200
 rep movsb
 popa

 push ecx
 F1CKEN4 0F7h
 push edi
 mov edi,20
 call RandomizeValue
 pop edi
 xchg eax,ecx
 mov al,90h
 F1CKEN4 0F7h
 rep stosb
 pop ecx

 F1CKEN4 0F7h
 push edi
 mov edi,5
 call RandomizeValue
 pop edi

 F1CKEN4 0F7h
 mov edx,(ContinueMan - offset ToAdd)
 add edx,ebx

 cmp eax,1
 jnz Dontuseedx

Dontuseedx:
 F1CKEN4 0F7h
 cmp eax,2
 jnz Dontuseedi
 F1CKEN4 0F7h
 movzx eax,word ptr [(offset InstructionTable - offset ToAdd) + (eax * 2) + ebx]
 stosw
 mov edi,edx
 jmp AlreadyPatched
Dontuseedi:
 cmp eax,3
 jnz Dontuseesi
 mov esi,edx
Dontuseesi:
 cmp eax,4
 jnz Dontuseebp
 mov ebp,edx
Dontuseebp:
 or eax,eax
 jnz Dontuseecx
 mov ecx,edx
Dontuseecx:
 F1CKEN4 0F7h
 movzx eax,word ptr [(offset InstructionTable - offset ToAdd) + (eax * 2) + ebx]
 stosw

AlreadyPatched:
 F1CKEN4 0F7h
 pusha
 mov eax,dword ptr [(CODEOFS2 - offset ToAdd) + ebx]
 jmp eax

ContinueMan:
 popa

 pusha
 mov esi,dword ptr [(offset RVATABLE - offset ToAdd) + ebx]
 mov edi,dword ptr [(CODEOFS2 - offset ToAdd) + ebx]
 mov ecx,200
 F1CKEN4 0F7h
 rep movsb
 popa

 dec ecx
 jnz FakeRVAJumpAgain


BahDasStinkt:
 F1CKEN4 0F7h
 mov edi,dword ptr [(offset RVATABLE - offset ToAdd) + ebx]
 mov ecx,(1000 / 4)
 xor eax,eax
 F1CKEN4 0F7h
 rep stosd
 mov ebp,ebx

 F1CKEN2 0FEh


 call [(GetTickCountRVA - offset ToAdd) + ebx]
 sub eax,dword ptr [(SAVETIME - offset ToAdd) + ebx]
 F1CKEN2 0FEh
 cmp eax,6000
 jae Encrypt_Block1_2

 cmp byte ptr [(HEURISTIC - offset ToAdd) + ebx],0
 jz HeuristicPassed
 mov edi,[(NEWIBASE - offset ToAdd) + ebp]              ; get the header start
 F1CKEN3 0FCh
 add edi,[edi+3Ch]

 F1CKEN2 0FEh

 mov edx,[edi+40]
 F1CKEN4 0F7h
 add edx,[(NEWIBASE - offset ToAdd) + ebp]              ; get the header start
 F1CKEN3 0FCh
 cmp dword ptr [edx+0Bh],"!DNR"                         ; check for the PEcrypt32 signature
 jz HeuristicPassed

 mov ax,[edi+6]                                         ; get the obj number
 cmp ax,word ptr [(OBJNUMBA - offset ToAdd) + ebp]      ; compare with the
 jz NoHeuristicAlert                                    ; saved one, alert if
HeuristicAlert:                                         ; changed
 push 30h
 mov eax,(offset HeuristicA1H - offset ToAdd)
 add eax,ebx
 F1CKEN2 0FFh
 push eax
 mov eax,(offset HeuristicA1 - offset ToAdd)
 add eax,ebx
 push eax
 push 0
 F1CKEN2 0FEh
 jmp MboxError
GetSystem_Time        db "GetSystemTime",0

Unexpected_Exception_Handler:

Patch_EBX:
 mov ebx,0190h
Patch_ECX:
 mov ecx,0190h
Patch_ESI:
 mov esi,0190h
Patch_EDX:
 mov edx,0190h
 mov ebp,ebx
 mov edi,esi

 rol edx,cl
 rol dword ptr [(offset VALUE6 - offset ToAdd) + ebx],cl
 xor dword ptr [(offset VALUE5 - offset ToAdd) + ebx],ecx
 jmp FinishedWithUnexpectedException

NoHeuristicAlert:
 mov edx,edi
 CONFUSE2 02H
 add edi,dword ptr [(LOBJ - offset ToAdd) + ebp]        ; pointer to the virtual size
 mov eax,[edi+8]                                        ; get the vsize

 F1CKEN2 0FEh
 cmp eax,dword ptr [(LSIZE - offset ToAdd) + ebp]       ; compare it with the saved one
 jz HeuristicPassed                                     ; the same? then passed
 F1CKEN2 0FEh
 mov edx,[edx+40]
 add edx,[(NEWIBASE - offset ToAdd) + ebp]              ; get the header start
 F1CKEN3 0FCh
 cmp dword ptr [edx+0Bh],"!DNR"
 jnz HeuristicAlert

HeuristicPassed:


 mov edi,(offset LayerTable - offset ToAdd)
 F1CKEN4 0F7h
 add edi,ebx
 mov ecx,(1000 / 4)
 mov eax,90909090h
 F1CKEN4 0F7h
 rep stosd

 F1CKEN4 0F7h

 cmp byte ptr [(AMETHOD - offset ToAdd) + ebx],0
 jz InstallExceptionHandler

 mov edx,(offset SICEVXD - offset ToAdd)
 add edx,ebx
 push 0

 F1CKEN4 0F7h
 push 80h
 push 3
 push 0
 push 3

 F1CKEN4 0F7h
 push 80000000h
 push edx
 push dword ptr [(FunctionRVA - offset ToAdd) + ebx]
 F1CKEN4 0F7h
 call CallApi

 cmp eax,0FFFFFFFFh
 jz NoSoftIceInstalled

NTICE_OR_WINICE_INSTALLED:
 F1CKEN4 0F7h
 push 30h
 mov eax,(offset SICEErrorHead - offset ToAdd)
 F1CKEN4 0F7h
 add eax,ebx
 push eax
 mov eax,(offset SICEError - offset ToAdd)
 add eax,ebx
 F1CKEN4 0F7h
 push eax
 push 0
 mov edx,(offset _USER32 - offset ToAdd)        ; offset of the dllname
 F1CKEN4 0F7h
 add edx,ebx
 mov esi,(offset f_MessageBoxA - offset ToAdd)  ; offset of the function
 F1CKEN4 0F7h
 add esi,ebx
 Call GetApi                                    ; get the rva of this function
 F1CKEN4 0F7h

 push eax
 call CallApi

 mov edx,(offset ModuleDLL - offset ToAdd)        ; offset of the dllname
 add edx,ebx
 mov esi,(offset f_ExitProcess - offset ToAdd)  ; offset of the function
 add esi,ebx
 Call GetApi                                    ; get the rva of this function
 push 0FFh
 push eax
 Call CallApi

NoSoftIceInstalled:
 mov edx,(offset NTICEVXD - offset ToAdd)
 add edx,ebx
 push 0

 F1CKEN4 0E9h
 push 80h
 push 3
 push 0
 push 3
 F1CKEN4 0F7h
 push 80000000h
 push edx
 call dword ptr [(FunctionRVA - offset ToAdd) + ebx]
 F1CKEN4 0E9h
 cmp eax,0FFFFFFFFh
 jnz NTICE_OR_WINICE_INSTALLED

EncryptedAntiDebuggingLayer_1_Start:
 mov edx,(offset ModuleDLL - offset ToAdd)        ; offset of the dllname
 add edx,ebx
 F1CKEN4 0E9h
 mov esi,(offset f_SetUnhandledExceptionFilter - offset ToAdd)
 add esi,ebx
 call GetApi

 mov edx,(offset Unexpected_Exception_Handler - offset ToAdd)
 add edx,ebx
 push edx
 F1CKEN4 0E9h
 call eax
 mov dword ptr [(offset HANDLER - offset ToAdd) + ebx],eax

 mov dword ptr [(offset Patch_EBX - offset ToAdd +1 )+ ebx],ebx

 F1CKEN4 0EFh
 mov esi,(offset CPL0_NOT_ACTIVE - offset ToAdd)
 add esi,ebx
 F1CKEN 0FFh
 mov edi,esi
 mov ecx,(offset InCPL3 - offset CPL0_NOT_ACTIVE) / 4
 F1CKEN 0FFh
 mov edx,dword ptr [(offset VALUE6 - offset ToAdd) + ebx]
Decrypt_First_Antidebugging_Layer:
 push esi
 push ecx
 mov ecx,(offset EncryptedAntiDebuggingLayer_1_End - offset HeuristicPassed) / 4
 F1CKEN 0FFh
 mov esi,(offset HeuristicPassed - offset ToAdd)
 add esi,ebx
Generate_CRC_overFirst_Antidebugging_Layer:
 mov eax,[esi]
 xor edx,eax
 xor edx,ecx
 add esi,4
 dec ecx
 jnz Generate_CRC_overFirst_Antidebugging_Layer
 pop ecx
 pop esi
 jmp JumpAboveConfusingTrick
 VALUE5 dd 0
f_SetUnhandledExceptionFilter:
 db "SetUnhandledExceptionFilter",0
f_VirtualProtect:
 db "VirtualProtect",0
SICEVXD:
 db "\\.\SICE",0
 VALUE6 dd 0
NTICEVXD:
 db "\\.\NTICE",0
JumpAboveConfusingTrick:
 F1CKEN 0FFh
 mov dword ptr [(offset Patch_ECX - offset ToAdd +1 )+ ebx],ecx
 mov dword ptr [(offset Patch_ESI - offset ToAdd +1 )+ ebx],esi
 F1CKEN 0FFh
 mov dword ptr [(offset Patch_EDX - offset ToAdd +1 )+ ebx],edx

 mov ebp,'BCHK'
 mov eax, 4
 int 03h
FinishedWithUnexpectedException:
 lodsd
 xor eax,edx
 stosd
 xor edx,ecx
 inc dword ptr [(offset VALUE5 - offset ToAdd) + ebx]
 F1CKEN 0FFh
 xor dword ptr [(offset VALUE6 - offset ToAdd) + ebx],ecx
 dec ecx
 jnz Decrypt_First_Antidebugging_Layer
EncryptedAntiDebuggingLayer_1_End:

CPL0_NOT_ACTIVE:
 mov edx,(offset ModuleDLL - offset ToAdd)        ; offset of the dllname
 add edx,ebx
 mov esi,(offset f_SetUnhandledExceptionFilter - offset ToAdd)
 add esi,ebx
 call GetApi
 mov edx,dword ptr [(offset HANDLER - offset ToAdd) + ebx]
 push edx
 F1CKEN4 0EFh
 call eax

 mov dword ptr [(VALUE5 - offset ToAdd) + ebx],0
 F1CKEN 0FFh
 mov dword ptr [(VALUE6 - offset ToAdd) + ebx],0
 F1CKEN 0FFh
 mov dword ptr [(offset Patch_EBX - offset ToAdd +1 )+ ebx],0190h
 F1CKEN 0FFh
 mov dword ptr [(offset Patch_ECX - offset ToAdd +1 )+ ebx],0190h
 F1CKEN 0FFh
 mov dword ptr [(offset Patch_ESI - offset ToAdd +1 )+ ebx],0190h
 F1CKEN 0FFh
 mov dword ptr [(offset Patch_EDX - offset ToAdd +1 )+ ebx],0190h

 mov ebp,ebx
 mov edx,(offset Exception_Handler - offset ToAdd)
 add edx,ebx
 push edx
 push dword ptr fs:[0]
 mov fs:[0],esp
 mov dword ptr [(PIZZA - offset ToAdd) + ebx],esp

 mov esi,(offset InCPL3 - offset ToAdd)
 add esi,ebx
 mov edi,esi
; mov ecx,(offset EncryptLayer3_End - offset InCPL3) / 4
 mov ecx,(offset EncryptedLayer_4_Start - offset InCPL3) / 4

 mov edx,dword ptr [(ENCRYPTV11 - offset ToAdd) + ebx]
Decrypt_AD_Block:
 push esi
 push ecx
 mov ecx,(offset InCPL3 - offset NoHeuristicAlert) / 4
 mov esi,(offset NoHeuristicAlert - offset ToAdd)
 add esi,ebx
GenerateAD_CRC_2:
 mov eax,[esi]
 xor edx,eax
 xor edx,ecx
 add esi,4
 dec ecx
 jnz GenerateAD_CRC_2
 pop ecx
 pop esi
 lodsd
 xor eax,edx
 stosd
 sidt fword ptr [(IDTVALUE - offset ToAdd) + ebx]         ; get the IDT
 mov esi,dword ptr [(IDTVALUE - offset ToAdd)+ 2 + ebx]   ; get the interrupt table offset
Possible_Second_Exception:
 mov [esi+8],ecx                                          ; overwrite the int 1 data
 xor edx,dword ptr [(offset VALUE4 - offset ToAdd) + ebx] ; simple xor but effective ;)
 mov esi,edi
 jmp JumpaboveMutation
 VALUE3 dd 0
 VALUE4 dd 0
Exception_Handler:
 mov ebp,esp
 mov eax,[ebp+0Ch]                                        ; get the offset of another information buffer
 mov ebp,[eax+0B8h]                                       ; get the EIP where the exception obcurred
 mov edi,[eax+9Ch]                                        ; get the damn edi value
 mov ebx,[eax+9Ch+4+4]
 mov edx,[eax+9Ch+4+4+4]
 mov ecx,[eax+9Ch+4+4+4+4]
 mov esi,edi
 pusha
 mov edx,(Possible_Second_Exception -  offset ToAdd)      ; compare with the 2nd exception
 add edx,ebx                                              
 cmp ebp,edx
 jz SecondSupposed_Memory_Violation                       ; jump if they are equal
 popa
 jmp edx                                                  ; for some tricks with SEH

SecondSupposed_Memory_Violation:
 popa
 xor edx,dword ptr [(offset VALUE4 - offset ToAdd) + ebx] ; simple xor but effective ;)
 jmp JumpaboveMutation

InstallExceptionHandler:
 mov edx,(offset Exception_Handler - offset ToAdd)
 F1CKEN 0FFh
 add edx,ebx
 F1CKEN 0FFh
 push edx
 F1CKEN 0FFh
 push dword ptr fs:[0]
 F1CKEN 0FFh
 mov fs:[0],esp
 F1CKEN 0FFh
 mov dword ptr [(PIZZA - offset ToAdd) + ebx],esp
 jmp EncryptLayer3


JumpaboveMutation:
 inc dword ptr [(VALUE3 - offset ToAdd) + ebx]
 xor edx,ecx
 dec ecx
 jnz Decrypt_AD_Block
InCPL3:

EncryptLayer3:
 mov ebp,ebx
NtCompatibleAD:
 SEH_TRICK1 0EAH

 mov ebx,ebp
 mov dword ptr [(offset VALUE4 - offset ToAdd) + ebx],0
 F1CKEN4 0FFh
 mov dword ptr [(MutateCRC2 - offset ToAdd) + ebx],0
 mov dword ptr [(VALUE3 - offset ToAdd) + ebx],0

 mov edx,(offset ModuleDLL - offset ToAdd)                         ; offset of the _KERNEL32
 add edx,ebx
 CONFUSE 08h                                                       ; Confusing jump crap
 cmp byte ptr fs:[23h],00h
 jnz GenerateAD_CRC_2
 mov esi,(offset GetSystem_Time - offset ToAdd)
 add esi,ebx
 CONFUSE 03h                                                       ; Confusing jump crap
 push esi
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 call dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 mov dword ptr [(GetSystemTimeRVA - offset ToAdd) + ebx],eax

 F1CKEN4 0FFh
 mov esi,(offset SYSTEMTIME_STRUCTURE - offset ToAdd) + 1
 add esi,ebx
 push esi
 call dword ptr [(GetSystemTimeRVA - offset ToAdd) + ebx]

 SEH_TRICK1 0EFH

 mov edx,(offset ModuleDLL - offset ToAdd)        ; offset of the _KERNEL32
 add edx,ebx

 F1CKEN 0FFh
 cmp byte ptr [(KILLHEAD - offset ToAdd) + ebx],0 ; Header erasing disabled?
 jz DontErasePEHeader                             ; if yes, then jump

 mov esi,(offset f_OpenProcess - offset ToAdd)    ; offset of the function
 add esi,ebx
 call GetApi                                      ; get the offset of OpenProcess
 mov dword ptr [(F7RVA - offset ToAdd) + ebx],eax ; save the rva of this function

 CONFUSE 02h                                      ; Confusing jump crap

 mov esi,(offset f_WriteProcessMemory - offset ToAdd) ; offset of the function
 add esi,ebx
 F1CKEN4 0FFh
 call GetApi                                      ; get the offset of OpenProcess
 mov dword ptr [(F8RVA - offset ToAdd) + ebx],eax ; save the rva of this function

 CONFUSE 01h                                      ; Confusing jump crap

; SEH_TRICK1 0EAH
 mov esi,(offset f_GetCurrentProcessId - offset ToAdd)  ; offset of the function
 add esi,ebx
 call GetApi                                      ; get the offset of OpenProcess
 mov dword ptr [(F9RVA - offset ToAdd) + ebx],eax ; save the rva of this function
 CONFUSE 02h                                      ; Confusing jump crap

 call dword ptr [(F9RVA - offset ToAdd) + ebx]    ; get the current process id
 push eax
 push 0
 push 0c0h
 call dword ptr [(F7RVA - offset ToAdd) + ebx]
 CONFUSE 03h                                                       ; Confusing jump crap
 or eax,eax
 jz DontPatchHeader

 F1CKEN4 0FFh
 mov edi,(offset BYTEWRITTEN - offset ToAdd)
 add edi,ebx
 CONFUSE 01h                                                       ; Confusing jump crap
 push edi
 push 1024
 mov edi,(InstructionTable - offset ToAdd)
 add edi,ebx
 push edi
 CONFUSE 02h                                                       ; Confusing jump crap
 push dword ptr [(NEWIBASE - offset ToAdd) + ebx]
 CONFUSE 03h                                                       ; Confusing jump crap
 push eax
 call dword ptr [(F8RVA - offset ToAdd) + ebx]

DontErasePEHeader:
DontPatchHeader:

; SEH_TRICK1 0D3H

 F1CKEN4 0FFh
 mov ebp,ebx
 mov edx,(offset ModuleDLL - offset ToAdd)    ; offset of the _KERNEL32
 add edx,ebx

 F1CKEN4 0FFh
 mov esi,(offset f_VirtualAlloc - offset ToAdd)  ; offset of the function
 add esi,ebx
 CONFUSE 03h                                                       ; Confusing jump crap
 Call GetApi                                ; get the rva of this function
 mov dword ptr [(F2RVA - offset ToAdd) + ebx],eax

 F1CKEN 0EAh
 F1CKEN 0FFh
 mov esi,(offset f_VirtualFree - offset ToAdd)  ; offset of the function
 add esi,ebx
 F1CKEN 0FFh
 Call GetApi                                ; get the rva of this function
 mov dword ptr [(F4RVA - offset ToAdd) + ebx],eax                  ; save rva of virtualalloc

; SEH_TRICK1 0E8H

 mov esi,(offset OBJTABLE - offset ToAdd) ; offset of the obj info table
 F1CKEN4 0E8h
 add esi,ebx
 mov edx,dword ptr [NEWIBASE - offset ToAdd + ebx] ; get the imagebase
GetThenextobj:
 push edx

 F1CKEN 0FFh

 cmp dword ptr [esi],0                                    ; is there another obj?
 jz Finito                                                ; no? then jump

 F1CKEN4 0FFh

 pushad
 mov edx,dword ptr [(PreviousCRC - offset ToAdd) + ebx]   ; get the previous
 mov edi,esi                                              ; crc for decryption

 F1CKEN 0FFh

 xor eax,eax
 push esi
 F1CKEN4 0E8h
 mov ecx,33                                               ; size of the objtable
DecryptOBJTable:
 lodsb                                                    ; get a byte
 xor eax,edx                                              ; and decrypt it
 inc edx                                                  ; with the value
 stosb                                                    ; of the previous
 dec ecx                                                  ; crc calculation
 jnz DecryptOBJTable

 pop esi

 F1CKEN 0FFh

 add dword ptr [(CRAPVAR - offset ToAdd) + ebx],eax

 mov ecx,33                     ; size of all entries = 21 bytes
 CONFUSE 03h                                                       ; Confusing jump crap
 xor eax,eax
 mov edx,dword ptr [(ENCRYPTV1 - offset ToAdd) + ebx]

 F1CKEN 0FFh

CalculateOBJCRC2:
 lodsb                         ; get a byte
 xor eax,ecx                   ; and calculate a simple checksum
 rol eax,cl                    ; which will be later used
 add eax,edx                   ; to encrypt the next objecttable :)
 xor edx,eax
 xor edx,dword ptr [(ENCRYPTV1 - offset ToAdd) + ebx]
 inc edx                       ; cause i don't want that some lAmErZ
 dec ecx                       ; change it, tralalaaaa
 jnz CalculateOBJCRC2

 F1CKEN4 0FFh
 push esi

 F1CKEN 0FFh

 xor esi,esi
 CONFUSE 03h                                                       ; Confusing jump crap
 add esi,ebx

 F1CKEN 0FFh

 mov ecx,offset CodeCRC_End - offset ToAdd
 mov edx,dword ptr [(ENCRYPTV2 - offset ToAdd) + ebx]
CaculateCODECRC2:
 mov dl,[esi]
 add eax,edx
 rol eax,cl
 xor eax,ecx
 xor eax,dword ptr [(ENCRYPTV1 - offset ToAdd) + ebx]
 inc esi
 dec ecx
 jnz CaculateCODECRC2
 pop esi

 push esi
 mov edx,eax

 F1CKEN 0EAh

 mov esi,(offset PEText - offset ToAdd)
 CONFUSE 03h                                                       ; Confusing jump crap
 add esi,ebx

 F1CKEN 0EAh

 mov ecx,(offset ToAdd_END - offset PEText)
ChecksumText2:
 lodsb
 add edx,eax
 rol edx,cl
 xor edx,ecx
 dec ecx
 jnz ChecksumText2
 pop esi
 mov eax,edx

 mov dword ptr [(PreviousCRC - offset ToAdd) + ebx],eax ; save the crc value
 popad

 F1CKEN2 0EAh

 CheckforHookedFunctions
 CONFUSE 01h                                                       ; Confusing jump crap

 lodsd          ; get the rva of the obj
 or eax,eax     ; end of the objtable?
 jz Finito      ; then jump
 mov dword ptr [COUNTER - offset ToAdd + ebx],eax ; save the virtual offset
 add edx,eax    ; memstart = imagebase + virtualobjectadress
 mov dword ptr [(MEMSTARTI - offset ToAdd) + ebx],edx

 F1CKEN 0EAh

 lodsd          ; physical size of this object
 mov dword ptr [OBJRSIZE - offset ToAdd + ebx],eax
 push eax
 lodsd          ; get the encryptionvalue of this object

 F1CKEN 0EAh

 mov dword ptr [PatchCode1  - offset ToAdd + ebx],eax

 cmp byte ptr fs:[23h],00h
 jnz GenerateAD_CRC_2

 F1CKEN2 0FFh

 lodsd          ; get the virtual size of this object
 mov dword ptr [OBJVSIZE - offset ToAdd + ebx],eax
 lodsb          ; compressed or not?

 F1CKEN 0EAh

 mov byte ptr [(CTRUE - offset ToAdd + ebx)],al
 lodsd          ; get the CRC value of this object
 mov dword ptr [(OBJCRC - offset ToAdd) + ebx],eax
 F1CKEN4 0E8h
 lodsd
 mov dword ptr [(REAL_SIZE - offset ToAdd) + ebx],eax
 lodsd
 mov dword ptr [(REALSIZE - offset ToAdd) + ebx],eax  ; save the original physical size
 lodsd
 mov dword ptr [(FLAGI - offset ToAdd) + ebx],eax     ; save the section flags

 F1CKEN2 0C7h

 pop eax
 push esi       ; save esi for later use
 mov esi,edx
 CONFUSE 01h                                                       ; Confusing jump crap
 mov ecx,eax
 mov edi,esi
 F1CKEN 0EAh

 F1CKEN4 0E8h
 cmp byte ptr [(CRCERROR - offset ToAdd) + ebx],0  ; check if the crc option is off
 jz NO_OBJCRC_CHECK                                ; if yes, then jump
 pushad
 mov ecx,dword ptr [REAL_SIZE - offset ToAdd + ebx] ; get the virtual size of this obj
 shr ecx,2
 xor edx,edx
 xor ebx,ebx
CalculateOBJ_CRC2:
 lodsd
 xor edx,eax
 rol edx,cl
 shl edx,cl
 add edx,ebx
 mov ebx,eax
 dec ecx
 jnz CalculateOBJ_CRC2
 cmp eax,dword ptr [(OBJCRC - offset ToAdd) + ebp] ; compare calculated crc with original one
 popad
 jz NO_OBJCRC_CHECK                                ; jump if right
 cmp byte ptr [(CRCERROR - offset ToAdd) + ebx],1  ; check for the hangup option
 jz FinishedWithImports                            ; hangup if set
 push 30h
 mov eax,(offset CRCErrorH - offset ToAdd)
 add eax,ebx
 F1CKEN2 0FFh
 push eax
 mov eax,(offset CRCError - offset ToAdd)
 add eax,ebx
 push eax
 push 0
 F1CKEN2 0FEh
 jmp MboxError

NO_OBJCRC_CHECK:
 cmp byte ptr [CTRUE - offset ToAdd + ebx],1
 jz DeCompressResources
 F1CKEN 0EAh
 shr ecx,1
 jmp Encrypt
DeCompressResources:

 mov dword ptr [OBJRSIZE - offset ToAdd + ebx],ecx
 F1CKEN4 0E8h
 mov dword ptr [DECOMPSTART - offset ToAdd + ebp],edi ; bla,bla ;)

DecompressRelocations:
 push 4
 CONFUSE 03h                                                       ; Confusing jump crap
 push 1000h
 push dword ptr [OBJVSIZE - offset ToAdd + ebx]    ; push the real section size
 push 0                                            ; call the function
 call dword ptr [F2RVA - offset ToAdd + ebx]       ; and allocate memory
 CONFUSE 03h                                                       ; Confusing jump crap
 mov dword ptr [MemStart - offset ToAdd + ebx],eax ; save the rva
 mov edi,eax

 mov esi,dword ptr [DECOMPSTART - offset ToAdd + ebp]

 push ebp
 push ebx
 push esi
 push edx
 push ecx

getbitM MACRO
LOCAL stillbitsleft
 add dl,dl
 jnz stillbitsleft
 mov dl,[esi]
 inc esi
 adc dl,dl
stillbitsleft:
ENDM getbitM

domatchM MACRO reg
 push esi
 mov esi, edi
 sub esi, reg
 rep movsb
 pop esi
ENDM domatchM

getgammaM MACRO reg
LOCAL getmorebits
 mov reg, 1
getmorebits:
 getbitM
 adc reg, reg
 getbitM
 jc getmorebits
ENDM getgammaM


_aP_depack_asm_fast:
 push ebp
 mov ebp,esp
 push ebp

 cld
 mov dl,80h

literal:
 mov al,[esi]
 inc esi
 mov [edi],al
 inc edi
nexttag:
 getbitM
 jnc literal
 getbitM
 jnc codepair
 getbitM
 jnc shortmatch
 xor eax,eax
 getbitM
 adc eax,eax
 getbitM
 adc eax,eax
 getbitM
 adc eax,eax
 getbitM
 adc eax,eax
 jz thewrite
 neg eax
 mov al,[edi+eax]
thewrite:
 mov [edi],al
 inc edi
 jmp short nexttag
codepair:
 getgammaM eax
 sub eax, 2
 jnz normalcodepair
 getgammaM ecx
 domatchM ebp
 jmp nexttag
normalcodepair:
 dec eax
 shl eax, 8
 mov al,[esi]
 inc esi
 mov ebp,eax
 getgammaM ecx
 cmp eax,1280
 jb not_gt_1280
 inc ecx
not_gt_1280:
 cmp eax,7fh
 ja dont_add_2
 add ecx,2
dont_add_2:
 domatchM eax
 jmp nexttag
shortmatch:
 xor eax,eax
 mov al,[esi]
 inc esi
 xor ecx,ecx
 db 0c0h,0e8h,001h
 jz donedepacking
 adc ecx,2
 mov ebp,eax
 domatchM eax
 jmp nexttag
donedepacking:
 pop ebp
 pop ebp
 pop ecx
 pop edx
 pop esi
 pop ebx
 pop ebp

 CONFUSE 03h                                                       ; Confusing jump crap
 sub edi,dword ptr [(MemStart - offset ToAdd) + ebp]
 mov ecx,edi

 mov esi,dword ptr [(MemStart - offset ToAdd) + ebp]
 CONFUSE 03h                                                       ; Confusing jump crap
 mov edi,dword ptr [(DECOMPSTART - offset ToAdd) + ebp]
 rep movsb

 push 2
 push dword ptr [(OBJVSIZE - offset ToAdd) + ebx]
 CONFUSE 03h                                                       ; Confusing jump crap
 push dword Ptr [(MemStart - offset ToAdd) + ebx]
 Call dword ptr [(F4RVA - offset ToAdd) + ebx]
 or eax,eax
 jz ImpFound
 push 30h
 mov eax,(offset DeallocErrorHead - offset ToAdd)
 add eax,ebx
 push eax
 mov eax,(offset DeallocError - offset ToAdd)
 F1CKEN4 08Bh
 add eax,ebx
 push eax
 push 0
 jmp MboxError
NoErrorWhileDeallocating_2:

Encrypt:
 lodsw          ; get a byte
 rol ax,cl
 xor eax,dword ptr [PatchCode1 - offset ToAdd + ebx]
 not ax
 xor ax,cx
 stosw          ; store a byte
 inc dword ptr [PatchCode1 - offset ToAdd + ebx]
 dec ecx
 jnz Encrypt

 F1CKEN 0EBh

ImpFound:
 F1CKEN4 08Bh

 cmp byte ptr [(RelocCCC - offset ToAdd) + ebx],1 ; is the relocation decompression running?
 mov byte ptr [(RelocCCC - offset ToAdd) + ebx],0 ; zero this internal flag
 jz ContinueRelocationCompression                 ; if yes then continue decompression
 cmp byte ptr [DECOMR - offset ToAdd + ebx],1
 jz NoResources


 pusha

 F1CKEN4 08Bh


 cmp byte ptr [(IMP_DESTROY - offset ToAdd) + ebx],0
 jz NoFakeIATPossible

 F1CKEN4 08Bh
 mov ecx,dword ptr [(OBJVSIZE - offset ToAdd) + ebx]

 F1CKEN4 08Bh
 mov eax,dword ptr [(REALSIZE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 cmp eax,ecx
 jae NoFakeIATPossible
 sub ecx,eax
 F1CKEN4 08Bh
 or ecx,ecx
 jz NoFakeIATPossible
 mov edi,dword ptr [(MEMSTARTI - offset ToAdd) + ebx]
 add edi,eax
 F1CKEN4 08Bh
 mov eax,ecx
 mov ecx,6
 F1CKEN4 08Bh
 xor edx,edx
 div ecx
 F1CKEN4 08Bh
 mov ecx,eax
 dec ecx
 F1CKEN4 08Bh
 or ecx,ecx
 jz NoFakeIATPossible
 
 F1CKEN4 08Bh
 push ecx
 F1CKEN4 08Bh
 push edi
 mov edx,(offset ModuleDLL - offset ToAdd)    ; offset of the _KERNEL32
 F1CKEN4 08Bh
 add edx,ebx
 push edx
 F1CKEN4 08Bh
 push dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx]
 call CallApi
 mov esi,eax
 F1CKEN4 08Bh
 mov ebp,eax
 pop edi
 F1CKEN4 08Bh
 pop ecx
Generate_Fake_IAT:
 push esi
 push ebp
 F1CKEN4 08Bh
 push eax
 push edi
 F1CKEN4 08Bh

 add eax,dword ptr [esi+3Ch] ; pointer to the PE header start
 mov edi,esi
 F1CKEN4 08Bh
 mov eax,[eax+120]
 add eax,esi
 F1CKEN4 08Bh
 xchg eax,esi

 F1CKEN4 08Bh
 call Randomize2
 F1CKEN4 08Bh
 and eax,0FFh
 sub eax,[esi+16]            ; add the ordinal base to the ordinal numba

 push edi
 F1CKEN4 08Bh
 mov edi,[esi+28]
 F1CKEN4 08Bh
 mov esi,ebp
 add edi,esi
 F1CKEN4 08Bh
 mov eax,[eax*4+edi]
 pop edi
 F1CKEN4 08Bh
 add eax,edi
 F1CKEN4 08Bh
 pop edi
 mov ax,25FFh
 stosw
 stosd
 pop eax
 F1CKEN4 08Bh
 pop ebp
 F1CKEN4 08Bh
 pop esi
 F1CKEN4 08Bh
 dec ecx
 jnz Generate_Fake_IAT
NoFakeIATPossible:
 popa

 pop esi
 pop edx
 inc word ptr [OBJCOUNTI - offset ToAdd + ebx]
 jmp GetThenextobj

Finito:
 CONFUSE 01h                                                       ; Confusing jump crap

 cmp byte ptr [(PEText+88h - offset ToAdd)+ebx],"r"
 jnz Encrypt

 cmp byte ptr [(RCOMP - offset ToAdd) + ebx],2        ; no resource processing needed?
 jz NoResources                                       ; if yes, jump
 CONFUSE 02h                                                       ; Confusing jump crap
 cmp dword ptr [(RESOURCEOFS - offset ToAdd) + ebx],0 ; no resources?
 jz NoResources                                       ; if yes, jump
 F1CKEN4 0FFh
 mov eax,dword ptr [RESOURCEOFS - offset ToAdd + ebx]
 F1CKEN4 0FFh
 add eax,dword ptr [NEWIBASE - offset ToAdd + ebx]
 CONFUSE 04h                                                       ; Confusing jump crap
 mov ebp,eax
 xchg esi,eax

 F1CKEN 0EBh

 cmp byte ptr [RCOMP - offset ToAdd + ebx],0        ; compressed resources?
 jz NoCompResources                                 ; no? then skip decompression

 mov ebp,ebx
 mov byte ptr [DECOMR - offset ToAdd + ebx],1
 mov eax,dword ptr [RESOURCESIZ - offset ToAdd + ebx]

 F1CKEN 0EBh

 mov dword ptr [OBJRSIZE - offset ToAdd + ebx],eax
 mov eax,dword ptr [RESOURCEVSIZ - offset ToAdd + ebx]
 CONFUSE 06h                                                       ; Confusing jump crap
 mov dword ptr [OBJVSIZE - offset ToAdd + ebx],eax

 F1CKEN 0EBh

 mov ecx,eax
 sub ecx,dword ptr [DIRSIZE - offset ToAdd + ebx]
 add esi,dword ptr [DIRSIZE - offset ToAdd + ebx]
 F1CKEN 063h
 mov edi,esi
 CONFUSE 0Dh                                                       ; Confusing jump crap

 push eax
 mov eax,dword ptr [(RESOURCEBYT - offset ToAdd) + ebx]
 cmp [esi],eax
 pop eax
 jnz DeCompressResources
 jmp NoResources

Encrypted_Layer_1End:

NoCompResources:
 xor edi,edi
 mov dword ptr [(RESOURCEOFS - offset ToAdd) + ebx],0      ; zero it
 mov ebp,esi
 CONFUSE 03h                                                       ; Confusing jump crap
 mov edx,dword ptr [NEWIBASE - offset ToAdd + ebx]

 call ParseSubDirectory
 jmp ResDecryptionFinished

ParseSubDirectory Proc
 push edx
 movzx ecx,word ptr [esi+14] ; get the number of ID entries (root directory)
 movzx edx,word ptr [esi+12]   ; get number of named entries (root directory)
 add ecx,edx
 pop edx
ReadSubdirectory_3:
 push ecx
 add esi,16                  ; Image Resource Directory Format = 16 bytes
 push esi
ScanNext2:

ContinueDirParsing3:

 mov eax,dword ptr [esi+4]   ; get data or directory offset
			     ; (directory if 800000000h is set)
 and eax,7FFFFFFFh           ; pointer contains of 31 bit
 test dword ptr [esi+4],80000000h   ; test for directory / raw data structure
 jnz SubDirectoryFound2      ; jump if set (subdirectory)
 jmp RawStructureFound2      ; Raw data structure found

SubDirectoryFound2:
 cmp byte ptr [esi],10h
 jz SkipThisEntry
 mov esi,ebp                  ; get the memory offset
 add esi,eax                  ; add the pointer to the sub directory
 call ParseSubDirectory
 CONFUSE 03h                                                       ; Confusing jump crap
SkipThisEntry:
 pop esi
 pop ecx
 sub esi,8
 or ecx,ecx
 jz Retit2
 dec ecx
 jnz ReadSubdirectory_3
Retit2:
 ret
 jmp ContinueDirParsing3

DontEncryptThisEntry:
 add esi,8
 jmp ScanNext2

RawStructureFound2:
 add eax,ebp
 xchg esi,eax
 mov eax,[esi]               ; get the raw data offset
 CONFUSE 03h                                                       ; Confusing jump crap
 mov ecx,[esi+4]             ; get the size of this raw data entry
 add eax,edx                 ; add the memory start of the allocated mem

 sub eax,edi                 ; subtract the resource ofs to get the new offset
 mov esi,eax

 push esi
 push ecx
 mov esi,(offset EncryptLayer3 - offset ToAdd)        ; checksum start
 add esi,ebx                                          ; add the pecrypt32 rva
 mov ecx,(offset HookedAPICODE_START - EncryptLayer3)
Patch_Crc1:
 mov eax,1
GenerateResourceChecksum:
 xor al,[esi]
 xor eax,ecx
 not eax
 rol eax,4
 dec ecx
 jnz GenerateResourceChecksum
 pop ecx
 pop esi

 cmp byte ptr [esi],28h      ; check for the first icon signature
 jz DontEncryptRawData       ; don't encrypt if icon

Encrypt_RawData:
 cmp byte ptr [esi],0       ; check for the first group icon signature
 jnz EncryptRawData
 cmp byte ptr [esi+2],01     ; check for the 2nd group icon signature
 jz DontEncryptRawData       ; don't encrypt if icon

 cmp byte ptr [(DURCHGANG - offset ToAdd) + ebx],1
 jz FickDich
 cmp byte ptr [(DURCHGANG - offset ToAdd) + ebx],2
 jz FickDich2
 push eax
 mov eax,dword ptr [(RESOURCEBYT - offset ToAdd) + ebx] ; get the resource bytes
 cmp [esi],eax
 pop eax
 jz ResDecryptionFinished
 mov byte ptr [(DURCHGANG - offset ToAdd) + ebx],2
 jmp FickDich2

FickDich:
 push eax
 mov eax,[esi]
 mov dword ptr [(RESOURCEBYT - offset ToAdd) + ebx],eax
 mov byte ptr [(DURCHGANG - offset ToAdd) + ebx],2
 pop eax

FickDich2:

EncryptRawData:
 xor [esi],al
 xor eax,ecx
 not eax
 add eax,ecx
 inc esi
 dec ecx
 jnz EncryptRawData
DontEncryptRawData:
 CONFUSE 03h                                                       ; Confusing jump crap
 pop esi
 pop ecx
 ret
ParseSubDirectory endp

ResDecryptionFinished:
 mov ebp,ebx
NoResources:

 F1CKEN4 0FFh


 cmp byte ptr [(LOADRELOC - offset ToAdd + ebx)],0
 jz Thesame
 CONFUSE 03h                                        ; Confusing jump crap
 mov eax,dword ptr [NEWIBASE - offset ToAdd + ebx]  ; get the calculated imagebase
 F1CKEN4 08Dh
 cmp eax,dword ptr [IMAGEBASE - offset ToAdd + ebx] ; get the imagebase
 jz Thesame                                         ; the same? then jump
 sub eax,dword ptr [IMAGEBASE - offset ToAdd + ebx] ; calculate the delta

 CheckforHookedFunctions
 CONFUSE 03h                                                       ; Confusing jump crap

 F1CKEN2 0C7h

 mov dword ptr [RELOCDELTA - offset ToAdd + ebx],eax
 pop esi

 F1CKEN 062h

 mov edx,esi
 add esi,dword ptr [RELOCBASE - offset ToAdd + ebx] ; relocbase + imagebase relocstart
 F1CKEN 062h
 add dword ptr [(CRAPVAR - offset ToAdd) + ebx],eax
 mov eax,dword ptr [SAVEFIRSTRB - offset ToAdd + ebx]
 CONFUSE 03h                                                       ; Confusing jump crap
 mov dword ptr [esi],eax

 F1CKEN 062h

 cmp byte ptr [(RELOCCOMPP - offset ToAdd) + ebx],0 ; check for relocation
 jz NoRelocationCompression                         ; compression

 mov eax,dword ptr [RELOCSAVE - offset ToAdd + ebx]
 mov dword ptr [esi],eax

 F1CKEN 062h

 mov eax,dword ptr [RELOCSAVE - offset ToAdd + 4 + ebx]
 mov dword ptr [esi+4],eax

 F1CKEN 062h

 mov ax,word ptr [RELOCSAVE - offset ToAdd + 8 + ebx]
 mov word ptr [esi+8],ax

 CONFUSE 03h                                                       ; Confusing jump crap
 mov ebp,ebx
 mov byte ptr [(RelocCCC - offset ToAdd) + ebx],1     ; enable the relocation = running variable
 mov dword ptr [DECOMPSTART - offset ToAdd + ebp],esi ; save the relocation start
 CONFUSE 03h                                                       ; Confusing jump crap
 mov eax,dword ptr [(RelocSize - offset ToAdd) + ebx] ; get the relocation size (before 2nd compression)
 mov dword ptr [OBJVSIZE - offset ToAdd + ebx],eax    ; save the size
 jmp DecompressRelocations

ContinueRelocationCompression:

 mov esi,dword ptr [DECOMPSTART - offset ToAdd + ebp] ; get the relocation section rva
 xor ebp,ebp

GetNextRBlock:
 mov ecx,dword ptr [esi+4]                          ; get the length of this relocation block

 add dword ptr [PCounter - offset ToAdd + ebx],ecx
 mov eax,[esi]
 mov dword ptr [TEMPVAR - offset ToAdd + ebx],eax   ; save it
 add esi,8

 xor eax,eax
 lodsw
 and ax,0FFFh
 mov word ptr [DECRELOCOFS - offset ToAdd + ebx],ax

 add eax,dword ptr [TEMPVAR - offset ToAdd + ebx]    ; add the virtual reloc block
 mov edi,eax                                         ; adress to the relocation offset

 add edi,dword ptr [NEWIBASE - offset ToAdd + ebx]   ; add the new imagebase
 mov eax,dword ptr [RELOCDELTA - offset ToAdd + ebx] ; get the relocationdelta
 add dword ptr [edi],eax                             ; load the relocation
 cmp ecx,1
 jnz DecompReloc
 jmp OnlyoneRelocation

DecompReloc:
 xor eax,eax
 lodsb
 test al,80h
 jz AnotherReloc
 and al,7Fh

 add ax,word ptr [DECRELOCOFS - offset ToAdd + ebx]
 mov word ptr [DECRELOCOFS - offset ToAdd + ebx],ax
 jmp NoDamnway
AnotherReloc:
 dec esi
 lodsw
 mov [esi-2],cx                                      ; erase the relocation
 xchg ah,al
 and ax,0FFFh
 mov word ptr [DECRELOCOFS - offset ToAdd + ebx],ax

NoDamnway:
 add eax,dword ptr [TEMPVAR - offset ToAdd + ebx]    ; add the virtual reloc block
 mov edi,eax                                         ; adress to the relocation offset

 add edi,dword ptr [NEWIBASE - offset ToAdd + ebx]   ; add the new imagebase
 mov eax,dword ptr [RELOCDELTA - offset ToAdd + ebx] ; get the relocationdelta

 add dword ptr [edi],eax                             ; load the relocation
 dec ecx
 jnz DecompReloc
OnlyoneRelocation:

 CONFUSE 01h                                                       ; Confusing jump crap
 mov ebp,dword ptr [TEMPVAR - offset ToAdd + ebx]
 cmp ebp,dword ptr [Paranoia - offset ToAdd + ebx]
 jnz GetNextRBlock
 jmp Thesame

NoRelocationCompression:
 xor ebp,ebp
Titten:
 add ebp,8
 mov ecx,dword ptr [esi+4]                          ; get the length of this relocation block
 F1CKEN 0FFh
 mov eax,[esi]
 mov dword ptr [TEMPVAR - offset ToAdd + ebx],eax   ; save it
 add esi,8
 F1CKEN 0FFh
 sub ecx,8
 shr ecx,1                                           ; divide by 2, cause every reloc is a word
Lodi:
 add ebp,2
 xor eax,eax

 pushad
 mov esi,(offset ResDecryptionFinished - offset ToAdd)
 add esi,ebx

 F1CKEN 0FFh

 mov edx,dword ptr [(ENCRYPTV3 - offset ToAdd) + ebx]
 mov edi,dword ptr [(ENCRYPTV4 - offset ToAdd) + ebx]

 F1CKEN 0FFh

 mov ecx,(offset NoTracerRunning - offset ResDecryptionFinished)

 shr ecx,2
Calculate_RCRC2:
 mov eax,[esi]
 add edx,eax
 xor edx,ecx
 xor edi,eax
 rol edi,cl
 add esi,4
 dec ecx
 jnz Calculate_RCRC2
 xor edx,edi
 add dword ptr [(CRAPVAR - offset ToAdd) + ebx],eax

 F1CKEN 0FFh

 mov dword ptr [(ENCRYPTV5 - offset ToAdd) + ebx],edx
 popad

 F1CKEN 0FFh

 lodsw                                               ; get it
 xor ax,word ptr [(ENCRYPTV5 - offset ToAdd) + ebx]  ; encrypt it with the CRC
 xor ax,word ptr [CRYPTVALUE2 - offset ToAdd + ebx]  ; decrypt the relocation
 mov [esi-2],cx                                      ; erase the relocation
 cmp byte ptr [(ARTOFRELOC1 - offset ToAdd) + ebx],1 ; check for 12 or 16bit
 jnz Only12bitencryption                             ; relocation encryption
 xor ax,cx
 ror ax,cl
 not ax
Only12bitencryption:
 and ax,0FFFh                                        ; only 12 bits are needed
 or ax,ax                                            ; absolute relocation?
 jz AbsoluteRelocation                               ; if yes then jump! (don't load relocation)
 add eax,dword ptr [TEMPVAR - offset ToAdd + ebx]    ; add the virtual reloc block
 mov edi,eax                                         ; adress to the relocation offset
 add edi,dword ptr [NEWIBASE - offset ToAdd + ebx]   ; add the new imagebase
 mov eax,dword ptr [RELOCDELTA - offset ToAdd + ebx] ; get the relocationdelta
 F1CKEN2 0C7h
 add dword ptr [edi],eax                             ; load the relocation
AbsoluteRelocation:
 dec ecx
 jnz Lodi
 F1CKEN 0FFh
 cmp ebp,dword ptr [RELOCLENG - offset ToAdd + ebx]  ; relocations done?
 jz Thesame
 jmp Titten

Thesame:
 F1CKEN4 08Dh
 
 pusha
 cmp byte ptr [(IMP_DESTROY - offset ToAdd) + ebx],0
 jz No_FakeIAT_Possible

 cmp dword ptr [(RELOCSIZE - offset ToAdd) + ebx],0
 jz No_FakeIAT_Possible

 mov ecx,dword ptr [(RELOCSIZE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 mov edi,dword ptr [(NEWIBASE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 add edi,dword ptr [(RELOCBASE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 mov eax,ecx
 mov ecx,6
 F1CKEN4 08Bh
 xor edx,edx
 div ecx
 F1CKEN4 08Bh
 mov ecx,eax
 dec ecx
 F1CKEN4 08Bh
 or ecx,ecx
 jz No_FakeIAT_Possible
 
 F1CKEN4 08Bh
 push ecx
 F1CKEN4 08Bh
 push edi
 mov edx,(offset ModuleDLL - offset ToAdd)    ; offset of the _KERNEL32
 F1CKEN4 08Bh
 add edx,ebx
 push edx
 F1CKEN4 08Bh
 push dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx]
 call CallApi
 mov esi,eax
 F1CKEN4 08Bh
 mov ebp,eax
 pop edi
 F1CKEN4 08Bh
 pop ecx
Generate_Fake_IAT_3:
 push esi
 push ebp
 F1CKEN4 08Bh
 push eax
 push edi
 F1CKEN4 08Bh

 add eax,dword ptr [esi+3Ch] ; pointer to the PE header start
 mov edi,esi
 F1CKEN4 08Bh
 mov eax,[eax+120]
 add eax,esi
 F1CKEN4 08Bh
 xchg eax,esi

 F1CKEN4 08Bh
 call Randomize2
 F1CKEN4 08Bh
 and eax,0FFh
 sub eax,[esi+16]            ; add the ordinal base to the ordinal numba

 push edi
 F1CKEN4 08Bh
 mov edi,[esi+28]
 F1CKEN4 08Bh
 mov esi,ebp
 add edi,esi
 F1CKEN4 08Bh
 mov eax,[eax*4+edi]
 pop edi
 F1CKEN4 08Bh
 add eax,edi
 F1CKEN4 08Bh
 pop edi
 mov ax,25FFh
 stosw
 stosd
 pop eax
 F1CKEN4 08Bh
 pop ebp
 F1CKEN4 08Bh
 pop esi
 F1CKEN4 08Bh
 dec ecx
 jnz Generate_Fake_IAT_3

No_FakeIAT_Possible:
 popa









 movzx edx,word ptr [(wSecond - offset ToAdd) + ebx]
 push edx
 F1CKEN4 0F7h
 mov esi,(offset SYSTEMTIME_STRUCTURE - offset ToAdd) + 1
 add esi,ebx
 push esi
 F1CKEN4 0E8h
 call dword ptr [(GetSystemTimeRVA - offset ToAdd) + ebx]
 movzx eax,word ptr [(wSecond - offset ToAdd) + ebx]
 F1CKEN4 08Dh
 pop edx
 cmp eax,edx
 F1CKEN4 08Dh
 jz NoTracerRunning
 sub eax,edx
 F1CKEN4 08Dh
 cmp eax,50
 jae AbsoluteRelocation

NoTracerRunning:
 F1CKEN4 08Dh
 mov dword ptr [(NEWAPIBUFFE - offset ToAdd) + ebx],ebx ; points now to ToAdd (PECRYPT32 start)
 CONFUSE 01h                                            ; Confusing jump crap
 add [(TablePos - offset ToAdd) + ebx],ebx          ; add ebx to the tableofs
 add [(TablePos2 - offset ToAdd) + ebx],ebx         ; add ebx to the 2nd tableoffset

 CONFUSE 02h                                                       ; Confusing jump crap
 add [(HOOKEDAPIS - offset ToAdd) + ebx],ebx        ; ebx = pecrypt32 start = available memory
 CONFUSE 04h                                                       ; Confusing jump crap
 mov eax,dword ptr [(offset RVATABLE - offset ToAdd) + ebx] ; get the reversed memory offset
 CONFUSE 05h                                                       ; Confusing jump crap
 mov dword ptr [(HookVar3 - offset ToAdd) + ebx + 2 ],eax   ; write it in the code
 CONFUSE 06h                                                       ; Confusing jump crap
 add [(HookVar4 - offset ToAdd) + ebx + 1 ],ebx     ; add the base to this offset
 CONFUSE 07h                                                       ; Confusing jump crap
 add [(HookVar5 - offset ToAdd) + ebx + 3 ],ebx     ; add the base to this jump offset
 add [(NoAntiBpxStuffSelected - offset ToAdd) + ebx + 3],ebx
 CONFUSE 08h                                                       ; Confusing jump crap
 add [(HookVar11 - offset ToAdd) + ebx + 1 ],ebx    ; add the base to this jump offset
 F1CKEN2 0C7h
 CONFUSE 09h                                                       ; Confusing jump crap
 CheckforHookedFunctions

 mov esi,dword ptr [IMPORTOFS - offset ToAdd + ebx] ; get the import rva
 F1CKEN4 08Dh
 add esi,dword ptr [NEWIBASE - offset ToAdd + ebx]
 F1CKEN4 08Dh

NextMainImport:
 mov dword ptr [(SAVEDLLRVA - offset ToAdd) + ebx],0190331
 push esi
 cmp dword ptr [esi+16],0              ; check for end of the imports
 jz FinishedWithImports                ; if end, jump

 cmp dword ptr [esi],0   ; check for the 2nd import crap
 jnz FirstImportStandart ; if not then jump

 F1CKEN4 08Dh
 cmp dword ptr [(DLLPOS - offset ToAdd) + ebx],0  ; was there a previous dllname?
 jz DontDeleteDLLName                   ; no? then jump
 pusha
 mov esi,dword ptr [(DLLPOS - offset ToAdd) + ebx] ; get the dll name offset
 mov edi,esi
 F1CKEN4 08Dh
 mov ecx,20
DeleteDLLName:
 lodsb
 or al,al
 jz FinishedDlldeleting
 xor al,byte ptr [(CRAPVAR - offset ToAdd) + ebx]
 stosb
 add byte ptr [(CRAPVAR - offset ToAdd) + ebx],al
 dec ecx
 jnz DeleteDLLName
FinishedDlldeleting:
 popa

DontDeleteDLLName:
 mov edx,dword ptr [esi+12] ; get the pointer to the dll name
 mov [esi+12],ecx           ; overwrite this pointer
 F1CKEN4 08Dh
 add edx,dword ptr [NEWIBASE - offset ToAdd + ebx]
 mov dword ptr [(DLLPOS - offset ToAdd) + ebx],edx

 F1CKEN4 08Dh
 pusha
 mov esi,edx
 mov edi,(offset DLLSTRING - offset ToAdd)
 add edi,ebx

 movzx ecx,byte ptr [(NAMECOUNTI - offset ToAdd) + ebx]
 F1CKEN4 08Dh
 add ecx,(offset DLLNAMESL - offset ToAdd)
 add ecx,ebx
 CONFUSE 02h                                                       ; Confusing jump crap
 movzx ecx,byte ptr [ecx]

DecryptDllName:
 lodsb
 F1CKEN4 66h
 push esi
 push ecx
 push edi
 push eax
 mov ecx,(offset MutateHookedApi - offset ContinueRelocationCompression) / 4
 F1CKEN4 66h
 mov esi,(offset ContinueRelocationCompression - offset ToAdd)
 add esi,ebx
 F1CKEN4 66h
 mov edx,dword ptr [(IMPENC4 - offset ToAdd) + ebx]
Generate_Lame_Checksum_2_2:
 lodsd
 xor eax,ecx
 add edx,eax
 not edx
 rol edx,cl
 dec ecx
 jnz Generate_Lame_Checksum_2_2
 mov dword ptr [(IMPENC4 - offset ToAdd) + ebx],edx

 pop eax
 pop edi
 pop ecx
 pop esi
 xor al,dl
 stosb
 dec ecx
 jnz DecryptDllName

Dll_NameFinished:
 xor al,al
 stosb
 popa
 inc byte ptr [(NAMECOUNTI - offset ToAdd) + ebx]

 F1CKEN4 66h
 mov edx,(offset DLLSTRING - offset ToAdd)
 add edx,ebx

 F1CKEN4 66h
 mov eax,dword ptr [esi+16] ; get the thunk table offset
 mov [esi+16],ecx           ; overwrite this pointer
 add eax,dword ptr [NEWIBASE - offset ToAdd + ebx] ; add the imagebase

 mov esi,eax
 mov edi,esi ; edi = esi = thunktable
 jmp SecondImportStandart

FirstImportStandart:
 mov edi,dword ptr [esi+16]
 mov [esi+16],ecx                                 ; overwrite this pointer
 add edi,dword ptr [NEWIBASE - offset ToAdd + ebx]
 F1CKEN 0FFh

 F1CKEN4 66h
 cmp dword ptr [(DLLPOS - offset ToAdd) + ebx],0  ; was there a previous dllname?
 jz DontDeleteDLLName2                  ; no? then jump
 pusha
 F1CKEN4 0F7h
 mov esi,dword ptr [(DLLPOS - offset ToAdd) + ebx] ; get the dll name offset
 mov edi,esi
 mov ecx,20
DeleteDLLName2:
 lodsb
 or al,al
 jz FinishedDlldeleting2
 xor al,byte ptr [(CRAPVAR - offset ToAdd) + ebx]
 stosb
 add byte ptr [(CRAPVAR - offset ToAdd) + ebx],al
 dec ecx
 jnz DeleteDLLName2
FinishedDlldeleting2:
 popa
DontDeleteDLLName2:
 mov edx,dword ptr [esi+12]
 mov [esi+12],ecx                                  ; erase this pointer
 add edx,dword ptr [NEWIBASE - offset ToAdd + ebx]
 mov dword ptr [(DLLPOS - offset ToAdd) + ebx],edx

 pusha
 F1CKEN4 0F7h
 mov esi,edx
 mov edi,(offset DLLSTRING - offset ToAdd)
 add edi,ebx

 F1CKEN4 0F7h
 movzx ecx,byte ptr [(NAMECOUNTI - offset ToAdd) + ebx]
 add ecx,(offset DLLNAMESL - offset ToAdd)
 add ecx,ebx
 movzx ecx,byte ptr [ecx]
 F1CKEN4 0F7h

DecryptDllName_2:
 lodsb
 push esi
 push ecx
 push edi
 push eax
 mov ecx,(offset MutateHookedApi - offset ContinueRelocationCompression) / 4
 mov esi,(offset ContinueRelocationCompression - offset ToAdd)
 add esi,ebx

 mov edx,dword ptr [(IMPENC4 - offset ToAdd) + ebx]
Generate_Lame_Checksum_2_2_2:
 lodsd
 xor eax,ecx
 add edx,eax
 not edx
 rol edx,cl
 dec ecx
 jnz Generate_Lame_Checksum_2_2_2
 mov dword ptr [(IMPENC4 - offset ToAdd) + ebx],edx
 pop eax
 pop edi
 pop ecx
 pop esi

 xor al,dl
 stosb
 dec ecx
 jnz DecryptDllName_2

Dll_NameFinished_2:
 xor al,al
 stosb
 popa
 inc byte ptr [(NAMECOUNTI - offset ToAdd) + ebx]

 mov edx,(offset DLLSTRING - offset ToAdd)
 add edx,ebx

 F1CKEN4 0F7h
 mov eax,dword ptr [esi]
 mov dword ptr [(SAVEDLLRVA - offset ToAdd) + ebx],eax
 mov [esi],ecx                                     ; overwrite this pointer
 F1CKEN4 0F7h
 add eax,dword ptr [NEWIBASE - offset ToAdd + ebx]
 mov esi,eax
SecondImportStandart:
ParseNextImport:
 lodsd
 or eax,eax
 jz MainImportFinished

 F1CKEN4 0F7h
 push edx
 push edi
 push esi
 push eax
 mov edi,esi
 F1CKEN4 0F7h
 mov ecx,(offset MutateHookedApi - offset ContinueRelocationCompression) / 4
 mov esi,(offset ContinueRelocationCompression - offset ToAdd)
 add esi,ebx
 F1CKEN4 0F7h
 mov edx,dword ptr [(IMPENC2 - offset ToAdd) + ebx]
Generate_Lame_Checksum_2:
 lodsd
 xor eax,ecx
 add edx,eax
 not edx
 rol edx,cl
 dec ecx
 jnz Generate_Lame_Checksum_2
 mov dword ptr [(IMPENC2 - offset ToAdd) + ebx],edx
 pop eax
 xor eax,edx
 F1CKEN4 0F7h
 pop esi
 pop edi
 pop edx

 F1CKEN4 0F7h

 cmp byte ptr [(LOADEROPT - offset ToAdd) + ebx],0    ; function hooking enabled
 jz HolladrioChick                                    ; if yes, then continue

 jmp OnlyApiHookingEnabled
AntiBpxStuffEnabled:
 pusha

 F1CKEN4 08Bh
 mov edi,dword ptr [(TablePos2 - offset ToAdd) + ebx]               ; get the table position
 mov eax,dword ptr [(InternalFunctionCounter - offset ToAdd) + ebx] ; get the counter
 F1CKEN4 08Bh
 movzx edx,word ptr [edi]                                           ; get the function value
 F1CKEN4 08Bh
 cmp eax,edx                                                        ; compared both
 jnz AntiBpxBpmCrapFinished                                         ; skip if not equal
 
 F1CKEN4 08Bh

 add edi,2
 mov dword ptr [(TablePos2 - offset ToAdd) + ebx],edi   ; save the new table offset
 mov byte ptr [(Hookem - offset ToAdd) + ebx],1         ; function needs to get hooked

 F1CKEN4 08Bh
 cmp byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],0
 jnz JumpsAreNotNeeded

 mov edi,dword ptr [(NEWAPIBUFFE - offset ToAdd) + ebx] ; points to the PECRYPT32 start
 mov dword ptr [(HookRVA - offset ToAdd) + ebx],edi     ; save the new rva


 push edi
 mov ecx,(HookedAPICODE_END - offset HookedAPICODE_START)
 mov esi,(offset HookedAPICODE_START - offset ToAdd)    ; points to the api code
 add esi,ebx
 rep movsb
 mov dword ptr [(NEWAPIBUFFE - offset ToAdd) + ebx],edi ; save the new buffer pos
 pop edi
 push edi
 mov eax,dword ptr [(TableEntry - offset ToAdd) + ebx]  ; get the rva counter
 add edi,(offset HookVar1 - offset HookedAPICODE_START + 1)
 mov [edi],eax                                          ; write the counter in the code
 pop edi
 add edi,(offset JMPDATA - offset HookedAPICODE_START) ; points to the 2nd fake var

 F1CKEN4 08Bh
 mov edx,(offset MAINAPICODE_START - offset ToAdd)      ; points to the main api code
 add edx,ebx
 sub edx,edi
 sub edx,4                                              ; becoz of the jmp opcode
 mov [edi],edx                                          ; write the new jump position

JumpsAreNotNeeded:
 mov al,byte ptr [(KINDOFHOOK - offset ToAdd) + ebx]
 or al,1                                                ; 0 bit set = anti bpx hook
 mov byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],al

 jmp AntiBpxBpmCrapFinished

OnlyApiHookingEnabled:
 pusha
 F1CKEN4 0F7h


 F1CKEN4 08Bh
 mov eax,dword ptr [(InternalFunctionCounter - offset ToAdd) + ebx] ; get the counter
 mov edi,dword ptr [(TablePos - offset ToAdd) + ebx]  ; get the table offset
 F1CKEN4 08Bh
 movzx edx,word ptr [edi]                             ; get the function value
 cmp eax,edx                                          ; are they the same?
 jnz NoHooking                                        ; if not jump

 add edi,2                                            ; pointer to the next entry
 F1CKEN4 08Bh
 mov dword ptr [(TablePos - offset ToAdd) + ebx],edi  ; save the new table offset
 mov byte ptr [(Hookem - offset ToAdd) + ebx],1       ; function needs to get hooked
 mov edi,dword ptr [(NEWAPIBUFFE - offset ToAdd) + ebx] ; points to the PECRYPT32 start
 F1CKEN4 08Bh
 mov dword ptr [(HookRVA - offset ToAdd) + ebx],edi     ; save the new rva

 push edi
 F1CKEN4 0F7h
 mov ecx,(HookedAPICODE_END - offset HookedAPICODE_START)
 mov esi,(offset HookedAPICODE_START - offset ToAdd)    ; points to the api code
 add esi,ebx
 rep movsb
 F1CKEN4 0F7h
 mov dword ptr [(NEWAPIBUFFE - offset ToAdd) + ebx],edi ; save the new buffer pos
 pop edi
 push edi
 F1CKEN4 0F7h
 mov eax,dword ptr [(TableEntry - offset ToAdd) + ebx]  ; get the rva counter
 add edi,(offset HookVar1 - offset HookedAPICODE_START + 1)
 mov [edi],eax                                          ; write the counter in the code
 pop edi
 F1CKEN4 0F7h
 add edi,(offset JMPDATA - offset HookedAPICODE_START) ; points to the 2nd fake var

 mov edx,(offset MAINAPICODE_START - offset ToAdd)      ; points to the main api code
 add edx,ebx
 sub edx,edi
 CONFUSE 03h                                                       ; Confusing jump crap
 sub edx,4                                              ; becoz of the jmp opcode
 mov [edi],edx                                          ; write the new jump position
 mov al,byte ptr [(KINDOFHOOK - offset ToAdd) + ebx]
 or al,4
 mov byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],al
NoHooking:
 popa
HolladrioChick:
 cmp byte ptr [(ANTIBPXBPM - offset ToAdd) + ebx],1
 jz AntiBpxStuffEnabled
 jmp Nixpoppen
AntiBpxBpmCrapFinished:
 popa

Nixpoppen:
 F1CKEN4 0F7h
 push eax
 mov eax,dword ptr [(SYSTEMTIME_STRUCTURE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 mov [esi-4],eax
 F1CKEN4 08Bh
 pop eax

 test eax,80000000h                                     ; if name entry then jump
 jz Pointer2NameDir

 F1CKEN4 0F7h
 and eax,7FFFFFFFh
 push edx
 push edi
 push esi
 push eax
 push edx
 push edx

 call dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx] ; call "GetmoduleHandle"
 pop edx
 F1CKEN 0FFh
 or eax,eax
 jnz Dllalreadyloaded
 push edx
 push edx
 call dword [(offset Thunktable+4+4-4 - offset ToAdd)+ebx]
 pop edx
 or eax,eax
 jz DllError

Dllalreadyloaded:
 F1CKEN4 08Bh
 mov esi,eax
 mov ebp,eax
 F1CKEN4 08Bh
 add eax,dword ptr [esi+3Ch] ; pointer to the PE header start
 mov edi,esi
 mov eax,[eax+120]
 F1CKEN4 08Bh
 add eax,esi
 xchg eax,esi
 pop eax
 F1CKEN4 08Bh
 sub eax,[esi+16]            ; add the ordinal base to the ordinal numba
 push edi
 mov edi,[esi+28]
 F1CKEN4 08Bh
 mov esi,ebp
 add edi,esi
 F1CKEN4 08Bh
 mov eax,[eax*4+edi]
 pop edi
 add eax,edi
 pop esi
 pop edi
 pop edx
 F1CKEN4 08Bh
 jmp OrdinalImport

Pointer2NameDir:
 F1CKEN4 08Bh
 add eax,dword ptr [NEWIBASE - offset ToAdd + ebx]
 inc eax
 F1CKEN4 08Bh
 inc eax
 push esi
 push eax

 F1CKEN4 0E8h
 xchg eax,esi
 Call GetApi
 pop ebp
 push edi
 mov edi,ebp
 F1CKEN4 08Bh
 mov ecx,0FFFFh
DeleteImport:
 cmp byte ptr [edi],0
 jz DeletingFinished
 mov [edi],cl
 inc edi
 dec ecx
 jnz DeleteImport
DeletingFinished:
 pop edi

 pop esi

OrdinalImport:
 F1CKEN4 08Bh
 cmp byte ptr [(Hookem - offset ToAdd) + ebx],1     ; does this function need to be hooked?
 jnz NoHooking_2                                    ; no? then jump

 F1CKEN4 0E8h
 push edi
 push edx
 mov byte ptr [(Hookem - offset ToAdd) + ebx],0     ; zero it
 F1CKEN4 08Bh
 mov edi,[(TableEntry - offset ToAdd) + ebx]        ; get the rva counter
 push eax
 mov eax,5
 F1CKEN4 08Bh
 mul edi
 xchg eax,edi
 F1CKEN4 08Bh
 pop eax
 F1CKEN4 08Bh
 add edi,dword ptr [(offset RVATABLE - offset ToAdd) + ebx]
 F1CKEN4 0F7h
 mov [edi],eax                                      ; save the rva
 F1CKEN4 08Bh
 mov al,byte ptr [(KINDOFHOOK - offset ToAdd) + ebx]
 mov [edi+4],al                                     ; save the kind of api hooking
 F1CKEN4 08Bh
 mov byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],0 ; zero it

 F1CKEN4 08Bh
 mov eax,dword ptr [(HookRVA - offset ToAdd) + ebx] ; get the new rva (points to PECRYPT32)
 F1CKEN4 08Bh
 inc dword ptr [(TableEntry - offset ToAdd) + ebx]  ; increase the rva counter
 pop edx
 pop edi

NoHooking_2:
 mov dword ptr [edi],eax
 F1CKEN4 083h
 cmp byte ptr [(ANTIBPXBPM - offset ToAdd) + ebx],0
 jz DontCheckForHookedApis
 F1CKEN4 08Bh
 cmp byte ptr [eax],0CCh
 jz Anti_Loader_Handler

DontCheckForHookedApis:

Dontpatchimport:
 mov dword ptr [(SYSTEMTIME_STRUCTURE - offset ToAdd) + ebx],eax
 add edi,4
 inc dword ptr [(InternalFunctionCounter - offset ToAdd) + ebx] ; increase the function counta
jmp ParseNextImport
 pop esi
MainImportFinished:

 pop esi

 F1CKEN 0FFh
 add esi,20
CompareAgain_2:
 mov eax,dword ptr [(SAVEDLLRVA - offset ToAdd) + ebx]
 cmp eax,[esi]                    ; compare it with the current one
 jnz NextMainImport               ; difference? then everything is okay
 add esi,20                       ; add 20 bytes to get to the next entry
 Jmp CompareAgain_2               ; compare again

jmp NextMainImport
FinishedWithImports:

EncryptedLayer_4_Start:

 mov esp,dword ptr [(PIZZA - offset ToAdd) + ebx]
 pop dword ptr fs:[0]


 CONFUSE 01h                                              ; Confusing jump crap
 cmp byte ptr [(PEText - offset ToAdd +91h)+ebx],"k"
 jnz ParseNextImport

 CONFUSE 01h                                              ; Confusing jump crap
 pusha
 mov esi,dword ptr [(CODEBASE - ToAdd) + ebx]             ; get the codebase
 add esi,dword ptr [(NEWIBASE - offset ToAdd) + ebx]      ; add the calculated imagebase
 CONFUSE2 04H
 mov dword ptr [(HookVar6 - offset ToAdd) + ebx + 1],esi  ; save the codesection rva
 
 mov dword ptr [(MemoryPosition - offset ToAdd) + ebx + 1],esi  ; save the codesection rva

 mov ecx,dword ptr [(CODESIZE - offset ToAdd) + ebx]      ; get physical size of the codesection
 CONFUSE 04h                                                       ; Confusing jump crap
 mov dword ptr [(HookVar7 - offset ToAdd) + ebx + 1],ecx  ; write the physical code section size

 mov dword ptr [(MemorySize - offset ToAdd) + ebx + 1],ecx  ; write the physical code section size

 CONFUSE 01h                                                       ; Confusing jump crap
 mov eax,dword ptr [(CRC32VALUE1 - offset ToAdd) + ebx]   ; get the first CRC32 Value
 CONFUSE 01h                                                       ; Confusing jump crap
 mov dword ptr [(HookVar10 - offset ToAdd) + ebx + 1],eax ; patch the second value in the code

 mov dword ptr [(CRCValue_2 - offset ToAdd) + ebx + 1],eax ; patch the second value in the code

 mov edx,dword ptr [(CRC32VALUE1 - offset ToAdd) + ebx]
 call Calculate_CRC32                                  ; calculate the crc32 routine
 mov dword ptr [(CRC32VALUE - offset ToAdd) + ebx],eax ; save the crc32 for later use
 mov dword ptr [(REALCRCVALUE - offset ToAdd) + ebx],eax ; save the precalculated crc32 value
 popa

 F1CKEN2 0C7h

 pusha

 F1CKEN4 08Bh

 cmp dword ptr [(BUFFISIZE - offset ToAdd) + ebx],0
 jz No_FakeIATPossible
 mov ecx,dword ptr [(BUFFISIZE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 mov edi,dword ptr [(NEWIBASE - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 add edi,dword ptr [(BUFFIRVA - offset ToAdd) + ebx]
 F1CKEN4 08Bh
 mov eax,ecx
 mov ecx,6
 F1CKEN4 08Bh
 xor edx,edx
 div ecx
 F1CKEN4 08Bh
 mov ecx,eax
 dec ecx
 F1CKEN4 08Bh
 or ecx,ecx
 jz No_FakeIATPossible
 
 F1CKEN4 08Bh
 push ecx
 F1CKEN4 08Bh
 push edi
 mov edx,(offset ModuleDLL - offset ToAdd)    ; offset of the _KERNEL32
 F1CKEN4 08Bh
 add edx,ebx
 push edx
 F1CKEN4 08Bh
 push dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx]
 call CallApi
 mov esi,eax
 F1CKEN4 08Bh
 mov ebp,eax
 pop edi
 F1CKEN4 08Bh
 pop ecx
Generate_Fake_IAT_2:
 push esi
 push ebp
 F1CKEN4 08Bh
 push eax
 push edi
 F1CKEN4 08Bh

 add eax,dword ptr [esi+3Ch] ; pointer to the PE header start
 mov edi,esi
 F1CKEN4 08Bh
 mov eax,[eax+120]
 add eax,esi
 F1CKEN4 08Bh
 xchg eax,esi

 F1CKEN4 08Bh
 call Randomize2
 F1CKEN4 08Bh
 and eax,0FFh
 sub eax,[esi+16]            ; add the ordinal base to the ordinal numba

 push edi
 F1CKEN4 08Bh
 mov edi,[esi+28]
 F1CKEN4 08Bh
 mov esi,ebp
 add edi,esi
 F1CKEN4 08Bh
 mov eax,[eax*4+edi]
 pop edi
 F1CKEN4 08Bh
 add eax,edi
 F1CKEN4 08Bh
 pop edi
 mov ax,25FFh
 stosw
 stosd
 pop eax
 F1CKEN4 08Bh
 pop ebp
 F1CKEN4 08Bh
 pop esi
 F1CKEN4 08Bh
 dec ecx
 jnz Generate_Fake_IAT_2

No_FakeIATPossible:
 popa

DontWriteJump:

 CONFUSE 03h                                                       ; Confusing jump crap
 pusha
 call Randomize2
 mov dword ptr [(offset EVALUE - offset ToAdd) + ebx],eax

 mov esi,dword ptr [(HookVar3 - offset ToAdd) + 2 + ebx]
 mov edx,eax
 CONFUSE 03h                                                       ; Confusing jump crap
 mov edi,esi
 mov ecx,0FFFFFFFFh
Encrypt_It:
 lodsd
 or eax,eax
 jz Table_End_2
 ror eax,cl
 xor eax,edx
 sub eax,dword ptr [(CRC32VALUE - offset ToAdd) + ebx]
 stosd
 lodsb
 xor al,cl
 stosb
 dec ecx
 jnz Encrypt_It
Table_End_2:
 popa

 mov esi,(offset DecryptionRoutinesFinished - offset ToAdd)
 CONFUSE 03h                                                       ; Confusing jump crap
 add esi,ebx
 mov edi,(offset DecryptionRoutines - offset ToAdd)
 add edi,ebx
 mov ecx,(offset MAINAPICODE_END - offset DecryptionRoutinesFinished)
 CONFUSE 0Fh                                                       ; Confusing jump crap
 mov byte ptr [(HowMuchLayers - offset ToAdd) + ebx],2
 mov edx,(offset DecryptionRoutinesFinished - offset MAINAPICODE_START)
 call RelocateMteCode

DllExitCode_Execution:

 F1CKEN4 0E8h
 cmp byte ptr [(ALOADER - offset ToAdd) + ebx],0
 jz BackgroundStuffDisabled
 push 0
 push 4
 push 1000h
 F1CKEN4 0E8h
 push 1024 
 push 0    
 F1CKEN4 0E8h

 push dword ptr [F2RVA - offset ToAdd + ebx]       ; allocate memory for the anti loader handler
 call CallApi

 push eax
 CONFUSE 0Fh                                                       ; Confusing jump crap
 F1CKEN4 0E8h
 mov edx,(offset ModuleDLL - offset ToAdd)        ; offset of the dllname
 add edx,ebx
 F1CKEN4 0E8h
 mov esi,(offset f_VirtualProtect - offset ToAdd)
 add esi,ebx
 call GetApi
 pop edx

 CONFUSE 0Fh                                                       ; Confusing jump crap
 push edx
 mov esi,(offset BYTEWRITTEN - offset ToAdd)
 F1CKEN4 0E8h
 add esi,ebx

 push esi                     ; push the variable for the old privileges..
 F1CKEN4 0E8h
 push PAGE_EXECUTE_READWRITE  ; push the desired access flag (execute&read/write)
 push (Anti_Loader_Handler_End - offset Anti_Loader_Handler) ; size of the region
 F1CKEN4 0E8h
 push edx
 push eax
 Call CallApi

 pop eax
 push eax

 CONFUSE 83h                                                       ; Confusing jump crap
 mov edi,eax
 mov esi,(offset Anti_Loader_Handler - offset ToAdd)
 add esi,ebx
 mov ecx,(Anti_Loader_Handler_End - offset Anti_Loader_Handler)
Copy_And_Erase:
 lodsb
 mov byte ptr [esi-1],0
 stosb
 dec ecx
 jnz Copy_And_Erase

 F1CKEN4 0E8h
 mov esi,(offset GetCurrentProcess_Id - offset ToAdd)
 add esi,ebx
 F1CKEN4 0E8h
 push esi
 F1CKEN4 0E8h
 push dword ptr [(Kernel32RVA - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 push dword ptr [(Thunktable - offset ToAdd)+ebx]                  ; call "GetProcAddress"
 call CallApi

 push eax
 Call CallApi

 CONFUSE 36h                                                       ; Confusing jump crap
 push eax                                                          ; push processid
 push 0
 push PROCESS_SET_INFORMATION
 push dword ptr [(OpenProcessRVA - offset ToAdd) + ebx]
 call CallApi
 F1CKEN4 0E8h
 mov dword ptr [(PROCESSHANDLE - offset ToAdd) + ebx],eax          ; save the process handle
 pop eax

 CONFUSE 0F7h                                                       ; Confusing jump crap
 mov edx,(offset Thread_ID2 - offset ToAdd)
 add edx,ebx
 push edx
 push CREATE_SUSPENDED                                             ; create a thread which runs after resumethread
 push 0
 push eax
 push 0
 push 0
 F1CKEN4 0E8h
 push dword ptr [(CreateThreadRVA - offset ToAdd) + ebx]
 call CallApi
 F1CKEN4 0E8h
 mov dword ptr [(Thread_Handle2 - offset ToAdd) + ebx],eax         ; save thread handle

 CONFUSE 0F7h                                                      ; Confusing jump crap
 push THREAD_PRIORITY_LOWEST
 push dword ptr [(Thread_Handle2 - offset ToAdd) + ebx]            ; push thread id
 F1CKEN4 0E8h
 push dword ptr [(SetThreadPriorityRVA - offset ToAdd) + ebx]
 call CallApi

 F1CKEN4 0E8h
 push dword ptr [(Thread_Handle2 - offset ToAdd) + ebx]            ; push thread handle
 F1CKEN4 0E8h
 push dword ptr [(ResumeThreadRVA - offset ToAdd) + ebx]
 call CallApi

BackgroundStuffDisabled:
 mov esp,dword ptr [SAVEESP2 - offset ToAdd + ebx]   ; restore esp
 pop ebp
 F1CKEN4 0E8h
 pop edi
 pop esi

 mov eax,dword ptr [NEWIBASE - offset ToAdd + ebx]  ; get the imagebase
 F1CKEN4 0E9h
 add eax,dword ptr [RIGHTONE - offset ToAdd + ebx]  ; add the rva
 jmp eax

Anti_Loader_Handler:
 call $+5
 pop ebx
 sub ebx,5
 F1CKEN4 0F7h
RestartCalculatingTheCrc:

MemoryPosition:
 mov esi,1                                 ; points to the code section
 F1CKEN4 0F7h
MemorySize:
 mov ecx,1                                 ; Physical Size of the code section
 F1CKEN4 0F7h
CRCValue_2:
 mov edx,1                                 ; second CRC32 Value
 F1CKEN4 0F7h
 shr ecx,2
 F1CKEN4 0F7h
Calculate_CRC_32:
 lodsd
 add edx,eax
 xor edx,ecx
 dec ecx
 jnz Calculate_CRC_32
 F1CKEN4 0F7h
 xchg eax,edx
 cmp eax,[(REALCRCVALUE - offset Anti_Loader_Handler) + ebx]
 jz CrcIsOkay
 F1CKEN4 0F7h
 mov edi,dword ptr [(MemoryPosition - offset Anti_Loader_Handler) + 1 + ebx]
 F1CKEN4 0F7h
 mov ecx,dword ptr [(MemorySize - offset Anti_Loader_Handler) + 1 + ebx]
 F1CKEN4 0F7h
 shr ecx,2
 F1CKEN4 0F7h
 rep stosd
CrcIsOkay:
 jmp RestartCalculatingTheCrc
 REALCRCVALUE dd 0    ; offset of the pre calculated crc value...
Anti_Loader_Handler_End:

MutateHookedApi:
 pusha
 call $+5
 pop ebx
 sub ebx,(offset MutateHookedApi - offset ToAdd) + 6
 CONFUSE 02h                                                       ; Confusing jump crap
 mov esi,(offset DecryptionRoutinesFinished - offset ToAdd)
 add esi,ebx
 mov edi,(offset DecryptionRoutines - offset ToAdd)
 add edi,ebx
 CONFUSE 01h                                                       ; Confusing jump crap
 mov ecx,(offset MAINAPICODE_END - offset DecryptionRoutinesFinished)
 mov byte ptr [(HowMuchLayers - offset ToAdd) + ebx],2
 mov edx,(offset DecryptionRoutinesFinished - offset MAINAPICODE_START)
 call RelocateMteCode
 popa
 pop eax
 F1CKEN4 0E8h
 test byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],00000000000000000000000000000001b
 jz NoAntiBpxStuff_Selected
 popa
HookVar5:
 push dword ptr cs:[(JumpOffset - offset ToAdd)]

CallApi2:
 push ebx
 call $+5
 pop ebx
 sub ebx,(offset CallApi2 - offset ToAdd) + 6
 mov dword ptr [(SAVEEAX - offset ToAdd) + ebx],eax ; save eax
 pop eax
 F1CKEN4 0E8h
 mov dword ptr [(SAVEEBX - offset ToAdd) + ebx],eax ; save ebx
 F1CKEN4 0E8h
 mov dword ptr [(SAVEECX - offset ToAdd) + ebx],eax ; save ecx
 F1CKEN4 0E8h
 mov dword ptr [(SAVEEDX - offset ToAdd) + ebx],edx ; save edx
 F1CKEN4 0E8h
 mov dword ptr [(SAVEEDI - offset ToAdd) + ebx],edi ; save edi
 F1CKEN4 0E8h
 mov dword ptr [(SAVEESI - offset ToAdd) + ebx],esi ; save esi
 F1CKEN4 0E8h
 mov dword ptr [(SAVEEBP - offset ToAdd) + ebx],ebp ; save ebp
 pop esi
 mov dword ptr [(SAVEEIP - offset ToAdd) + ebx],esi ; save eip

 F1CKEN4 0E8h
 cmp byte ptr [esi],0CCh
 jz HookVar4
               
GetNextMnemonic2:
 xor eax,eax
 F1CKEN4 0E8h
 lodsb
 cmp al,50h
 jb NoPushblainstruction2
 cmp al,57h
 ja NoPushblainstruction2
 sub al,50h             
 push dword ptr [(eax*4)+(offset SAVEEAX - offset ToAdd) + ebx]
 jmp GetNextMnemonic2
NoPushblainstruction2:
 cmp al,68h
 jnz NoDirectDwordValuePush2
 push dword ptr [esi]
 add esi,4
 jmp GetNextMnemonic2
NoDirectDwordValuePush2:
 cmp al,0E8h
 jnz NoCall2
 push esi
 mov esi,[esi]
 jmp GetNextMnemonic2
NoCall2:
 cmp word ptr [esi-1],0EC8Bh
 jnz NoMoVEbpEsp2
 inc esi
 mov dword ptr [(SAVEEBP - offset ToAdd) + ebx],esp
 jmp GetNextMnemonic2
NoMoVEbpEsp2:
 cmp word ptr [esi-1],0D22Bh
 jnz NoSubEdxEdx2
 mov dword ptr [(SAVEEDX - offset ToAdd) + ebx],0
 inc esi
 jmp GetNextMnemonic2
NoSubEdxEdx2:
 cmp al,6Ah
 jnz NoDirectPushi2
 movzx eax,byte ptr [esi]
 push eax
 inc esi
 jmp GetNextMnemonic2

NoDirectPushi2:
 F1CKEN4 0E8h
 mov edx,(FarJmpOffset2 - offset ToAdd)
 add edx,ebx
 sub esi,6
 mov edi,esi
 sub edi,edx
 mov dword ptr [edx+1],edi
 F1CKEN4 0E8h
 mov eax,dword ptr [(SAVEEAX - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov ecx,dword ptr [(SAVEECX - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov edx,dword ptr [(SAVEEDX - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov edi,dword ptr [(SAVEEDI - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov esi,dword ptr [(SAVEESI - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov ebp,dword ptr [(SAVEEBP - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov ebx,dword ptr [(SAVEEBX - offset ToAdd) + ebx]
FarJmpOffset2:
 db 0E9h
 dd 0
NoAntiBpxStuff_Selected:
 popa
NoAntiBpxStuffSelected:
 push dword ptr cs:[(JumpOffset - offset ToAdd)]
 ret
JumpOffset:
 dd 0 ; includes the rva for this APIcall

HookedAPICODE_START:
 pusha
HookVar1:
 mov ebp,1      ; 1 = variable
HookJump1:
 db 0E9h        ; far jump
JMPDATA:
 dd 0
Holladrio:
HookedAPICODE_END:

MAINAPICODE_START:
 DecryptionRoutines db 130 dup (90h)         ; buffer for the api decryption routines

DecryptionRoutinesFinished:
 push eax
 mov eax,5
 mul ebp
 xchg eax,ebp
 pop eax

HookVar3:
 add ebp,1234

HookVar6:
 mov esi,1                                 ; points to the code section
HookVar7:
 mov ecx,1                                 ; Physical Size of the code section
HookVar10:
 mov edx,1                                 ; second CRC32 Value
; call Calculate_CRC32                      ; calculate the crc32 routine

 shr ecx,2
 push esi
 push ecx
 push edx

Calculate_CRC32_2__:
 lodsd
 add edx,eax
 xor edx,ecx
 dec ecx
 jnz Calculate_CRC32_2__
 xchg eax,edx
 pop edx
 pop ecx
 pop esi

 pusha
RelocateDecryptCode:
 call $+5
 pop ebx
 sub ebx,(offset RelocateDecryptCode - offset ToAdd) + 5

 mov ebp,eax

 F1CKEN4 0E8h
 mov esi,dword ptr [(HookVar3 - offset ToAdd) + 2 + ebx]
 mov edx,dword ptr [(offset EVALUE - offset ToAdd) + ebx]
 F1CKEN4 0E8h
 mov edi,esi
 CONFUSE 03h                                                       ; Confusing jump crap
 mov ecx,0FFFFFFFFh
DecryptIt:
 lodsd
 or eax,eax
 jz TableEnd
 add eax,ebp
 xor eax,edx
 rol eax,cl
 stosd
 lodsb
 xor al,cl
 stosb
 dec ecx
 jnz DecryptIt
TableEnd:
 popa

RelocateMyself:
 call $+5
 pop ebx
 sub ebx,(RelocateMyself - offset ToAdd) + 5

 F1CKEN4 0E8h
 mov eax,[ebp]                             ; get the api offset
 push edx
 mov dl,byte ptr [ebp+4]                   ; get kind of api hook
 F1CKEN4 0E8h
 mov byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],dl ; save it
 pop edx
HookVar4:
 mov edi,(JumpOffset - offset ToAdd)       ; pointer to the api variable
 mov [edi],eax

 shl ecx,2
; call Calculate_CRC32                      ; calculate the crc32 routine

 shr ecx,2
 push esi
 push ecx
 push edx

Calculate_CRC_32_2:
 lodsd
 add edx,eax
 xor edx,ecx
 dec ecx
 jnz Calculate_CRC_32_2
 xchg eax,edx
 pop edx
 pop ecx
 pop esi



 pusha
 F1CKEN4 0E8h
 mov ebp,eax

 F1CKEN4 0E8h

 push ecx
 push ebx
 mov ecx,10
 mov ebx,esp
 sub ebx,10
GenerateDamnRandomValue:
 xor eax,[ebx]
 inc ebx
 dec ecx
 jnz GenerateDamnRandomValue
 pop ebx
 pop ecx

 mov dword ptr [(offset EVALUE - offset ToAdd) + ebx],eax
 CONFUSE 03h                                                       ; Confusing jump crap
 mov esi,dword ptr [(HookVar3 - offset ToAdd) + 2 + ebx]
 F1CKEN4 0E8h
 mov edx,eax
 mov edi,esi
 F1CKEN4 0E8h
 mov ecx,0FFFFFFFFh
EncryptIt:
 lodsd
 or eax,eax
 jz Table_End
 ror eax,cl
 xor eax,edx
 sub eax,ebp
 stosd
 lodsb
 xor al,cl
 stosb
 dec ecx
 jnz EncryptIt
Table_End:
 popa
 CONFUSE2 01H
HookVar11:
 mov edi,(offset CRC32VALUE - offset ToAdd); points to CRC32VALUE variable

 F1CKEN4 0E8h
 test byte ptr [(KINDOFHOOK - offset ToAdd) + ebx],00000000000000000000000000000100b
 jz AgainNoChecksumNeeded
 F1CKEN4 0E8h
 cmp eax,[edi]                             ; compare the calculated checksums
 jnz EncryptedLayer_4_Start                ; jump into garbage code
AgainNoChecksumNeeded:
 call MutateHookedApi

CRC32VALUE:
 dd 0 ; crc32 for the code section
EVALUE:
 dd 0 ; encryption value for the rva table ;)

MAINAPICODE_END:

 RIGHTONE dd 0 ; Entrypoint aka RVA

 include r-crc32.inc ; includes the lame crc32 routine

EncryptedLayer_4_End:
Encrypt2Layer_End:
EncryptLayer3_End:


;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;Parameter of GetApi
;edx = offset of the dll name ( 0 terminated of course)
;esi = offset of the Function name ( 0 terminated of course)
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ

MemAError:
 push 30h
 F1CKEN 0FFh
 mov eax,(offset DeallocErrorHead - offset ToAdd)
 add eax,ebx
 push eax

 F1CKEN 0FFh

 mov eax,(offset AllocError - offset ToAdd)
 add eax,ebx
 push eax
 push 0

MboxError:
 mov edx,(offset _USER32 - offset ToAdd)       ; offset of the dllname
 add edx,ebx
 mov esi,(offset f_MessageBoxA - offset ToAdd)  ; offset of the function
 add esi,ebx
 Call GetApi                                ; get the rva of this function

 F1CKEN 0FFh

 call eax

 mov edx,(offset ModuleDLL - offset ToAdd)    ; offset of the _KERNEL32
 add edx,ebx

 F1CKEN 0FFh

 mov esi,(offset f_ExitProcess - offset ToAdd)  ; offset of the function
 add esi,ebx
 Call GetApi                                ; get the rva of this function
 push 0FFh
 call eax                                   ; quit

GetApi proc
 push edx
 push edx

 push dword ptr [(offset Thunktable+4 - offset ToAdd)+ebx]
 call CallApi
 or eax,eax
 jnz LibaryFound
 pop edx

 push edx
 push edx
 push edx
 push dword ptr [(offset Thunktable - offset ToAdd)+((3*4)-4)+ebx]
 call CallApi
 pop edx
 or eax,eax
 jz DllError
LibaryFound:
 push esi
 push eax
 push dword ptr [(Thunktable - offset ToAdd)+ebx]   ; call "GetProcAddress"
 call CallApi
 or eax,eax
 pop edx
 jz FunctionNotImportable
 ret
GetApi Endp

FunctionNotImportable:
 mov edi,esi
 push edi
 xor al,al
 repnz scasb
 stosb
 pop esi
 sub edi,esi
 mov ecx,edi
 mov edi,(offset ImportError2 - offset ToAdd) + 41
 add edi,ebx
 rep movsb
 xor al,al
 stosb
 push 30h
 mov eax,(offset ImportError2H - offset ToAdd)
 add eax,ebx
 push eax
 mov eax,(offset ImportError2 - offset ToAdd)
 add eax,ebx
 push eax
 push 0
 jmp MboxError

DllError:
 mov edi,edx
 push edi
 xor al,al
 repnz scasb
 stosb
 pop esi
 sub edi,esi
 mov ecx,edi
 mov edi,(offset ImpError - offset ToAdd) + 15
 add edi,ebx
 rep movsb
 xor al,al
 stosb
 F1CKEN 0FFh
 push 30h
 mov eax,(offset ImportError - offset ToAdd)
 add eax,ebx
 push eax
 mov eax,(offset ImpError - offset ToAdd)
 add eax,ebx
 push eax
 push 0
 jmp MboxError


;Generates a random value
;edi = maximal value allowed
;
RandomizeValue proc
 push ecx
GenerateAgain2:
 Call Randomize2
 xchg ecx,eax
 Call Randomize2
 xor ecx,eax
 Call Randomize2
 xor eax,ecx
; mov ecx,eax
; and ecx,0FFFFh
 mov ecx,255
 xor edx,edx
GenValues2:
 xor eax,ecx
 rol edx,cl
 inc edx
 dec ecx
 jnz GenValues2
 xor eax,edx
 xor edx,edx
 div edi
 mov eax,edx
 or eax,eax
 jz GenerateAgain2
 pop ecx
 ret
RandomizeValue endp

CallApi proc
 push ebx
 call $+5
 pop ebx
 sub ebx,(offset CallApi - offset ToAdd) + 6
 mov dword ptr [(SAVEEAX - offset ToAdd) + ebx],eax ; save eax
 F1CKEN 0FFh
 pop eax
 mov dword ptr [(SAVEEBX - offset ToAdd) + ebx],eax ; save ebx
 mov dword ptr [(SAVEECX - offset ToAdd) + ebx],eax ; save ecx
 F1CKEN 0FFh
 mov dword ptr [(SAVEEDX - offset ToAdd) + ebx],edx ; save edx
 mov dword ptr [(SAVEEDI - offset ToAdd) + ebx],edi ; save edi
 F1CKEN 0B8h
 mov dword ptr [(SAVEESI - offset ToAdd) + ebx],esi ; save esi
 mov dword ptr [(SAVEEBP - offset ToAdd) + ebx],ebp ; save ebp
 pop esi
 F1CKEN 0FFh
 mov dword ptr [(SAVEEIP - offset ToAdd) + ebx],esi ; save eip
 pop esi

 F1CKEN 0D8h
 push dword ptr [(SAVEEIP - offset ToAdd) + ebx]    ; push current eip

 F1CKEN 0F7h
 cmp byte ptr [esi],0CCh
 F1CKEN4 0F7h
 jz HookVar4
 F1CKEN4 0E9h

GetNextMnemonic:
 xor eax,eax
 lodsb
 cmp al,50h
 jb NoPushblainstruction
 cmp al,57h
 ja NoPushblainstruction
 sub al,50h             
 push dword ptr [(eax*4)+(offset SAVEEAX - offset ToAdd) + ebx]
 jmp GetNextMnemonic
NoPushblainstruction:
 cmp al,68h
 jnz NoDirectDwordValuePush
 push dword ptr [esi]
 add esi,4
 jmp GetNextMnemonic
NoDirectDwordValuePush:
 cmp al,0E8h
 jnz NoCall
 push esi
 mov esi,[esi]
 jmp GetNextMnemonic
NoCall:
 cmp word ptr [esi-1],0EC8Bh
 jnz NoMoVEbpEsp
 inc esi
 mov dword ptr [(SAVEEBP - offset ToAdd) + ebx],esp
 jmp GetNextMnemonic
NoMoVEbpEsp:
 cmp word ptr [esi-1],0D22Bh
 jnz NoSubEdxEdx
 mov dword ptr [(SAVEEDX - offset ToAdd) + ebx],0
 inc esi
 jmp GetNextMnemonic
NoSubEdxEdx:
 cmp al,6Ah
 jnz NoDirectPushi
 movzx eax,byte ptr [esi]
 push eax
 inc esi
 jmp GetNextMnemonic

NoDirectPushi:
 mov edx,(FarJmpOffset - offset ToAdd)
 add edx,ebx
 sub esi,6
 mov edi,esi
 sub edi,edx
 mov dword ptr [edx+1],edi
 mov eax,dword ptr [(SAVEEAX - offset ToAdd) + ebx]
 mov ecx,dword ptr [(SAVEECX - offset ToAdd) + ebx]
 mov edx,dword ptr [(SAVEEDX - offset ToAdd) + ebx]
 mov edi,dword ptr [(SAVEEDI - offset ToAdd) + ebx]
 mov esi,dword ptr [(SAVEESI - offset ToAdd) + ebx]
 mov ebp,dword ptr [(SAVEEBP - offset ToAdd) + ebx]
 mov ebx,dword ptr [(SAVEEBX - offset ToAdd) + ebx]
CodeCRC_End:

FarJmpOffset:
 db 0E9h
 dd 0
CallApi endp

Randomize2 proc
 push ecx
 call dword ptr [(GetTickCountRVA - offset ToAdd) + ebx] 
 xchg eax,ecx
 call dword ptr [(GetTickCountRVA - offset ToAdd) + ebx] 
 xor ecx,eax
 call dword ptr [(GetTickCountRVA - offset ToAdd) + ebx] 
 xor ecx,eax
 xchg eax,ecx
 pop ecx
 ret
Randomize2 endp

REALCODE_CRC_END:

 include r-slowmte2.inc

 Align 4
DECRRUNNING db 0 ; is already an api decryption running?
 KINDOFHOOK db 0             ; defines the kind of the hook (api or bpx/bpm trick..or both)
InternalFunctionCounter dd 0 ; internal function countaaaa (for the api hooking)
BYTEWRITTEN dd 0             ; needed for writeprocessmemory
   TablePos dd (offset FunctionT - offset ToAdd) ; position in the internal api table (needed for api hooking)
 TablePos2 dd (offset FunctionT2 - offset ToAdd) ; position in the internal api table (needed for anti bpx/bpm stuff)
     DLLPOS dd 0 ; position of the dllname in the import table
    CRAPVAR dd 0 ; holds a pseudo random value , used for lame routines ;)
 HOOKEDAPIS dd 0 ; points to available mem for hooked apis
 TableEntry dd 0 ; counter for the rva table
NEWAPIBUFFE dd 0 ; buffaaa
   CODEOFS2 dd 0 ; y000 niggaahhhh
  FunctionT db 2000 dup (0) ; 500 hooked functions = maximum
 FunctionT2 db 2000 dup (0) ; The Anti BPX routines can handle about 500 functions
     Hookem db 0 ; hooking of this api allowed?
    HookRVA dd 0 ; rva for the new function (points to the pecrypt32 apis)
CRC32VALUE1 dd 0 ; first CRC32 value
CRC32VALUE2 dd 0 ; second CRC32 value
  REAL_SIZE dd 0
   CRCERROR db 0 ; internal variable for the crc error handling
 PatchCode1 db 0 ; cryptvalue
     OLDRVA dd 0 ; The saved RVA
    TEMPVAR dd 0 ; just a lame tempvar ;)
   CODESIZE dd 0 ; CodeSize
  RELOCBASE dd 0 ; the relocation base ..uetz uetz 
  RELOCLENG dd 0 ; relocation obj length size....
 RELOCDELTA dd 0 ; relocation delta value  
 RELOCVSIZE dd 0 ; virtual size of the relocation object
   OBJTABLE db 800 dup (0) ; some obj things..lalalala
SAVEFIRSTRB dd 0
  RBCOUNTER dd 0 ; relocation base counter 
CRYPTVALUE2 dd 0 ; cryptvalue 2 (for the relocations)
  CRYPTVAR1 dd 0 ; don't know ;)
    COUNTER dd 0
     FICKEN dd 0 ; just a temp variable ;)
   OBJVSIZE dd 0 ; virtual size of this section
   OBJRSIZE dd 0 ; real size of a section 
DECOMPSTART dd 0 ; pointer to the decompression buffa
      CTRUE db 0 ; compressed or not?
    SAVEORD dd 0 ; save variable for the ordinal number
      PIZZA dd 0 ; just a lame variable
     DECOMR db 0
    DIRSIZE dd 0 ; size of the resource directory
DECRELOCOFS dw 0 ; offset of relocation for the reloc decompression routine
   Paranoia dd 0 ; this routine is getting annoying, grrrr
   PCounter dd 0 ; paranoia counta
  RELOCSAVE dd 0,0 ; relocation block information
 RELOCSAVE2 dw 0 ; first relocation (the block is only 10bytes)
PreviousCRC dd 0 ; previous crc (used for objecttable encryption)
     OBJCRC dd 0 ; CRC value of the current object
     VALUE1 dd 0 ; another lame value
     VALUE2 dd 0 ; another lame value ;)
      FLAGI dd 0 ; flags of this section
  ENCRYPTV1 dd 0 ; encryption value for the objecttable encryption
  ENCRYPTV2 dd 0 ; encryption value for the objecttable encryption ;)

  ENCRYPTV3 dd 0 ; used for the relocation encryption
  ENCRYPTV4 dd 0 ; l33t value for the relocation encryption
  ENCRYPTV5 dd 0 ; CRC value for the reloc encryption

  ENCRYPTV6 dd 0 ; CRC value for the resource encryption
  ENCRYPTV7 dd 0 ; encryption value for the resource encryption
  ENCRYPTV8 dd 0 ; encryption value for the resource encryption

  ENCRYPTV9 dd 0 ; encryption value for the 2nd layer (ring 0 of course) hehe
 ENCRYPTV10 dd 0 ; encryption value for the 2nd layer

 ENCRYPTV11 dd 0 ; encryption value for the 3rd layer
 ENCRYPTV12 dd 0 ; encryption value for the 3d layer
  DLLSTRING db 40 dup (0) ; buffer where the dllname gets decrypted to :]
   BUFFIRVA dd 0 ; start for the fake iat table
  BUFFISIZE dd 0 ; size of the fake iat table
RESOURCEBYT dd 0 ; 4 bytes from the first crap after the resource directory (for shared support)

;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;ErrorMessages for the pecrypt32 kernel
;
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ

 Align 4

DeallocErrorHead db "PECRYPT32: MEMORY ERROR!",0
    DeallocError db " - Deallocation error.",0
      AllocError db " - Allocation error.",0
   SICEErrorHead db "PECRYPT32: LOADER ERROR!",0
       SICEError db " YO HUEPFBAER, DISABLE SOFTICE",0

     ImportError db "PECRYPT32: IMPORT LOADER ERROR!",0
	ImpError db " - Can't find                                           "
   ImportError2H db "PECRYPT32: - IMPORT LOADER ERROR -",0
    ImportError2 db " -  Can't import the exported function :                 "

    HeuristicA1H db "PECRYPT32: HEURISTIC VIRUS ALERT!",0
     HeuristicA1 db "Possible virus infection of this PE file.  ",0
       CRCErrorH db "PECRYPT32: CRC ERROR!",0
	CRCError db "Execution stopped.",0
       IMPORTOFS dd 0 ; offset of the import section
f_GetKernelVersion db "GetVersion",0
	   F6RVA dd 0
   f_OpenProcess db "OpenProcess",0
	   F7RVA dd 0
f_WriteProcessMemory db "WriteProcessMemory",0
	   F8RVA dd 0
f_GetCurrentProcessId db "GetCurrentProcessId",0
	   F9RVA dd 0

Layer1End: ; <- end of layer1 encryption
Encrypted_Block1_End:

 Align 4

;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;new imports (just another lame try to call the fucking kernel32 apis)
;don't change anything!!!!
;change and die!
;change and kriech forever (english/german - mixture) :)
;ich hau dir auf die nuschel wenn du irgendwas aenderst..grrrrr
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
            dd 0
NamehOffset dd 0                               ; offset to the name/hide table
  StampDate dd 0                               ; date of this import
     FChain dd 0                               ; forward chain, not needed
     Dllrva dd offset _KERNEL32  - offset ToAdd ; rva to the dll name 
   ThunkRva dd offset Thunktable - offset ToAdd ; rva of the thunk table
	    dd 0
	    dd 0
	    dd 0
	    dd 0
	    dd 0

 Thunktable dd offset iGetProcAddress - offset ToAdd
	    dd offset iGetModuleHandleA - offset ToAdd
	    dd offset iLoadLibraryA - offset ToAdd
	    dd 0
	    dd 0   
 Align 4

 iGetProcAddress dw 0 
	    db "GetProcAddress",0
 Align 4
 iGetModuleHandleA dw 0
	    db "GetModuleHandleA",0
 Align 4

 iLoadLibraryA dw 0
	    db "LoadLibraryA",0
 Align 4

    _KERNEL32 db "KERNEL32.DLL",0,0
ImportEnd:
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ

 Align 4

   f_MessageBoxA db "MessageBoxA",0
	 _USER32 db "USER32.DLL",0
   f_ExitProcess db "ExitProcess",0
	 ERRORMH db "PECRYPT32: LOADER ERROR!",0
	  ERRORM db "ERROR WHILE LOADING",0
  f_VirtualAlloc db "VirtualAlloc",0
   f_VirtualFree db "VirtualFree",0
	   F4RVA dd 0
   f_CreateFileA db "CreateFileA",0

 Align 4
	RVATABLE dd 0 ; 1024 bytes (1kb) of memory are needed for the rvatable
	   F1RVA dd 0
	   F5RVA dd 0
	    LOBJ dd 0 ; pre calculated value ;)
	   LSIZE dd 0 ; virtual size of the last obj (for the virus check)
RESOURCE_ENCRYPT dd 0
	CODEBASE dd 0 ; base of the code 
       IMAGEBASE dd 0 ; Image base
	NEWIBASE dd 0 ; calculated imagebase :) (for relocation loading)
     DLLLOCATION dd 0
	MemStart dd 0
     FunctionRVA dd 0
     RESOURCEOFS dd 0 ; rva of the resource obj
     RESOURCESIZ dd 0 ; resource size,muahaha
    RESOURCEVSIZ dd 0 ; virtual size of the resource section
	   F2RVA dd 0
	SAVEESP2 dd 0 ; 2nd temp variable for esp
	SAVEESP3 dd 0 ; 3nd temp variable for esp (needed by slowmte2.inc)
     START_VALUE dd 0 ; value for the first encryption layer
	OFSVALUE dd 0 ; value for the first routine
	OFSVSIZE dd 0 ; virtual size for the first routine
	SAVECRAP dd 0 ; just a lame temp variable
	hash_seg dd 0
       CCOUNTER1 dd 0
       CCOUNTER2 dd 0
	REALSIZE dd 0 ; real physical size of the current section
	TEMPVARI db 0
	  ALDONE db 0 ; already done?
       OBJCOUNTI dw 0

;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;some antidebugging variables ;)
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
    Align 4

    IDTVALUE dd 0 ; value for the great idt crap ;)
	     dw 0 ; 6 bytes (fword) 
   SaveFTemp dd 0 ; just to save some crap like rvas :)
 ARTOFRELOC1 db 0
 IMP_DESTROY db 0 ; enhanced import destroying? eg: IAT fakes
   LOADRELOC db 1 ; load relocation? 1 = yes, 0 = no
       RCOMP db 0 ; compressed resources? , 1 = yes, 0 = no
    CUTDINFO db 0 ; debug info removed?
      RESEND db 0 ; resource section = last section?
  RELOCCOMPP db 0 ; internal relocation compression flag
     AMETHOD db 0 ; antidebugging method
   HEURISTIC db 0 ; internal variable for the virus heuristic option
    OBJNUMBA dw 0 ; number of objects in the peheader
  FATALERROR db 0 ; internal variable for a fatal error ;)
   HOOKFUNCT db 0 ; hook functions?
   LOADEROPT db 0             ; variable for the api hooking
    KILLHEAD db 0             ; variable for the erasing of the header
    RelocCCC db 0 ; relocation compression running?
     ALOADER db 0 ; anti loader option
   RelocSize dd 0 ; the size of the relocation section before it
		  ; was packed with the 2nd compression layer
;
   RELOCSIZE dd 0
;  COMPATIBLE db 0 ; enables the compatibility with other programs like BJFnt
  ANTIBPXBPM db 0 ; anti bpx <api> / bpm <api> protection
    EXEFLAGS db 0 ; DLL or Program ?
  SAVEDLLRVA dd 0 ; needed to fix this damn fucking conseal bug
VALUE_THREAD dd 0 ; value needed for the thread encryption / decryption
   SAVEBYTES db 5 dup(0)
   DLLNAMESL db 50 dup (0) ; buffer for all dll name sizes
  NAMECOUNTI db 0          ; dll name countiii
     SAVEESP dd 0 ; temp variable for esp
  SAVEOLDRVA dd 0
     IMPENC2 dd 0 ; random value for the import encryption / decryption
     IMPENC4 dd 0 ; random value for the import encryption / decryption
   ORIGBYTES dd 0
	     db 0



 SAVEEAX dd 0
 SAVEECX dd 0
 SAVEEDX dd 0
 SAVEEBX dd 0
SAVEESP9 dd 0
 SAVEEBP dd 0
 SAVEESI dd 0
 SAVEEDI dd 0
 SAVEEIP dd 0

InstructionTable:
	   dw 0E1FFh
	   dw 0E2FFh
	   dw 0E7FFh
	   dw 0E6FFh
	   dw 0E5FFh


;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;Some variables and function rvas for the thread decryption
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
	     OLDIMPRVA dd 0                       ; the old import rva
	   Kernel32RVA dd 0                       ; rva of kernel32.dll
  GetCurrentProcess_Id db "GetCurrentProcessId",0 ; functioname
	OpenProcessRVA dd 0                       ; openprocess rva
	  Open_Process db "OpenProcess",0         ; functioname
     SetPriority_Class db "SetPriorityClass",0    ; functioname
   SetPriorityClassRVA dd 0                       ; 'SetPriorityClass' rva
	 Create_Thread db "CreateThread",0        ; functioname
       CreateThreadRVA dd 0                       ; 'CreateThread' rva
    SetThread_Priority db "SetThreadPriority",0   ; functioname
  SetThreadPriorityRVA dd 0                       ; 'SetThreadPriority' rva
	 CreateEvent_A db "CreateEventA",0        ; functioname
       CreateEventARVA dd 0                       ; 'CreateEventA' rva
  WaitForSingle_Object db "WaitForSingleObject",0 ; functioname
WaitForSingleObjectRVA dd 0                       ; 'WaitForSingleObject' rva
	     Set_Event db "SetEvent",0            ; functioname
	   SetEventRVA dd 0                       ; 'SetEvent' rva
	   Reset_Event db "ResetEvent",0          ; functioname
	 ResetEventRVA dd 0                       ; 'ResetEvent' rva
	Suspend_Thread db "SuspendThread",0       ; functioname
      SuspendThreadRVA dd 0                       ; 'SuspendThread' rva
	 Resume_Thread db "ResumeThread",0        ; functioname
       ResumeThreadRVA dd 0                       ; 'ResumeThread' rva
      Terminate_Thread db "TerminateThread",0     ; functioname
    TerminateThreadRVA dd 0                       ; 'TerminateThread' rva
  GetTickCountFunction db "GetTickCount",0        ; functioname
	   LayerBuffer dd 0                       ; reserved memory for the decryption layers
	    Thread_ID2 dd 0 ; identifier of the created thread
	Thread_Handle2 dd 0 ; handle of the created thread
	 Byte2Encrypt2 dd 0 ; holds the dword which needs to get encrypted
	EventO_Handle2 dd 0 ; holds the handle of the created event object
       EventO_Handle22 dd 0 ; holds the 2nd event handle
	      SaveEDX2 dd 0 ; holds edx
	      SaveECX2 dd 0 ; holds ecx
	      SAVETIME dd 0 ; saves the time
	 PROCESSHANDLE dd 0 ; handle of the opened process
       GetTickCountRVA dd 0 ; rva of the gettickcount function
      GetSystemTimeRVA dd 0 ; 'GetSystemTime' rva
	     ModuleDLL db "KERNEL32.DLL",0
  SYSTEMTIME_STRUCTURE db 0
		 wYear dw 0
		wMonth dw 0
	    wDayOfWeek dw 0
		  wDay dw 0
		 wHour dw 0
	       wMinute dw 0
	       wSecond dw 0
	 wMilliseconds dw 0
	       HANDLER dd 0
	     DURCHGANG db 0
	     MEMSTARTI dd 0

PEText:
  db 0dh,0ah,"ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ",0dh,0ah
  db         "  -[þ]- PECRYPT32 ",PE_CryptVer,"  ú  coding project by random & killa   -[þ]-"
  db 0dh,0ah,"ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ"
ToAdd_END:

;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;Information about the new PECRYPT32 objecttable
;
;1 dword = rva of the object
;1 dword = physical size of this object
;1 dword = encryption value
;1 dword = virtual size
;1 byte  = compressed or not?
;1 dword = crcvalue of this object
;1 dword = real size of this object (not aligned)
;1 dword = old physical size of this object 
;1 dword = flags of this section
;
;every objecttable is 33 bytes in length
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
