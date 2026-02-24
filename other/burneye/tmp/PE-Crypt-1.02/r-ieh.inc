;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;New Pecrypt32 Encryption / Decryption Routine
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;
;Features: 
; - 1 Thread for generating of checksum & decryption
; - main process for writing the decrypted memory
;
RIEHInc_Start:

Thread_Encryption_Start:

 call GetCurrentProcessId          ; get current process id

 push eax                          ; push processid
 push 0
 push PROCESS_SET_INFORMATION+DEBUG_ONLY_THIS_PROCESS  ; enable set information flag & debug flag 
 call OpenProcess                  ; open process and receive handle

 push REALTIME_PRIORITY_CLASS
 push eax                          ; push process handle
 call SetPriorityClass             ; set the priority class of this thread

 push offset Thread_ID             ; for later save of the thread id
 push CREATE_SUSPENDED             ; create a thread which runs after resumethread
 push 0
 push offset Thread_Handler        ; thread entrypoint
 push 0
 push 0
 Call CreateThread                 ; create a new funny thread
 mov dword ptr [Thread_Handle],eax ; save thread handle

 push THREAD_MAX_PRIORITY
 push dword ptr [Thread_Handle]    ; push thread id
 call SetThreadPriority            ; set thread priority

 push 0                            ; no event name needed niggaz
 push 0                            ; initial state = non signaled
 push 0                            ; wtf??
 push 0                            ; default security descriptor is enough
 call CreateEventA
 mov dword ptr [EventO_Handle],eax ; save the handle of the created event object

 push 0                            ; no event name needed niggaz
 push 0                            ; initial state = non signaled
 push 0                            ; wtf??
 push 0                            ; default security descriptor is enough
 call CreateEventA

 mov dword ptr [EventO_Handle2],eax ; save the handle of the created event object

 push dword ptr [Thread_Handle]    ; push thread handle
 call ResumeThread                 ; resume the suspended thread


 mov esi,offset Encrypted_Thread_Block_End - 4
 mov edi,esi
 mov ecx,(offset Encrypted_Thread_Block_End - Encrypted_Thread_Block) / 4 
 mov edx,dword ptr [VALUE_THREAD]  ; get the initial state 
 mov dword ptr [SaveECX],ecx       ; save ECX initial state
 mov dword ptr [SaveEDX],edx       ; save the initial state of EDX

 std
Encrypt_Block1:
 lodsd
 mov dword ptr [Byte2Encrypt],eax  ; save the byte which needs to get encrypted

 pusha
 push dword ptr [EventO_Handle]    ; push event handle
 call SetEvent                     ; set event to signaled

 push 0FFFFFFFFh                   ; wait forever ;)
 push dword ptr [EventO_Handle2]   ; push the handle of the 2nd event
 call WaitForSingleObject          ; wait for thread to set this event to signaled
 push dword ptr [EventO_Handle2]   ; event handle is needed
 call ResetEvent                   ; set event to nonsignaled!$="$"
 popa

 mov eax,dword ptr [Byte2Encrypt]  ; get the encrypted dword
 stosd
 dec ecx
 mov dword ptr [SaveECX],ecx       ; save the current ECX value
 jnz Encrypt_Block1

 push dword ptr [Thread_Handle]    ; push the thread handle
 call SuspendThread                ; suspend the thread
 cld
 jmp Thread_Encryption_Finished

Thread_Handler:
Restart_Thread:
 pusha
 push 0FFFFFFFFh                   ; wait forever ;)
 push dword ptr [EventO_Handle]    ; event handle is needed
 call WaitForSingleObject          ; wait for the event to set signaled
 push dword ptr [EventO_Handle]    ; event handle is needed
 call ResetEvent                   ; set event to nonsignaled!$="$"

 mov edx,dword ptr [SaveEDX]       ; get the saved EDX value
 mov ecx,(offset Encrypted_Thread_Block - offset CRC_Block1) / 4

 mov esi,offset CRC_Block1
Generate_Thread_CRC:
 mov eax,[esi]
 xor edx,eax
 not edx
 xor edx,ecx
 add edx,eax
 add esi,4
 dec ecx
 jnz Generate_Thread_CRC

 mov eax,dword ptr [Byte2Encrypt]
 xor eax,edx

; xor eax,dword ptr [ENCVALUE]
 xor eax,0C11BD91Dh


 mov dword ptr [Byte2Encrypt],eax

 xor edx,dword ptr [SaveECX]
 mov dword ptr [SaveEDX],edx

 push dword ptr [EventO_Handle2]   ; push event handle
 call SetEvent                     ; set event to signaled
 popa
 jmp Restart_Thread

RIEHInc_End:

.Data
     Thread_ID dd 0 ; identifier of the created thread
 Thread_Handle dd 0 ; handle of the created thread
  Byte2Encrypt dd 0 ; holds the dword which needs to get encrypted
 EventO_Handle dd 0 ; holds the handle of the created event object
;EventO_Handle2 dd 0 ; holds the 2nd event handle
       SaveEDX dd 0 ; holds edx
       SaveECX dd 0 ; holds ecx

;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
; Some definitions (flags for openprocess and such stuff) (thnx to gromi hehe)
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ

PROCESS_SET_INFORMATION   equ 0200h
NORMAL_PRIORITY_CLASS     equ 00000020h
IDLE_PRIORITY_CLASS       equ 00000040h
HIGH_PRIORITY_CLASS       equ 00000080h
REALTIME_PRIORITY_CLASS   equ 00000100h
    THREAD_MAX_PRIORITY   equ 02h
       CREATE_SUSPENDED   equ 00000004h
          DEBUG_PROCESS   equ 00000001h
DEBUG_ONLY_THIS_PROCESS   equ 00000002h

Thread_Encryption_End:
