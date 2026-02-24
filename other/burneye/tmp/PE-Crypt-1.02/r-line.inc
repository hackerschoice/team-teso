
RunningLineEncryption:
 int 3
 push offset RunningLineHandler
 push dword ptr fs:[0]    
 mov dword ptr fs:[0],esp 

 push 100h
 push cs
 push offset EnableRunningLine
 iret
EnableRunningLine:
 nop
 nop
 nop
 nop
 pop dword ptr fs:[0]
 ret



RunningLineHandler:
 int 3
; mov ebp,esp
 mov eax,[esp+4]                     ; get the buffer to the exception_code
 mov esi,[eax]                       ; get the EXCEPTION CODE
 mov eax,[esp+10h - 4]               ; get the offset of another information buffer                
 mov esi,[eax+0B8h]                  ; get the EIP where the exception obcurred

 mov ecx,[eax+0C0h]
 or ch,1
 mov [eax+0C0h],ecx
 xor eax,eax
 ret



