;
;SectionData struct
;
;8 bytes maximal fuer den sectionsnamen
;1 dword fuer den rva
;1 dword fuer die virtual size
;1 dword fuer das offset auf der pladde 
;1 dword fuer die physical size
;1 dword fuer die flags
;==
;28
;
;ZERO DWORD TERMINATED
;
;SectionStates struct

;bpro section ein byte
;0=none
;1=encrypt
;2=compress

RSreadIncStart:

ReadSectionData proc
 pusha
 
 xor eax,eax
 push eax
 push eax
 push 3
 push eax
 push eax
 push 80000000h+40000000h
 push offset CryptFile
 call CreateFileA           ; Open file with read&write access
 cmp eax,-1
 jnz FileOpened
 WriteConsole2 <offset Error1>
 jmp FinishedWithReading

FileOpened:
 mov dword ptr [Fhandle],eax

 push offset HighOrderF
 push dword ptr [Fhandle]
 call GetFileSize
 or eax,eax
 jz No_PE_File2

 mov edx,offset DosHeader
 mov ecx,80
 call ReadFromFile

 cmp word ptr [DosHeader],"ZM"
 jz DosExecutable
 cmp word ptr [DosHeader],"MZ"
 jz DosExecutable
 jmp No_PE_File2

DosExecutable:
 push offset HighOrderF
 push dword ptr [Fhandle]
 call GetFileSize

 mov edx,dword ptr [DosHeader+3Ch]
 cmp edx,eax
 ja No_PE_File2

 call SeekFile
 mov edx,offset PEHeader
 mov ecx,4000
 call ReadFromFile
 cmp word ptr [PEHeader],"EP"
 jz PEFileForSure
No_PE_File2:
 WriteConsole2 <offset NotPE>
 push dword ptr [Fhandle]
 call CloseHandle
 jmp FinishedWithReading

PEFileForSure:
 cmp dword ptr [PEHeader+40],0
 jnz RvaAvailable
 WriteConsole2 <offset Baukasten37>
 push dword ptr [Fhandle]
 jmp FinishedWithReading


RvaAvailable:
 mov esi,offset PEHeader+248     ; pointer to the first obj
 movzx ecx,word ptr [PEHeader+6] ; get the number of objects
 mov edi,offset SectionData      ; points to sectiondata start
 mov edx,offset SectionStates    ; points to the section states buffa
CreateSectionBuffer:

 push esi
 push ecx
 push esi
 mov ecx,8                       ; section name is 8 bytes (maximum)
 rep movsb                       ; copy it to the sectiondata structure
 pop esi
 mov eax,[esi+12]                ; get the section rva
 stosd                           ; save it
 mov eax,[esi+8]                 ; get the virtual size
 stosd                           ; save it
 mov eax,[esi+20]                ; get the physical offset
 stosd                           ; save it
 mov eax,[esi+16]                ; get the physical size
 stosd                           ; save it
 mov eax,[esi+36]                ; get the section flags
 stosd                           ; save them

 push edi

 cmp dword ptr [esi+20],0        ; is the physical offset = 0
 jz WriteNoEncryptionByte        ; if yes, then don't encrypt / pack
 cmp dword ptr [esi+16],0        ; is the physical size = 0
 jz WriteNoEncryptionByte        ; if yes, then don't encrypt / pack

 push esi
 mov edi,offset TLS_String        ; pointer to the usual tls string
 mov ecx,4                        ; size of the string = 3 bytes (".tls")
 rep cmpsb                        ; compare th000se 2 strings
 pop esi
 jz WriteNoEncryptionByte

 mov eax,dword ptr [PEHeader+120] ; get the export rva
 mov ebx,dword ptr [esi+12]       ; get the current rva
 cmp eax,ebx
 jl NoExportForSure
 add ebx,dword ptr [esi+8]
 cmp eax,ebx
 jl WriteNoEncryptionByte        ; don't encrypt / pack this section!
NoExportForSure:

 push esi
 mov edi,offset DGROUP_String     ; pointer to the dgroup string
 mov ecx,7                        ; 7 bytes = size (".dgroup")
 rep cmpsb
 pop esi
 jz WriteNoEncryptionByte

 push esi
 mov edi,offset Icon_String
 mov ecx,5
 rep cmpsb
 pop esi
 jz WriteNoEncryptionByte

 mov eax,dword ptr [PEHeader+192] ; get tls section rva
 mov ebx,dword ptr [esi+12]       ; get the section rva
 cmp eax,ebx
 jl NoTlsForSure
 add ebx,[esi+8]                  ; get the section vsize
 cmp eax,ebx
 jl WriteNoEncryptionByte
NoTlsForSure:

 mov eax,dword ptr [PEHeader+120]
 cmp eax,dword ptr [esi+12]
 jz WriteNoEncryptionByte

 mov eax,dword ptr [PEHeader+136]   ; check if this obj is the resource obj
 cmp eax,dword ptr [esi+12]
 jz ResourceConfig

 mov eax,dword ptr [PEHeader+164]
 mov dword ptr [RELOCSIZE],eax    ; save the original size of the relocation section

 mov eax,dword ptr [PEHeader+160] ; get relocation section rva
 mov ebx,dword ptr [esi+12]       ; get the section rva
 cmp eax,ebx
 jl NoRelocationsForSure
 add ebx,[esi+8]                  ; get the section vsize
 cmp eax,ebx
 jl RelocationConfig
NoRelocationsForSure:

 test [esi+36],00010000000000000000000000000000b         ; check for the shared flag!
 jnz WriteNoEncryptionByte                            

 mov edi,edx
 cmp byte ptr [COMPRESSION],1
 jz PackingEnabled
 mov al,1
 jmp Finished_With_This_Section
PackingEnabled:
 mov al,2
 jmp Finished_With_This_Section

RelocationConfig:
 mov edi,edx
 cmp byte ptr [RELOCCOMP],1
 jz RelocationCompressionEnabled
 mov al,1
 jmp Finished_With_This_Section

RelocationCompressionEnabled:
 mov al,2
 jmp Finished_With_This_Section

ResourceConfig:
 mov edi,edx
 mov al,byte ptr [RESOURCECOMP]
 cmp al,2
 jnz ConvertCrap
 xor al,al
 jmp Finished_With_This_Section
ConvertCrap:
 cmp al,1
 jnz ConvertCrap2
 mov al,2
 jmp Finished_With_This_Section
ConvertCrap2:
 mov al,1
 jmp Finished_With_This_Section

WriteNoEncryptionByte:
 mov edi,edx
 xor al,al

Finished_With_This_Section:
 stosb
 inc edx
 pop edi

 pop ecx
 pop esi

 add esi,40                      ; points now to the next object
 dec ecx
 jnz CreateSectionBuffer

 xor eax,eax
 stosd

 push dword ptr [Fhandle]
 call CloseHandle

 popa
 ret
FinishedWithReading:
 popa
 pop eax
 jmp finish

ReadSectionData endp


RSreadIncEnd:
