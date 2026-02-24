;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
;                PECRYPT32 1.02 (c) in 1998 by random and killa  
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
;
;changes since final release of 1.02 :
; - added the new version of the apack library.
;
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�

Cryptor_Start:

 mov edi,offset IconPointers   ; points to the data stuff
 mov dword ptr [IconPointi],edi
 mov ecx,500
 xor eax,eax
 rep stosd

 mov word ptr [OBJnumber],0
 mov byte ptr [DontStore],1
 mov dword ptr [KILLASTINKT],ebp
 mov dword ptr [MONGOKILLA],esp

 mov al,byte ptr [KILLH]
 mov byte ptr [KILLHEAD],al
 mov al,byte ptr [HOOKFUNC]
 mov byte ptr [LOADEROPT],al

 mov al,byte ptr [ANTIBPX]
 mov byte ptr [ANTIBPXBPM],al

 mov al,byte ptr [IMPORTD]
 mov byte ptr [IMP_DESTROY],al
 mov byte ptr [I_MERGING],al

 mov al,byte ptr [ANTILOADER]
 mov byte ptr [ALOADER],al

 call Randomize
 mov dword ptr [Impenc],eax      ; random value for the new separate import encryption
 mov dword ptr [IMPENC2],eax     ; save it again
 call Randomize                  
 mov dword ptr [Impenc3],eax     ; random value for the new separate import encryption
 mov dword ptr [IMPENC4],eax     ; save it again
 call Randomize
 mov dword ptr [Patch_Crc1+1],eax ; patch another random value into the code
 call Randomize
 mov dword ptr [CRC32VALUE1],eax ; save the first CRC32 Value
 call Randomize
 mov dword ptr [CRC32VALUE2],eax ; save the second CRC32 Value
 call Randomize                  ; great random function,yeahh
 mov dword ptr [ENCRYPTV1],eax   ; random value for an encryption routine
 call Randomize                  ; great random function,yeahh
 mov dword ptr [ENCRYPTV2],eax   ; random value for an encryption routine

 mov al,byte ptr [ANTID]         ; get the antidebugging option
 mov byte ptr [AMETHOD],al       ; save it as internal decrypter variable

 mov al,byte ptr [VHEURISTIC]    ; get the heuristic option
 mov byte ptr [HEURISTIC],al     ; set the internal flag

 mov al,byte ptr [CRCM]          ; get the crc option
 mov byte ptr [CRCERROR],al      ; set the internal flag


; int 3
; mov esi,offset PEText
; mov ecx,(ToAdd_END - offset PEText)
; shr ecx,2
; xor eax,eax
;EncryptStuff:
; xor eax,[esi]
; not eax
; xor eax,ecx
; add esi,4
; dec ecx
; jnz EncryptStuff
;

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
 jnz FileFound

FilenotFound:
 WriteConsole2 <offset Error1>
 jmp End_OF_Crypt_Routine

FileFound:
 mov dword ptr [Fhandle],eax

 push 4
 push 1000h
 cmp byte ptr [PEText+88h],"r" ; tag verification 
 jz TagNotChanged
 push 200h
 jmp TagChanged
TagNotChanged:
 push 10000 ; nacher wieder aendern ;))
TagChanged:
 push 0
 call VirtualAlloc
 mov dword ptr [LayerBuffer],eax
 or eax,eax
 jnz NoAllocError
AllocError1:
 WriteConsole2 <offset a_error>
 jmp End_OF_Crypt_Routine

NoAllocError:

 push offset HighOrderF
 push dword ptr [Fhandle]
 call GetFileSize
 add eax,100000
 mov dword ptr [FileSize],eax  ; save the filesize
 mov dword ptr [FileSize2],eax ; save the filesize

 push 4
 push 1000h
 push 100000
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart5],eax
 or eax,eax
 jz AllocError1

 push 4
 push 1000h
 push dword ptr [FileSize]
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart4],eax
 or eax,eax
 jz AllocError1

 pusha
 push 4
 push 1000h
 push (ToAdd_END - offset CRC_Block1)
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart7],eax
 or eax,eax
 jz AllocError1

 mov ecx,(ToAdd_END - offset CRC_Block1)
 mov esi,offset CRC_Block1
 mov edi,dword ptr [MemStart7]
 rep movsb
 popa


 push 4
 push 1000h
 push 1000000
 push 0
 call VirtualAlloc
 mov dword ptr [TextBuffer],eax
 or eax,eax
 jz AllocError1

 push 4
 push 1000h
 push 1000000
 push 0
 call VirtualAlloc
 mov dword ptr [IconBuffer],eax
 or eax,eax
 jz AllocError1

 WriteConsole2 <offset MemAllocated>

 mov edx,offset DosHeader
 mov ecx,80
 call ReadFromFile

 WriteConsole2 <offset String1>

 mov eax,[FileSize]
 mov edx,dword ptr [DosHeader+3Ch]
 cmp edx,eax
 jl NoFileCorruptError
 WriteConsole2 <offset Baukasten35>
 Call Memory_DeAlloc
 jmp End_OF_Crypt_Routine

NoFileCorruptError:
 call SeekFile

 mov al,byte ptr [ARTOFRELOC]
 mov byte ptr [ARTOFRELOC1],al
 mov al,byte ptr [RESOURCECOMP]
 mov byte ptr [RCOMP],al

 mov edx,offset PEHeader
 mov ecx,4000
 call ReadFromFile

 cmp word ptr [PEHeader],"EP"
 jz PeFile
No_PE_File:
 mov byte ptr [NoWayassi],1
 WriteConsole2 <offset NotPE>
 Call Memory_DeAlloc
 jmp End_OF_Crypt_Routine

PeFile:

 xor edx,edx
 call SeekFile
 mov edx,offset DosHeader
 movzx eax,word ptr [DosHeader+2]
 movzx ecx,word ptr [DosHeader+4]
 shl ecx,9
 add ecx,eax
 call ReadFromFile

 mov edx,dword ptr [PEHeader+80] ; get the imagebase
 add edx,10000
 mov dword ptr [Phillipsuckt],edx

 push 4
 push 1000h
 push dword ptr [Phillipsuckt]
 push 0
 call VirtualAlloc
 add eax,10000
 mov dword ptr [MemStart],eax
 or eax,eax
 jz AllocError1

; cmp byte ptr [BACKUPMODE],0     ; are we allowed to generate a backup?
; jz DontCreateBackup             ; if no, then don't generate one
 mov esi,offset CryptFile
 mov edi,offset BackupFile
 mov ecx,128
Generate_Backup_File:
 lodsb
 cmp al,"."
 jz EndofFileName
 stosb
 dec ecx
 jnz Generate_Backup_File

EndofFileName:
 stosb
 mov al,"s"
 stosb
 mov ax,"va"
 stosw
 xor al,al
 stosb

 push 4
 push 1000h
 push dword ptr [FileSize]
 push 0
 call VirtualAlloc
 or eax,eax
 jz AllocError1
 mov dword ptr [RVA_NEW],eax    ; another memory buffer

 mov byte ptr [Dealloc],1

 xor edx,edx                    ; seek to the start of the file
 call SeekFile
 mov edx,dword ptr [RVA_NEW]    ; points to the reserved memory
 mov ecx,dword ptr [FileSize]   ; get the filesize
 sub ecx,100000                 ; subtract the fake crap
 call ReadFromFile              ; read the whole file into memory

 push 0
 push 80h
 push 02
 push 0
 push 03
 push 80000000h+40000000h
 push offset BackupFile
 call CreateFileA
 cmp eax,-1
 jnz BackupGenerated
 WriteConsole2 <offset Baukasten34>
 Call Memory_DeAlloc
 jmp End_OF_Crypt_Routine

BackupGenerated:
 mov dword ptr [Fhandle2],eax
 mov edx,dword ptr [RVA_NEW]    ; points to the reserved memory
 mov ecx,dword ptr [FileSize]   ; get the filesize
 sub ecx,100000                 ; subtract the fake crap
 push 0
 push offset Howmuch
 push ecx
 push edx
 push eax
 call WriteFile
 push dword ptr [Fhandle2]

 Push 2
 push dword ptr [FileSize]        ; push the filesize (amount of allocated mem)
 Push DWord Ptr [RVA_NEW]         ; push the linear offset
 Call VirtualFree                 ; free  it
 or eax,eax                       ; check for error
 jnz dealloc_error                ; jump on error

 mov byte ptr [Dealloc],0

 call CloseHandle
 WriteConsole2 <offset String0>

DontCreateBackup:


 pushad
 mov esi,offset PEHeader+248    ; pointer to the first obj
 movzx ecx,word ptr [PEHeader+6] ; get the number of objects

ParseAllVSizes:
 cmp dword ptr [esi+8],0
 jnz VirtualSizeOkay
 mov edx,[esi+12]
 mov eax,[esi+52]
 sub eax,edx
 jmp NewCalculated
VirtualSizeOkay:
 mov eax,[esi+8]
 jmp NotTheLastObject
NewCalculated:
 mov [esi+8],eax
 cmp ecx,1
 jnz NotTheLastObject
 mov eax,dword ptr [PEHeader+80]
 sub eax,[esi+12]
 mov [esi+8],eax
NotTheLastObject:
 movzx edi,word ptr [OBJnumber]
 shl edi,2
 add edi,offset VSizeTable
 stosd
 add esi,40
 inc word ptr [OBJnumber]
 dec ecx
 jnz ParseAllVSizes
 popad

 mov eax,40
 movsx ecx,word ptr [PEHeader+6] ; objcounter * objsize = lastobj
 mul ecx
 add eax,208
 mov dword ptr [LOBJ],eax        ; precalculate for the virus check ;)
 add eax,offset PEHeader ;+208
 mov esi,eax

 mov edi,offset LastOBJ
 mov ecx,40
 rep movsb

 push offset HighOrderF
 push dword ptr [Fhandle]
 call GetFileSize

 mov ebx,dword ptr [LastOBJ+16]
 add ebx,dword ptr [LastOBJ+20]

 cmp ebx,eax
 ja NoFuckingOverlay

 cmp ebx,eax
 jz NoFuckingOverlay
 sub eax,ebx
 mov dword ptr [OverlaySize],eax ; save the overlay size
 mov byte ptr [OverLay],1

 push 4
 push 1000h
 push eax
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart8],eax
 or eax,eax
 jz AllocError1

 mov edx,dword ptr [LastOBJ+16] ; get the physical size
 add edx,dword ptr [LastOBJ+20] ; get the physical offset
 call SeekFile
 mov ecx,dword ptr [OverlaySize]
 mov edx,dword ptr [MemStart8]
 call ReadFromFile

NoFuckingOverlay:


 mov ecx,dword ptr [PEHeader+84]   ; get the size of the headers
; sub ecx,dword ptr [DosHeader+3Ch] ; subtract the dos header
 mov edi,ecx                       ; points now to the end of the header file
 mov ebx,4000
 cmp edi,ebx
 ja NotNeeded
 sub ebx,edi
 add edi,offset PEHeader           ; points to the peheader in memory
 mov ecx,ebx
 xor al,al
 rep stosb

NotNeeded:
 movzx eax,byte ptr [PEHeader+6]   ; amount of object in this file
 mov ecx,40                        ; 40 bytes = size of every object in the header
 mul ecx                           
 add eax,208                       ; add the start of the first obj
 add eax,80                        ; add the size of 2 objects needed for pecrypt32

 mov ebx,dword ptr [PEHeader+84]   ; get the peheader size
 mov dword ptr [OldHSize],ebx      ; save the old size of the PE Header & Dos header
 sub ebx,dword ptr [DosHeader+3Ch] ; subtract the dos header size to get the PE header size

 cmp ebx,eax                       ; compare them both
 jae SpaceInTheHeader              ; is there any space in the header?
AlignHeaderAgain:
 mov ebx,dword ptr [PEHeader+84]   ; get the peheader size
 add ebx,dword ptr [PEHeader+60]   ; add the file alignment value
 mov dword ptr [PEHeader+84],ebx   ; write the new header value
 sub ebx,dword ptr [DosHeader+3Ch] ; subtract the PE header start
 cmp ebx,eax                       ; still not enough space?
 jl AlignHeaderAgain               ; if yes then align again till there is enough room
 mov byte ptr [NewAlign],1

SpaceInTheHeader:

 mov al,byte ptr [RELOCCOMP]     ; get the relocation compression value
 mov byte ptr [RELOCCOMPP],al    ; set the internal crypter flag

 cmp dword ptr [PEHeader+128],0  ; check if there are any imports
 jz NoImportsForSure             ; if not, don't execute this funny routine

 mov dword ptr [EsiBuffer],esi
 Push 2
 push dword ptr [FileSize]        ; push the filesize (amount of allocated mem)
 Push DWord Ptr [MemStart4]       ; push the linear offset
 Call VirtualFree                 ; free  it
 or eax,eax                       ; check for error
 jnz dealloc_error                ; jump on error

 push 4
 push 1000h                       ; alignment 4096 bytes
 push dword ptr [PEHeader + 80]   ; allocate memory for the file
 push 0                                 
 call VirtualAlloc                ; allocate it
 or eax,eax                       ; any error?
 jz AllocError1                   ; if yes, go to the error handler
 mov dword ptr [MemStart4],eax    ; new memstart4 linear offset

 mov esi,offset PEHeader+248      ; points to the first PE object
 movzx ecx,word ptr [PEHeader+6]  ; get the amount of objects in this file

Load_PE_Object:
 pusha

 pusha
 mov eax,dword ptr [PEHeader+128] ; get the import section rva
 mov edx,[esi+12]                 ; get the RVA
 cmp eax,edx                      ; compare import rva with current section rva
 jl NoImportSection               ; import rva smaller than the current section rva? if they then skip
 add edx,[esi+16]                 ; add the physical size
 cmp eax,edx                      ; compare them again
 jae NoImportSection              ; jump if bigger (no import section in this object)
 mov dword ptr [ImpCounti],ecx    ; save the current import section
NoImportSection:
 popa

 mov edx,[esi + 20]               ; get the physical offset
 or edx,edx                       ; physical offset == 0?
 jz DontRead                      ; if yes, then don't read
 call SeekFile                    ; seek to the physical offset
 mov edx,[esi+12]                 ; get the RVA

 add edx,dword ptr [MemStart4]    ; add the Memory Start
 mov ecx,[esi+16]                 ; add the physical size
 or ecx,ecx                       ; physical size == 0?
 jz DontRead                      ; if yes then don't read
 call ReadFromFile                ; read from file

DontRead:
 popa
 add esi,40                       ; go to the next object
 dec ecx
 jnz Load_PE_Object

 push dword ptr [Fhandle]
 call CloseHandle

 push 0
 push 80h
 push 02
 push 0
 push 03
 push 80000000h+40000000h
 push offset CryptFile
 call CreateFileA
 mov dword ptr [Fhandle],eax

 mov eax,dword ptr [TextBuffer]
 mov dword ptr [BufferPos],eax         ; save the position of the textbuffer

 mov esi,dword ptr [MemStart4]
 add esi,dword ptr [PEHeader+128]      ; add the import rva
NextMainImport_2:
 mov dword ptr [SAVEDLLRVA],190331

 push esi
 cmp dword ptr [esi+16],0              ; check for end of the imports
 jz FinishedWithImports_2              ; if end, jump

 cmp dword ptr [esi],0                 ; check for the 2nd import crap
 jnz FirstImportStandart_2             ; if not then jump
 mov edx,dword ptr [esi+12]            ; get the pointer to the dll name
 add edx,dword ptr [MemStart4]         ; add the start of the import section
 mov esi,dword ptr [esi+16]            ; get the thunk table offset
 add esi,dword ptr [MemStart4]         ; add the start of the import section
 mov edi,esi ; edi = esi = thunktable
 jmp SecondImportStandart_2

FirstImportStandart_2:
 mov edi,dword ptr [esi+16]
 add edi,dword ptr [MemStart4]    ; add the memory start
 mov edx,dword ptr [esi+12]
 add edx,dword ptr [MemStart4]    ; add the memorystart

 mov esi,dword ptr [esi]
 mov dword ptr [SAVEDLLRVA],esi   ; save the dll rva
 add esi,dword ptr [MemStart4]    ; add the fucking kewl memory start

SecondImportStandart_2:
ParseNextImport_2:
 lodsd
 or eax,eax
 jz MainImportFinished_2

 pusha
 mov edi,esi
 mov ecx,(offset MutateHookedApi - offset ContinueRelocationCompression) / 4
 mov esi,offset ContinueRelocationCompression
 mov edx,dword ptr [Impenc]
Generate_Lame_Checksum:
 lodsd
 xor eax,ecx
 add edx,eax
 not edx
 rol edx,cl
 dec ecx
 jnz Generate_Lame_Checksum
 mov dword ptr [Impenc],edx
 xor dword ptr [edi-4],edx
 popa

 test eax,80000000h
 jz Pointer2NameDir_2

 push esi
 push edx
 push ecx
 and eax,0FFFFh                   ; only 16bit are needed
 mov esi,offset OrdinalNumba+4    
 call Hex2DecimalString           ; converts the ordinal numbaa

 mov ecx,2
 mov eax,offset OrdinalNumba
Besuch:
 cmp byte ptr [eax],20h
 jnz Besuch2
 inc eax
 dec ecx
 jnz Besuch
Besuch2:
 pop ecx
 pop edx
 pop esi
 jmp OrdinalImport_2

Pointer2NameDir_2:
 add eax,dword ptr [MemStart4]    ; add the memory start
 inc eax
 inc eax

OrdinalImport_2:
 pusha

 push eax
 mov esi,edx
 mov edi,dword ptr [BufferPos]   ; get the buffer offset
CopyText2:
 lodsb
 or al,al
 jz DllnameEnd
 stosb
 dec ecx
 jnz CopyText2
DllnameEnd:
 mov al,":"                      ; looks like DLLNAME:FUNCTIONNAME ;)
 stosb
 pop eax
 mov ecx,20
 mov esi,eax
CopyText:
 lodsb                          
 or al,al
 jz FunctionNameEnd              ; every rocking function is null terminated
 stosb
 dec ecx
 jnz CopyText
FunctionNameEnd:

 pusha
 mov eax,edi
 sub eax,dword ptr [BufferPos]
 mov ecx,56
 sub ecx,eax
 mov al,20h
 rep stosb
 xor al,al
 stosb
 stosb
 mov dword ptr [BufferPos],edi    ; save the new position
 popa
 popa
jmp ParseNextImport_2
MainImportFinished_2:
 pop esi

 push eax
 push esi
 push edi

 mov edi,edx                      ; pointer to the dll name
 mov esi,edx                      ; another pointer to the dll name
 mov ecx,40
EncryptDllName:
 lodsb
 or al,al
 jz DllNameFinished
 
 push esi
 push ecx
 push edi
 push eax
 mov ecx,(offset MutateHookedApi - offset ContinueRelocationCompression) / 4
 mov esi,offset ContinueRelocationCompression
 mov edx,dword ptr [Impenc3]
Generate_Lame_Checksum_1:
 lodsd
 xor eax,ecx
 add edx,eax
 not edx
 rol edx,cl
 dec ecx
 jnz Generate_Lame_Checksum_1
 mov dword ptr [Impenc3],edx
 pop eax
 pop edi
 pop ecx
 pop esi
 xor al,dl
 stosb
 dec ecx
 jnz EncryptDllName

DllNameFinished:
 pop edi
 pop esi
 pop eax

 add esi,20
CompareAgain:
 mov eax,dword ptr [SAVEDLLRVA]   ; get the last pointer to the named table
 cmp eax,[esi]                    ; compare it with the current one
 jnz NextMainImport_2_2_2         ; difference? then everything is okay
 add esi,20                       ; add 20 bytes to get to the next entry
 Jmp CompareAgain                 ; compare again

NextMainImport_2_2_2:
 pusha
 mov eax,40
 sub eax,ecx
 mov edi,offset DLLNAMESL
 movzx ebx,byte ptr [NAMECOUNTI]
 add edi,ebx
 stosb
 popa
 inc byte ptr [NAMECOUNTI]
 jmp NextMainImport_2

FinishedWithImports_2:
 mov byte ptr [NAMECOUNTI],0
 pop esi

 mov edx,dword ptr [MemStart4]    ; get the PE file base address (imagebase)
 add edx,dword ptr [PEHeader+40]  ; add the rva
 cmp dword ptr [edx+0Bh],"!DNR"   ; check for the pecrypt32 signature
 jnz NotPecrypted

 cmp byte ptr [IMPORTD],1
 jnz DisableAPIHooking

 push 30h
 push offset Baukasten36
 push offset Baukasten38
 push 0
 call MessageBoxA
 mov byte ptr [IMP_DESTROY],0
 mov byte ptr [I_MERGING],0
 mov byte ptr [IMPORTD],0

 cmp byte ptr [HOOKFUNC],0        ; is the api hooking enabled?
 jz NotPecrypted                  ; if yes check for pecrypt32 'protected' filez
 jmp NotPecrypted

DisableAPIHooking:
 cmp byte ptr [HOOKFUNC],0        ; is the api hooking enabled?
 jz NotPecrypted                  ; if yes check for pecrypt32 'protected' filez
 push 30h
 push offset Baukasten36
 push offset Baukasten362
 push 0
 call MessageBoxA
 mov byte ptr [HOOKFUNC],0        ; disable the api hooking
 mov byte ptr [LOADEROPT],0       ; disable that crap, LALALA

NotPecrypted:
 xor edx,edx
 call SeekFile
 mov edx,offset DosHeader
 movzx eax,word ptr [DosHeader+2]
 movzx ecx,word ptr [DosHeader+4]
 shl ecx,9
 add ecx,eax
 call WritetoFile

 cmp byte ptr [NewAlign],1        ; do we need to align the complete file?
 jnz NoNewAlign_Needed            ; NAH? k, the pass that crap :)
 mov edx,dword ptr [DosHeader+3Ch] ; seek to the peheader start
 call SeekFile                    ; the PEFile (header start)
 mov edx,offset PEHeader          ; point to the header buffer
 mov ecx,dword ptr [PEHeader+84]  ; get the whole header size (dos&peheader together)
 sub ecx,dword ptr [DosHeader+3Ch] ; subtract the pe header start
 call WritetoFile                 ; write the header
 mov ebx,dword ptr [PEHeader+84]  ; get the new header size
 sub ebx,dword ptr [OldHSize]     ; subtract the old one to get the difference for alignment
 mov dword ptr [OldHSize],ebx     ; save the difference

NoNewAlign_Needed:

 mov esi,offset PEHeader+248      ; points to the first PE object
 movzx ecx,word ptr [PEHeader+6]  ; get the amount of objects in this file

Resave_PE_FILE:
 pusha

 mov edx,[esi+12]                 ; get the section rva
 cmp byte ptr [I_MERGING],0
 jz NoImport_Merging
 cmp dword ptr [esi+16],0
 jnz ImportMergingPossible
 mov byte ptr [I_MERGING],0
 push 30h
 push offset Baukasten36
 push offset Baukasten372
 push 0
 call MessageBoxA
 jmp NoImport_Merging
ImportMergingPossible:
 cmp edx,dword ptr [PEHeader+128] ; compare it with the import rva
 jnz NoImport_Merging             ; different? then no import merging
 pusha
 
 push ecx
 mov edx,[esi-40 + 20]            ; get the physical offset of the last section
 call SeekFile                    ; seek to the physical offset
 pop ecx

 pusha
 mov eax,[esi+12]
 mov edx,[esi-40+8]
 add edx,[esi-40+12]
 mov dword ptr [BUFFIRVA],edx
 sub eax,edx
 mov dword ptr [BUFFISIZE],eax
 popa

 mov eax,[esi+8]                  ; get the virtual size of the current object
 add eax,[esi+12]                 ; add the rva
 sub eax,[esi-40+12]              ; subtract the rva of the last section
 mov ecx,dword ptr [PEHeader+56]  ; use the section aligment for the rva
 xor edx,edx                      ; calculation
 div ecx                                
 or edx,edx
 jz NoPhysicalSize_Rest_Value
 inc eax
NoPhysicalSize_Rest_Value:
 mul ecx
 mov [esi-40+16],eax              ; write the new physical size :]
 mov [esi-40+8],eax              ; write the new physical size :]

 mov edx,[esi - 40 +12]           ; get the RVA
 add edx,dword ptr [MemStart4]    ; add the Memory Start
 mov ecx,eax                      ; get the virtual size (= physical size)
 call WritetoFile                 ; write the whole object!

 mov edi,[esi+40 + 20]
 mov edx,[esi-40 + 20]            ; get the physical offset of the last section
 add edx,[esi-40 + 16]            ; add the physical size
 sub edx,edi
 mov dword ptr [SaveTmp],edx      ; save the reminder

 mov word ptr [OBJnumber],0
 mov esi,offset PEHeader+248    ; pointer to the first obj
 movzx ecx,word ptr [PEHeader+6] ; get the number of objects
 dec ecx

ParseAll_VSizes:
 cmp dword ptr [esi+8],0
 jnz Virtual_SizeOkay
 mov edx,[esi+12]
 mov eax,[esi+52]
 sub eax,edx
 jmp New_Calculated
Virtual_SizeOkay:
 mov eax,[esi+8]
 jmp Not_TheLastObject
New_Calculated:
 mov [esi+8],eax
 cmp ecx,1
 jnz Not_TheLastObject
 mov eax,dword ptr [PEHeader+80]
 sub eax,[esi+12]
 mov [esi+8],eax
Not_TheLastObject:
 movzx edi,word ptr [OBJnumber]
 shl edi,2
 add edi,offset VSizeTable
 stosd
 add esi,40
 inc word ptr [OBJnumber]
 dec ecx
 jnz ParseAll_VSizes

 mov esi,offset PEHeader+248      ; points to the first PE object
 movzx ecx,word ptr [PEHeader+6]  ; get the amount of objects in this file
 mov edi,esi
ParsePEheader:
 mov edx,[esi+12]                 ; get the section rva
 cmp edx,dword ptr [PEHeader+128] ; compare it with the import rva
 jnz Dont_Erase_Object            ; don't erase that one if thats not the import object
 add esi,40
 dec word ptr [PEHeader+6]
 jmp DontCopyThisTime

Dont_Erase_Object:
 push ecx
 mov ecx,40
 rep movsb
 pop ecx
DontCopyThisTime:
 dec ecx
 jnz ParsePEheader
 mov ecx,40
 xor al,al
 rep stosb
 popa
 popa
 jmp Merging_finished

NoImport_Merging:
 mov edx,[esi + 20]               ; get the physical offset
 or edx,edx                       ; physical offset == 0?
 jz DontRead_2                    ; if yes, then don't write
 cmp byte ptr [NewAlign],1
 jnz DontAlignThatStuff
 add edx,dword ptr [OldHSize]     ; add the difference
 mov [esi + 20],edx               ; resave the physical offset
DontAlignThatStuff:
 mov edx,[esi+20]                 ; get it
 add edx,dword ptr [SaveTmp]      ; add the reminder
 mov [esi+20],edx                 ; resave it
 call SeekFile                    ; seek to the physical offset
 mov edx,[esi+12]                 ; get the RVA
 add edx,dword ptr [MemStart4]    ; add the Memory Start
 mov ecx,[esi+16]                 ; add the physical size
 or ecx,ecx                       ; physical size == 0?
 jz DontRead_2                    ; if yes then don't write
 call WritetoFile                 ; write the whole object!
DontRead_2:
 popa
 add esi,40                       ; go to the next object
Merging_finished:
 dec ecx
 jnz Resave_PE_FILE

 mov edx,dword ptr [DosHeader+3Ch] ; seek to the peheader start
 call SeekFile                    ; the PEFile (header start)
 mov edx,offset PEHeader          ; point to the header buffer
 mov ecx,dword ptr [PEHeader+84]  ; get the whole header size (dos&peheader together)
 sub ecx,dword ptr [DosHeader+3Ch] ; subtract the dos header size to get the PE header sizeeee
 call WritetoFile                 ; write the header
NoNewAlign_Needed_2:

 Push 2
 push dword ptr [PEHeader+80]     ; push the filesize (amount of allocated mem)
 Push DWord Ptr [MemStart4]       ; push the linear offset
 Call VirtualFree                 ; free  it
 or eax,eax                       ; check for error
 jnz dealloc_error                ; jump on error

 push 4
 push 1000h
 push dword ptr [FileSize2]
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart4],eax
 or eax,eax
 jz AllocError1
 mov esi,dword ptr [EsiBuffer]    ; restore esi

NoImportsForSure:
 movzx esi,word ptr [PEHeader+20]
 add esi,offset PEHeader+18h
 mov edi,offset CODEOBJ
 mov ecx,40
 rep movsb

 mov ax,word ptr [PEHeader+16h]    ; get the file characteristics
 test ax,2000h
 jz NoDllFile
 mov byte ptr [EXEFLAGS],1        ; mark this file as a DLL!

NoDllFile:
 mov eax,dword ptr [PEHeader+40]  ; get the rva
 mov dword ptr [RIGHTONE],eax     ; save it        

 mov eax,dword ptr [CODEOBJ+12] ; get the code rva
 mov dword ptr [CODEBASE],eax   ; save it

 mov eax,dword ptr [CODEOBJ+16] ; get the physical size
 mov dword ptr [CODESIZE],eax   ; save it for later use in the loader

 mov eax,40
 movsx ecx,word ptr [PEHeader+6] ; objcounter * objsize = lastobj
 mul ecx
 add eax,208
 mov dword ptr [LOBJ],eax        ; precalculate for the virus check ;)
 add eax,offset PEHeader ;+208
 mov esi,eax

 mov eax,[esi+8]                 ; get the virtual size of the last obj
 mov dword ptr [LSIZE],eax       ; save it for the heuristic virus check

 mov dword ptr [NewOBJPos],esi   ; save the position of the last obj
 add dword ptr [NewOBJPos],40    ; pointer to the new obj

 push esi
 mov edi,offset DData
 mov ecx,6
 rep cmpsb
 pop esi
 jnz NotDInfo
 sub [NewOBJPos],40
 mov byte ptr [CUTDINFO],1
 sub esi,40
 dec word ptr [PEHeader+6]

NotDInfo:
 push esi
 mov edi,offset LastOBJ
 mov ecx,40
 rep movsb
 pop esi
fickenlan:
 mov byte ptr [AddNew],1
 mov byte ptr [RESEND],1

 push eax
 mov eax,dword ptr [esi+12]
 mov dword ptr [OFSVALUE],eax
 mov eax,dword ptr [esi+8]
 mov dword ptr [OFSVSIZE],eax
 pop eax

 mov eax,dword ptr [LastOBJ+12]
 add eax,dword ptr [LastOBJ+16]

 mov ecx,dword ptr [PEHeader+40]
 mov dword ptr [RVA],eax
 mov dword ptr [PEHeader+40],eax

 mov eax,dword ptr [LastOBJ+16]
 add eax,dword ptr [LastOBJ+20]
 mov dword ptr [PhysicalO],eax

 mov esi,offset PEHeader+248
 mov edi,offset OBJTABLE
 mov dword ptr [TempVar],edi
 mov word ptr [OBJnumber],0

Parseobj:
 mov dword ptr [NewPhysS],0 ; set to zero

 cmp byte ptr [KILLH],0     ; killheader option enabled?
 jz NoNeedtoKillTheHeader
 pusha
 mov edi,esi
 mov esi,offset NewOBJ
 mov ecx,8
 rep movsb
 popa
NoNeedtoKillTheHeader:
 mov eax,[esi+12]    ; get the current rva
 mov dword ptr [CurrentRVA],eax

 mov eax,[esi+8]     ; get the current virtualsize
 mov dword ptr [CurrentVSIZE],eax

 mov eax,[esi+36]    ; get the flags of this object
 mov dword ptr [CurrentFLAGS],eax 

 mov eax,[esi+16]    ; save old physicalsize
 mov dword ptr [CurrentPhysS],eax

 call DisplayCounter ; displays the obj number and some other crap

 mov eax,[esi+36]               ; get the objflags
 or eax,80000000h
 mov [esi+36],eax

Cryptyes:
 mov edx,dword ptr [esi+20]
 mov dword ptr [SavePosition],edx
 sub edx,dword ptr [Csize]
 mov dword ptr [esi+20],edx
 mov dword ptr [LastOBJPos],esi

 push eax

 push eax
 mov eax,dword ptr [PEHeader+136]   ; check if this obj is the resource obj
 cmp eax,dword ptr [esi+12]
 pop eax
 jz EncryptResources                ; if yes encrypt resources    

 mov eax,dword ptr [PEHeader+160] ; get relocation rva
 mov ebx,dword ptr [esi+12]       ; get the section rva
 cmp eax,ebx
 jl NoRelocationsFor_Sure
 add ebx,[esi+8]                  ; get the section vsize
 cmp eax,ebx
 jl CheckForRelocations
NoRelocationsFor_Sure:

 movzx eax,word ptr [OBJnumber]   ; get the current obj number
 add eax,offset SectionStates     ; add the lame section state buffer
 cmp byte ptr [eax],0
 jz MoveObject

 cmp byte ptr [eax],0
 jnz Compressit

MoveObject:
 cmp dword ptr [esi+20],0        ; is the physical offset = 0
 jz ObjectGotIgnored
 cmp dword ptr [esi+16],0        ; is the physical size = 0
 jz ObjectGotIgnored

 push esi
 mov edx,dword ptr [SavePosition]
 call SeekFile

 mov edx,dword ptr [MemStart]
 mov ecx,dword ptr [esi+16]
 call ReadFromFile

 mov edx,dword ptr [esi+20]
 call SeekFile

 mov ecx,dword ptr [esi+16]
 mov edx,dword ptr [MemStart]   ; write the encrypted obj into the file
 call WritetoFile

 pop esi
ObjectGotIgnored:
 WriteConsole2 <offset Baukasten27>
 mov byte ptr [ResourceInde],1  ; don't display the lame object statistics
 jmp Dontcrypt

Compressit:
 mov edi,dword ptr [TempVar]
 mov eax,dword ptr [esi+12]     ; get the objoffset (rva)
 mov dword ptr [TempVar2],eax   ; save the rva
 stosd                          ; store it in a table
 mov eax,dword ptr [esi+16]     ; get the objlength 
 stosd                          ; store it in the objtable of pecrypt32

 call Randomize                 ; great random function,yeahh
 stosd                          ; save the random encryption value in the table

 mov dword ptr [CRYPTVAR1],eax  ; save it for encrypting

 movzx ecx,word ptr [OBJnumber]  
 shl ecx,2
 mov eax,[ecx+offset VSizeTable]
 stosd                          ; save the virtual size in the objecttable
 xor eax,eax
 stosb                          ; save it
 stosd                          ; zero the crc value
 stosd                          ; zero the not aligned realsize of this obj
 mov eax,[esi+16]               ; get the original physical size
 stosd                          ; save it
 mov eax,[esi+36]               ; get the flags of this section
 stosd                          ; save them
 mov dword ptr [TempVar],edi
 mov byte ptr [LazyNess],1

 mov edx,dword ptr [SavePosition]
 call SeekFile                  ; seek to the pos

 mov edi,dword ptr [MemStart]
 mov ecx,dword ptr [esi+16]
 shr ecx,2
 xor eax,eax
 rep stosd

 mov ecx,dword ptr [esi+16]     ; get the obj length for reading
 mov edx,dword ptr [MemStart]   ; start of the allocated memory
 mov dword ptr [RealSize],ecx   ; save the realsize
 push ecx
 call ReadFromFile              ; read the obj into the allocated mem
 pop ecx

CompressRelocs:
 push ecx
 push esi
 push edi

 mov esi,dword ptr [MemStart]
 mov dword ptr [MemStart2],esi
 mov edi,esi

CompressionON:
 movzx eax,word ptr [OBJnumber]   ; get the current obj number
 add eax,offset SectionStates     ; add the lame section state buffer
 cmp byte ptr [eax],1             ; encryption for this section?
 jz EncryptByte                   ; if yes, start with encryption
 
 mov dword ptr [CompressBytes],ecx
 mov dword ptr [OrigSize],ecx
 mov dword ptr [InfoSize],ecx

CompressThem:


 pusha
 push 4
 push 1000h
 push 1024*1024
 push 0
 call VirtualAlloc
 mov dword ptr [WorkMemory],eax
 or eax,eax
 jz AllocError1
 popa


 push ebx
 push esi
 push edi

 mov dword ptr [SaveEESP],esp


 mov eax,dword ptr [MemStart]   ; points to the source data
 mov edx,dword ptr [MemStart4]  ; points to the destination data
 mov ebx,ecx                    ; size of this data (physical size)
 
 cmp byte ptr [RCompress],1     ; check for running resource compression
 jz NoLameTextNeeded            ; don't display the 'processing' text if resource packing
                                ; is running


 cmp byte ptr [RelocCCC],1      ; check for relocation compression
 jz NoCallBackNeeded            ; if running then skip this crap
 WriteConsole2 <offset Spaces>
NoLameTextNeeded:
 push offset PackingInfo
 push dword ptr [WorkMemory]    ; push the workmem
 push ebx                       ; push the size
 push edx                       ; push destination
 push eax                       ; push source data
 jmp callbackjuhuuu

NoCallBackNeeded:
 push 0                         ; no callback needed
 push dword ptr [WorkMemory]    ; push the workmem
 push ebx                       ; push the size
 push edx                       ; push destination
 push eax                       ; push source data

callbackjuhuuu:
 call _aP_pack         
 add esp, 5*4         


 mov esp,dword ptr [SaveEESP]
 mov ecx,eax
 pop edi
 pop esi
 pop ebx

 mov dword ptr [CCounter],ecx

 mov edi,dword ptr [MemStart]
 mov esi,dword ptr [MemStart4]
 rep movsb

 push 2
 push 1024*1024
 push dword ptr [WorkMemory]
 Call VirtualFree                 ; free  it
 or eax,eax                       ; check for error
 jnz dealloc_error                ; jump on error


 cmp byte ptr [RelocCCC],1      ; check for running relocation compression
 jz RelocCRunning               ; jump if running 
 cmp byte ptr [RCompress],1     ; check for resource packing
 jz RelocCRunning               ; skip display routine if running
 WriteConsole2 <offset ReturnChars> ; display return chars
RelocCRunning:

 cmp byte ptr [RCompress],1     ; check for running resource compression
 jnz ResourceCRunning               ; jump if running 
 WriteConsole2 <offset Baukasten17>
ResourceCRunning:

 cmp byte ptr [RelocCCC],1
 mov byte ptr [RelocCCC],0     ; disable the relocation compression flag
 jz ContinueRelocationPacking  ; continue the relocation packing

 mov eax,dword ptr [MemStart2] ; get the memory start
 mov dword ptr [MemStart],eax  ; restore it
 jmp weida

PackingInfo:
 pusha
 mov ebx,100
 imul ebx
 mov ebx,dword ptr [InfoSize]
 xor edx,edx
 div ebx
 pusha
 call SendMessageA, [hPrgrs], WM_USER+2, eax, 0 ;PBM_SETPOS
 call UpdateWindow, [hMain]
blabla:
 popa
 popa
 db 0C3h
weida:
 pop edi
 pop esi
 pop ecx

 mov edx,dword ptr [esi+20]     ; seek to the obj start
NotCResources:
 call SeekFile

 mov eax,dword ptr [CCounter]
 add eax,dword ptr [DirSize]

 mov dword ptr [RealSize],eax   ; save the new physical size

 mov ecx,dword ptr [PEHeader+60]           ; get the value we need for alignment
 xor edx,edx
 div ecx
 or edx,edx
 jz No__RestiValue
 inc eax
No__RestiValue:
 mul ecx

 push dword ptr [esi+16]
 mov dword ptr [esi+16],eax

 mov dword ptr [OBJVSIZE],eax
 mov ecx,dword ptr [OrigSize]
 mov dword ptr [NewPhysS],eax   ; save new physicalsize
 cmp eax,ecx
 jae NoCompress

 mov edx,ecx
 sub edx,eax
 cmp edx,1024
 jl NoCompress

 mov dword ptr [RESOURCESIZ],eax
 push eax
 mov eax,[esi+8]
 mov dword ptr [RESOURCEVSIZ],eax
 pop eax

 cmp byte ptr [RCompress],1
 jz PassThisCrap

 mov edi,dword ptr [TempVar]
 mov byte ptr [edi-17],1
 sub edi,29
 stosd

PassThisCrap:
 push eax
 sub ecx,eax
 add dword ptr [Csize],ecx

 mov dword ptr [CCounter],0
 mov dword ptr [CompressCounter],0
 mov dword ptr [CompressBytes],0
 mov dword ptr [HowMany],0
 pop ecx
 pop edx

 jmp Compressed
NoCompress:
 mov dword ptr [DirSize],0

 pop dword ptr [esi+16]

 mov edx,dword ptr [MemStart2]
 mov dword ptr [MemStart],edx

 mov dword ptr [CCounter],0
 mov dword ptr [CompressCounter],0
 mov dword ptr [CompressBytes],0
 mov dword ptr [HowMany],0

 mov edx,dword ptr [SavePosition]
 call SeekFile                  ; seek to the pos

 mov ecx,dword ptr [esi+16]     ; get the obj length for reading
 mov edx,dword ptr [MemStart]   ; start of the allocated memory
 push ecx
 call ReadFromFile              ; read the obj into the allocated mem
 pop ecx
 push ecx
 push esi
 push edi
 mov esi,dword ptr [MemStart]
 mov edi,esi
 cmp byte ptr [RCompress],1    ; is the current section a resource section?
 jz EncryptResources           ; if yes, then use the special method :)
 jmp EncryptByte

Compressed:
 mov edx,dword ptr [MemStart2]
 mov dword ptr [MemStart],edx

 mov byte ptr [RCompress],0
 mov dword ptr [DirSize],0

NoCompressedResources:
 call WritetoFile
 jmp lalala

EncryptByte:
 shr ecx,1                        ; divide size by 2 (word encryption)
@NoTlsEntry:
 lodsw
 xor ax,cx
 not ax
 xor eax,dword ptr [CRYPTVAR1]
 ror ax,cl
 inc dword ptr [CRYPTVAR1]
 stosw
 inc dword ptr [TempVar2]
 dec ecx
 jnz @NoTlsEntry

ImportFound:
 pop edi
 pop esi
 pop ecx
 push ecx

 mov edx,dword ptr [esi+20]     ; seek to the obj start
 call SeekFile
 pop ecx
 mov edx,dword ptr [MemStart]   ; write the encrypted obj into the file
 call WritetoFile
 jmp lalala
Dontcrypt:
lalala:
 inc word ptr [OBJnumber]
 add esi,40
 mov ax,word ptr [PEHeader+6]

 cmp byte ptr [ResourceInde],1
 jz NoStatistic
 call DisplayStatistic ; display statistic 
NoStatistic:
 mov byte ptr [ResourceInde],0

 cmp byte ptr [LazyNess],0
 jz DontEncryptOBJTable

 pushad
 mov esi,dword ptr [MemStart]
 mov edi,dword ptr [TempVar]
 mov ecx,dword ptr [RealSize]   ; get the real size of this object
 mov [edi-12],ecx
 shr ecx,2
 xor edx,edx
 xor ebx,ebx
CalculateOBJ_CRC:
 lodsd
 xor edx,eax
 rol edx,cl
 shl edx,cl
 add edx,ebx
 mov ebx,eax
 dec ecx
 jnz CalculateOBJ_CRC
 mov edi,dword ptr [TempVar]
 mov [edi-16],eax                ; save the crc value in the objecttable
 popad

 pushad
 mov esi,dword ptr [TempVar]
 sub esi,33                     ; pointer to the first entry
 mov ecx,33                     ; size of all entries = 21 bytes
 xor eax,eax
 mov edx,dword ptr [ENCRYPTV1]
CalculateOBJCRC:
 lodsb                         ; get a byte 
 xor eax,ecx                   ; and calculate a simple checksum
 rol eax,cl                    ; which will be later used 
 add eax,edx                   ; to encrypt the next objecttable :)
 xor edx,eax
 xor edx,dword ptr [ENCRYPTV1]
 inc edx                       ; cause i don't want that some lAmErZ
 dec ecx                       ; change it, tralalaaaa 
 jnz CalculateOBJCRC

 push esi
 mov esi,offset ToAdd         ; pointer to the loaderstart
 mov ecx,offset CodeCRC_End - offset ToAdd
 mov edx,dword ptr [ENCRYPTV2]
CaculateCODECRC:
 mov dl,[esi]
 add eax,edx
 rol eax,cl
 xor eax,ecx
 xor eax,dword ptr [ENCRYPTV1]
 inc esi
 dec ecx
 jnz CaculateCODECRC
 pop esi

 mov edx,eax
 mov esi,offset PEText
 mov ecx,(offset ToAdd_END - offset PEText)
ChecksumText:
 lodsb
 add edx,eax
 rol edx,cl
 xor edx,ecx
 dec ecx
 jnz ChecksumText

 mov eax,edx
 pushad
 mov esi,dword ptr [TempVar]
 sub esi,33                   ; pointer to the last object
 mov edx,dword ptr [PreviousCRC] ; get the previous crc
 mov edi,esi
 mov ecx,33                   ; size = 21 bytes
EncryptOBJTable:
 lodsb
 xor eax,edx
 inc edx
 stosb
 dec ecx
 jnz EncryptOBJTable
 popad
 mov dword ptr [PreviousCRC],eax 
 popad

DontEncryptOBJTable:
 mov byte ptr [LazyNess],0

 cmp word ptr [OBJnumber],ax
 jae allobjsdone
 jmp Parseobj

CheckForRelocations:

 mov eax,[esi+36]
 and eax,0EFFFFFFFh
 mov [esi+36],eax

 pushad
 mov esi,offset ResDecryptionFinished
 mov ecx,(offset NoTracerRunning - offset ResDecryptionFinished)
 call Randomize
 mov dword ptr [ENCRYPTV3],eax
 mov edx,eax
 push edx
 call Randomize
 mov dword ptr [ENCRYPTV4],eax
 pop edx
 mov edi,eax
 xor eax,eax
 shr ecx,2
Calculate_RCRC:
 lodsd
 add edx,eax
 xor edx,ecx
 xor edi,eax
 rol edi,cl
 dec ecx
 jnz Calculate_RCRC
 xor edx,edi
 mov dword ptr [ENCRYPTV5],edx
 popad

 mov eax,[esi+16]                ;get the virtual size of the relocations
 mov dword ptr [RELOCVSIZE],eax  ;save them

 mov eax,dword ptr [esi+12]     ; get the relocation base :)
 mov dword ptr [RELOCBASE],eax  ; save it

 mov edx,dword ptr [SavePosition]
 call SeekFile                  ; seek to the pos of the .reloc obj

 pushad
 cmp byte ptr [INFOMODE],0
 jnz DontDisplaythiscrap
 WriteConsole2 <offset ReturnChars>
DontDisplaythiscrap:
 WriteConsole2 <offset Baukasten18>
 WriteConsole2 <offset Baukasten19>
 popad

 push esi
 mov ecx,dword ptr [PEHeader+164]      ; get the .reloc length for reading
 mov dword ptr [RelocLength],ecx ; save the lengh of the reloc obj
 mov dword ptr [RELOCLENG],ecx   ; save it lalalalaa
 push ecx
 mov ecx,dword ptr [esi+16]
 mov edx,dword ptr [MemStart]   ; start of the allocated memory
 call ReadFromFile              ; read the whole .reloc obj
 pop ecx

 mov edi,dword ptr [MemStart]   ; get the allocated memory
 add edi,dword ptr [PEHeader+160] ; add the relocation rva
 sub edi,[esi+12]                 ; subtract the section rva

 cmp dword ptr [edi],0          ; already protected with pecrypt32
 jnz  @Only12bitencryption      ; don't encrypt again
 mov byte ptr [LOADRELOC],0
 jmp Finishedrelocs
@Only12bitencryption:
 cmp byte ptr [RELOCCOMP],1     ; check for relocation compression
 jz CompressRelocations         ; if enabled, jump

 call Randomize                 ; great random function,yeahh

 cmp byte ptr [ARTOFRELOC1],1    ; check the type of relocation encryption
 jz Startwithrelocations
 pushad
 WriteConsole2 <offset Baukasten21>

 popad
 and ax,0FFFh                   ; only 12bit cryptvalues are allowed!
 jmp GrosseTitten
Startwithrelocations:
 WriteConsole2 <offset Baukasten20>

GrosseTitten:
 mov word ptr [CryptValue1],ax  ; save it
 mov word ptr [CRYPTVALUE2],ax

 xor ebx,ebx
 mov esi,dword ptr [MemStart]   ; esi=offset of the allocated memory
 mov eax,[esi]
 mov dword ptr [SAVEFIRSTRB],eax
 mov dword ptr [esi],0

Continuewithreloc:
 mov ecx,dword ptr [esi+4]
 sub ecx,8
 shr ecx,1                      ; divide the length by 2
 add ebx,8                      ; (cause every reloc is a word)
 add esi,8                      ; increase the pointer
                                ; points now to the first relocation in this
                                ; block.
 mov edi,esi
EncryptReloc:
 add ebx,2
 lodsw                          ; get the relocation
 cmp byte ptr [ARTOFRELOC1],1   ; 16 bit relocation encryption?
 jz Reloc16bit                  ; yeah? then jump
 and ax,0FFFh                   ; cut off the fucking relocation type
 jmp DontEncryptfr

Reloc16bit:
 not ax
 rol ax,cl
 xor ax,cx
DontEncryptfr:
 xor ax,word ptr [CryptValue1]
 xor ax,word ptr [ENCRYPTV5]
 stosw                          ; push it again
loop EncryptReloc
 cmp ebx,dword ptr [RelocLength] ;finished with the reloc obj?
 jnz Continuewithreloc           ; not? then do the next reloc block

Finishedrelocs: ; finished with relocations
 pop esi
 mov edx,dword ptr [esi+20]     ; seek to the obj start
 call SeekFile

 mov ecx,dword ptr [esi+16]
 mov edx,dword ptr [MemStart]     ; write the encrypted obj into the file
 call WritetoFile

 pushad
 WriteConsole2 <offset Baukasten22>
 popad
 mov byte ptr [ResourceInde],1
 jmp Dontcrypt
CompressRelocations:
 pushad
 WriteConsole2 <offset Baukasten25>
 popad
 mov esi,dword ptr [MemStart]   ; esi=offset of the allocated memory
 include r-relocc.inc               ; call the relocation compression
 mov byte ptr [ResourceInde],1
 pushad
 WriteConsole2 <offset Baukasten22>
 popad
 jmp Dontcrypt

Dontcrypt2:
 push esi
 mov edx,dword ptr [SavePosition]
 call SeekFile

 mov edx,dword ptr [MemStart]
 mov ecx,dword ptr [esi+16]
 call ReadFromFile

 mov edx,dword ptr [esi+20]
 call SeekFile

 mov ecx,dword ptr [esi+16]
 mov edx,dword ptr [MemStart]   ; write the encrypted obj into the file
 call WritetoFile

 pop esi
 jmp Dontcrypt

EncryptResources:

 cmp byte ptr [RCOMP],2            ; is the resource processing switched off?
 jz Dontcrypt2                     ; if yes then don't encrypt / pack
 cmp dword ptr [PEHeader+136],0
 jz Dontcrypt

 mov byte ptr [ResourceInde],1

 mov esi,dword ptr [LastOBJPos]
 push esi

 cmp byte ptr [RCompress],0       ; was there any previous compression try?
 jz NoPreviousCompression         ; if no, don't jump
 mov byte ptr [RESOURCECOMP],0    ; no resource compression anymore
 mov byte ptr [RCOMP],0
 mov byte ptr [AddNew],0
 mov byte ptr [RESEND],0
 mov byte ptr [PatchRrva],0       ; don't update the icon rvas

NoPreviousCompression:
 mov eax,dword ptr [PEHeader+136]
 mov dword ptr [RESOURCEOFS],eax

 mov byte ptr [RCompress],0
 mov edx,dword ptr [SavePosition]
 call SeekFile                  ; seek to the pos

 mov ecx,dword ptr [esi+16]     ; get the obj length for reading
 mov edx,dword ptr [MemStart]   ; start of the allocated memory
 call ReadFromFile              ; read the obj into the allocated mem
 Call Randomize
 xchg ebx,eax
 mov dword ptr [RESOURCE_ENCRYPT],ebx

 mov eax,[esi+8]
 mov dword ptr [RESOURCESIZ],eax

 Call DisplayResourceInformation

 cmp byte ptr [RESOURCECOMP],1
 jz CompressResources
 push esi

 mov esi,dword ptr [MemStart]
 mov ebp,esi
 mov edi,dword ptr [RESOURCEOFS]
 mov edx,ebp
 mov ebx,offset ToAdd
 mov byte ptr [DURCHGANG],1
 call ParseSubDirectory

EncryptionFinished2:
 mov byte ptr [DURCHGANG],0
 pushad
 WriteConsole2 <offset Baukasten17>
 popad
 pop esi

 mov edx,dword ptr [esi+20]     ; seek to the obj start
 call SeekFile
 mov edx,dword ptr [MemStart]   ; write the encrypted obj into the file
 mov ecx,dword ptr [esi+16]      ; get the obj length for writing
 call WritetoFile
 jmp Dontcrypt

CompressResources:
 push esi
 mov ebp,dword ptr [MemStart]
 mov esi,ebp
 mov edi,dword ptr [MemStart5]
 call ReadSubdirectory
 jmp DetermineDirectoryEnd

ReadSubdirectory Proc
 push edx
 movzx ecx,word ptr [esi+14] ; get the number of ID entries (root directory)
 movzx edx,word ptr [esi+12]   ; get number of named entries (root directory)
 add ecx,edx
 pop edx
ReadSubdirectory_2:
 push ecx
 add esi,16                  ; Image Resource Directory Format = 16 bytes
 push esi
 mov dword ptr [NumberofDirs],ecx ; save the number of subdirectories
ScanNext:
 cmp dword ptr [NumberofDirs],0
 jz ContinueDirParsing_restore_pointers

; cmp byte ptr [CheckIcon],4
; jz ScanForIconID
 cmp byte ptr [CheckIcon],1  ; check if the group icon scanning is enabled
 jz GroupIconScanning          
 cmp byte ptr [CheckIcon],2  ; check if the icon scanning is enabled
 jz NormalIconScanning
 cmp byte ptr [CheckIcon],6
 jz VersionInfoScanning

ContinueDirParsing:
 mov eax,dword ptr [esi+4]   ; get data or directory offset
                             ; (directory if 800000000h is set)
 and eax,7FFFFFFFh           ; pointer contains of 31 bit 
 test dword ptr [esi+4],80000000h   ; test for directory / raw data structure
 jnz SubDirectoryFound       ; jump if set (subdirectory)
 jmp RawStructureFound       ; Raw data structure found

SubDirectoryFound:
 mov esi,ebp                  ; get the memory offset
 add esi,eax                  ; add the pointer to the sub directory
 call ReadSubdirectory
 pop esi
 pop ecx
 sub esi,8
 or ecx,ecx
 jz Retit
 cmp byte ptr [CheckIcon],5
 jnz NoNormalScanningEnabled
 cmp ecx,1
 jz FinishedwithParsing
 

NoNormalScanningEnabled:
 dec ecx
 jnz ReadSubdirectory_2
Retit:
 ret
 jmp ReadSubdirectory

ContinueDirParsing_restore_pointers:
 cmp byte ptr [CheckIcon],6  ; is the version scanning finished?
 jnz NoVersionScanning
 cmp byte ptr [esi],10h
 jz VersionInformationFound
 mov byte ptr [CheckIcon],0
 jmp VersionScanningFinished

NoVersionScanning:
 cmp byte ptr [CheckIcon],2  ; check if the icon scanning is enabled
 jz NormalIconScanningNotEnabled
 cmp byte ptr [esi],03h
 jz NormalIconFound2
 mov byte ptr [CheckIcon],0
NormalIconScanningNotEnabled:
 cmp byte ptr [CheckIcon],1  ; check if the group icon scanning is enabled
 jnz GroupScanNotEnabled
 cmp byte ptr [esi],0Eh
 jz GroupIconFound
 mov byte ptr [CheckIcon],0
GroupScanNotEnabled:
VersionScanningFinished:

 pop esi
 push esi
 jmp ContinueDirParsing

VersionInfoScanning:
 cmp byte ptr [esi],10h
 jz VersionInformationFound
 add esi,8
 dec dword ptr [NumberofDirs]
 jmp ScanNext

GroupIconScanning:
 cmp byte ptr [esi],0Eh
 jz GroupIconFound
 add esi,8
 dec dword ptr [NumberofDirs]
 jmp ScanNext

NormalIconScanning:
 cmp byte ptr [esi],03h
 jz NormalIconFound2
 add esi,8
 dec dword ptr [NumberofDirs]
 jmp ScanNext

NormalIconFound2:
 mov byte ptr [CheckIcon],5
 mov byte ptr [IconResult],1
 jmp ContinueDirParsing

GroupIconFound:
 mov byte ptr [IconResult],1
 mov byte ptr [CheckIcon],3
 jmp ContinueDirParsing

VersionInformationFound:
 mov byte ptr [CheckVInfo],1
 mov byte ptr [CheckIcon],3
 jmp ContinueDirParsing

ScanForIconID:
 mov eax,dword ptr [IconID]
 cmp [esi],eax
 jz ContinueDirParsing2
 add esi,8
 jmp ScanNext

ContinueDirParsing2:
 mov byte ptr [CheckIcon],5
 jmp ScanNext

RawStructureFound:
 add eax,ebp
 xchg esi,eax
 mov eax,[esi]               ; get the raw data offset

 cmp byte ptr [CheckVInfo],1
 jz VersionInfoFound
 cmp byte ptr [CheckIcon],3
 jz Group_Icon_Found

 cmp byte ptr [CheckIcon],5
 jnz DontScanForNormalIcon

 push edx
 mov edx,dword ptr [RESOURCESIZ]   ; get the virtual size of the resources
 add edx,dword ptr [RESOURCEOFS]   ; add the resource rva     
 cmp eax,edx
 pop edx
 ja DontScanForNormalIcon

 push eax
 sub eax,[RESOURCEOFS]
 add eax,ebp
 
 cmp byte ptr [eax],28h
 pop eax
 jz Normal_Icon_Found
 jmp DontScanForNormalIcon

DontScanForNormalIcon:
; cmp byte ptr [CheckIcon],5
; jz Normal_Icon_Found

 cmp byte ptr [DontStore],0
 jz DontStoreOffsets
 mov dword ptr [OfsAmount],eax
 stosd                       ; store the raw data offset into the buffer
DontStoreOffsets:
 pop esi
 pop ecx
 ret
ReadSubdirectory endp

DetermineDirectoryEnd:
 mov eax,dword ptr [OfsAmount]

 mov ecx,edi                     ; get the current buffer position
 sub ecx,dword ptr [MemStart5]   ; subtract the buffer start to get the size
 shr ecx,2                       ; divide it by 4
 mov dword ptr [OfsAmount],ecx   ; store it
 mov esi,dword ptr [MemStart5]   ; get the offset buffer start

 mov eax,[esi]
 mov dword ptr [PosResult],eax ; save this as the result if only one resource entry exists

GetTheNextOffset:
 push ecx
 push esi

 mov eax,[esi]               ; get the next offset out of the buffer

 mov dword ptr [OfsPos],esi  ; save the current buffer position

 mov esi,dword ptr [MemStart5]   ; pointer to the buffer start for every offset
 mov ecx,dword ptr [OfsAmount]   ; get the amount of all offsets in the buffer
 cmp ecx,1
 jz DontContinueScanning
CompareOffsets:
 cmp esi,dword ptr [OfsPos]      ; compare the current pos with the offset pos
 jz DontAdd                      ; if equal then don't add
 cmp eax,[esi]               ; compare the offset with another offset
 jae DontAdd                 ; only add the small offsets
 inc dword ptr [OfsResult]   ; increase the offset counter
DontAdd:
 add esi,4                   ; set pointer to the next offset
 dec ecx
 jnz CompareOffsets

 mov ebx,dword ptr [OfsResult]     ; get the amount of offsets
 cmp ebx,dword ptr [EndResult]     ; compare it with the end result
 jle DontAddAnew                   ; dont add a new one if the result amount is smaller
 mov dword ptr [EndResult],ebx     ; save the new end result
 mov dword ptr [PosResult],eax     ; save the end offset

DontAddAnew:
 mov dword ptr [OfsResult],0       ; zero the offset counter

 pop esi
 add esi,4                         ; make it point to the next entry
 pop ecx
 dec ecx
 jnz GetTheNextOffset
 jmp ScanningSuccessful

DontContinueScanning:
 pop esi
 pop ecx

ScanningSuccessful:
 mov esi,dword ptr [MemStart]
 mov edi,dword ptr [PosResult]
 add edi,esi
 sub edi,dword ptr [RESOURCEOFS]
 mov dword ptr [MemStart],edi

 mov eax,[edi] ; get the first dword after the resource directory
 mov dword ptr [RESOURCEBYT],eax

 sub edi,esi
 pop esi
 mov dword ptr [DirSize],edi
 mov dword ptr [DIRSIZE],edi
 mov ecx,[esi+16]
 mov dword ptr [OrigSize],ecx
 sub ecx,edi
 mov dword ptr [InfoSize],ecx
 mov dword ptr [CompressBytes],ecx

 push ecx
 push esi
 push edi
 mov esi,dword ptr [MemStart]
 mov edi,esi
 mov byte ptr [RCompress],1
 mov byte ptr [IconResult],0
 mov byte ptr [DontStore],0
 Call CheckForIcons
 jmp CompressThem

DamnCrap:
 mov byte ptr [RCompress],1
 jmp EncryptResources

CheckForIcons Proc
 pushad
 mov dword ptr [SaveTemp2],esp


 mov byte ptr [CheckIcon],1      ; set the internal variable true
 mov esi,dword ptr [MemStart2]    ; points to the funny resources
 mov ebp,esi
 call ReadSubdirectory           ; read it

ScanningFinished:
 mov esp,dword ptr [SaveTemp2]
 popad
 ret

Group_Icon_Found:
 mov edx,dword ptr [MemStart2]

 mov eax,dword ptr [esi]   ; get the offset of this entry
 mov ecx,dword ptr [esi+4] ; get the length of this resource entry
 sub eax,dword ptr [RESOURCEOFS]
 add eax,edx

 pushad
 mov eax,[esi]                     ; get the rva of the first icon
 mov edx,dword ptr [RESOURCESIZ]   ; get the virtual size of the resources
 add edx,dword ptr [RESOURCEOFS]   ; add the resource rva     
 cmp eax,edx                       ; range checking
 popad
 ja ScanningFinished

 push eax
 mov eax,dword ptr [IconSize]
 mov [esi],eax
 pop eax

 pushad
 sub esi,dword ptr [MemStart2]      ; calculate some crap
 mov dword ptr [IconPointers],esi
 add dword ptr [IconPointi],4
; mov dword ptr [SPointer1],esi      ; save it
 mov edx,dword ptr [SavePosition]   ; get the old filepos
 sub edx,dword ptr [Csize]          ; subtract the packed bytes
 mov dword ptr [NewRPos],edx        ; save the new resource pos
 popad

 mov esi,eax
 mov edi,dword ptr [IconBuffer]     ; points to the reserved icon buffer
 add edi,dword ptr [IconSize]
 push edi
 add dword ptr [IconSize],ecx

CopyGroupIcon:
 lodsb
 mov byte ptr [esi-1],0
 stosb
 dec ecx
 jnz CopyGroupIcon
 pop esi

 mov byte ptr [CheckIcon],2      ; set the internal variable for the icon scanning
 mov esi,dword ptr [MemStart2]   ; points to the funny resources
 mov ebp,esi

 call ReadSubdirectory           ; read it
 jmp FinishedwithParsing

Normal_Icon_Found:
 mov edx,ebp

 mov eax,dword ptr [esi]   ; get the offset of this entry
 mov ecx,dword ptr [esi+4] ; get the length of this resource entry
 sub eax,dword ptr [RESOURCEOFS]
 add eax,edx

 pushad
 mov eax,[esi]                     ; get the rva of the first icon
 mov edx,dword ptr [RESOURCESIZ]   ; get the virtual size of the resources
 add edx,dword ptr [RESOURCEOFS]   ; add the resource rva     
 cmp eax,edx                       ; range checking
 popad
 ja DontStoreOffsets

 push eax
 mov eax,dword ptr [IconSize]
 mov [esi],eax
 pop eax

 pushad
 sub esi,dword ptr [MemStart2]
 mov edi,dword ptr [IconPointi]
 mov dword ptr [edi],esi
 add edi,4
 mov dword ptr [IconPointi],edi
; mov dword ptr [SPointer2],esi
 popad

 mov esi,eax
 push esi
 mov edi,dword ptr [IconBuffer] ; points to the allocated memory for the iconcrap
 add edi,dword ptr [IconSize]
 add dword ptr [IconSize],ecx

CopyNormalIcon:
 lodsb
 mov byte ptr [esi-1],0
 stosb
 dec ecx
 jnz CopyNormalIcon
 pop esi
 jmp DontStoreOffsets

FinishedwithParsing:

 mov byte ptr [CheckIcon],6      ; Enable the version information scanning
 mov esi,dword ptr [MemStart2]   ; points to the funny resources
 mov ebp,esi
 call ReadSubdirectory           ; read it
 mov byte ptr [CheckVInfo],0
 jmp NoVersionInfoInthisFile

VersionInfoFound:
 mov byte ptr [CheckVInfo],1

 mov eax,dword ptr [esi]   ; get the offset of this entry
 mov ecx,dword ptr [esi+4] ; get the length of this resource entry
 sub eax,dword ptr [RESOURCEOFS]
 add eax,edx

 pushad
 mov eax,[esi]                     ; get the rva of the first icon
 mov edx,dword ptr [RESOURCESIZ]   ; get the virtual size of the resources
 add edx,dword ptr [RESOURCEOFS]   ; add the resource rva     
 cmp eax,edx                       ; range checking
 popad
 ja ScanningFinished

 push eax
 mov eax,dword ptr [IconSize]
 mov [esi],eax
 pop eax

 pushad
 sub esi,dword ptr [MemStart2]
 mov dword ptr [SPointer3],esi
 popad

 mov esi,eax
 push esi
 mov edi,dword ptr [IconBuffer] ; points to the allocated memory for the iconcrap
 add edi,dword ptr [IconSize]
 add dword ptr [IconSize],ecx
CopyVersionInfo:
 lodsb
 mov byte ptr [esi-1],0
 stosb
 dec ecx
 jnz CopyVersionInfo

 pop esi
 pop ecx
 pop esi
NoVersionInfoInthisFile:
 mov byte ptr [PatchRrva],1 ; set flag for later rva patching
 jmp ScanningFinished

CheckForIcons endp

allobjsdone:

 mov dword ptr [PEHeader+80],0             ; zero the imagesize value
 sub esi,40

 movsx ecx,word ptr [PEHeader+6]  ; get the number of objects
 dec ecx
 mov eax,40                       ; in the pefile..and multiply them by
 mul ecx                          ; 40 (length of an obj block)
 add eax,offset PEHeader+248
 mov esi,eax

 mov eax,[esi+8]                  ; get virtualsize of the last obj
 add eax,[esi+12]                 ; add rva of the last object

 mov ecx,dword ptr [PEHeader+56]  ; use the section aligment for the rva
 xor edx,edx                      ; calculation
 div ecx                                
 or edx,edx
 jz NoRvaRestValue
 inc eax
NoRvaRestValue:
 mul ecx
 mov [RVA_NEW],eax                ; write the new rva into my ruling object

 mov eax,[esi+20]                 ; get the physical offset of the last object
 add eax,[esi+16]                 ; add the physical size = new offset of my object
 mov [Offset_NEW],eax             ; save the new physical offset

 mov eax,(Offset ToAdd_END - Offset ToAdd) ; size of the whole PECRYPT32 loader
 mov ecx,dword ptr [PEHeader+56]           ; get the value we need for alignment
 xor edx,edx
 div ecx
 or edx,edx
 jz NoRestValue
 inc eax
NoRestValue:
 mul ecx
 mov dword ptr [VirtualS_NEW],eax          ; save new virtual size

 mov eax,(Offset ToAdd_END - Offset ToAdd) ; size of the whole PECRYPT32 loader
 mov ecx,dword ptr [PEHeader+60]           ; get the value we need for alignment
 xor edx,edx
 div ecx
 or edx,edx
 jz NoRestiValue
 inc eax
NoRestiValue:
 mul ecx
 mov dword ptr [Physical_NEW],eax          ; save it as new physicalsize
chabojackson:
 add eax,dword ptr [Offset_NEW]            ; add the physical offset of this object
 mov [PhysOffset],eax                      ; save it as the new offset for the icon object

 mov eax,dword ptr [RVA_NEW]               ; get the new calculated rva
 add eax,dword ptr [VirtualS_NEW]          ; add the virtual size
 mov [Rva_NEW],eax                         ; save it as the RVA for the new icon object

 cmp dword ptr [IconSize],0                ; no icons / version info in the resources?
 jz No_Icon_VersionInfo

 mov eax,dword ptr [IconSize]              ; get the iconsize
 push eax
 mov ecx,dword ptr [PEHeader+56]           ; get the value we need for alignment
 xor edx,edx
 div ecx
 or edx,edx
 jz No_Rest_Value
 inc eax
No_Rest_Value:
 mul ecx
 add dword ptr [PEHeader+80],eax           ; add the '.icon' section vsize to the imagesize
 mov dword ptr [VSize_New],eax             ; save it as new vsize for the .icon object

 pop eax
 mov ecx,dword ptr [PEHeader+60]           ; use the file alignment to align
 xor edx,edx
 div ecx
 or edx,edx
 jz No__Rest_Value
 inc eax
No__Rest_Value:
 mul ecx
 mov dword ptr [PhysSize_New],eax          ; save it also as the new physical size

No_Icon_VersionInfo:
 mov eax,dword ptr [RVA_NEW]               ; get the new calculated rva
 mov dword ptr [PEHeader+40],eax           ; save it in the PEHEADER

 add dword ptr [Dllrva],eax                ; prepare the dll field
 add dword ptr [ThunkRva],eax              ; prepare the thunkarray
 add dword ptr [Thunktable],eax
 add dword ptr [Thunktable+4],eax

 cmp byte ptr [PEText+91h],"k" ; tag verification
 jz Tag_NotChanged
 xor eax,666h

Tag_NotChanged:
 add dword ptr [Thunktable+8],eax

 mov dword ptr [PEHeader+168],0 ; kill the debuginfo
 mov dword ptr [PEHeader+172],0

 mov dword ptr [PEHeader+208],0
 mov dword ptr [PEHeader+212],0

 mov dword ptr [PEHeader+216],0
 mov dword ptr [PEHeader+220],0

 push eax
 mov eax,dword ptr [PEHeader+128]
 mov dword ptr [IMPORTOFS],eax ; save the rva
 pop eax

 
 push eax
 add eax,offset NamehOffset - offset ToAdd
 mov dword ptr [PEHeader+128],eax          ; save the import table rva
 mov dword ptr [PEHeader+132],offset ImportEnd - offset NamehOffset
 pop eax
 mov dword ptr [NEWIBASE],eax ; save it as new imagebase

 add eax,dword ptr [VirtualS_NEW] ; add the virtual size of the new object
 add dword ptr [PEHeader+80],eax  ; write the new imagesize

 pusha
 movsx ecx,word ptr [PEHeader+6]  ; get the number of objects
 mov eax,40                       ; in the pefile..and multiply them by
 mul ecx                          ; 40 (length of an obj block)
 add eax,offset PEHeader+248
 inc word ptr [PEHeader+6]
 mov edi,eax
 mov esi,offset NewOBJ
 mov ecx,40
 rep movsb
 cmp byte ptr [CheckVInfo],1 ; do we need a new object for the version stuff?
 jz WriteNewObject           ; if yes then write one
 cmp byte ptr [PatchRrva],0  ; do we need a new icon object?
 jz NoIconObjectNeeded
WriteNewObject:
 mov esi,offset NewOBJ2
 mov ecx,40
 rep movsb
 inc word ptr [PEHeader+6]
NoIconObjectNeeded:
 popa

 mov eax,dword ptr [PEHeader+52]
 mov dword ptr [IMAGEBASE],eax
 cmp byte ptr [LOADEROPT],0   ; api hooking enabled?
 jz MenuCrapFinished          ; if no , then jump
 mov DialogAPI,0
 call MenuStart
MenuCrapFinished:
 cmp byte ptr [ANTIBPX],0
 jz AntiBpxStuffDisabled

 mov DialogAPI,1
 lea esi,FunctionT
 lea edi,TempBuffer
 mov ecx,500
 rep movsd

 call MenuStart
 lea esi,FunctionT
 lea edi,FunctionT2
 mov ecx,500
 rep movsd

 lea esi,TempBuffer
 lea edi,FunctionT
 mov ecx,500
 rep movsd

AntiBpxStuffDisabled:

;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
;Encryption routine for the first antidebugging layer
;
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�

 cmp byte ptr [COMPATIBLE],0
 jz TlsSupportEnabled
 mov dword ptr [PEHeader+192],0
 mov dword ptr [PEHeader+196],0


TlsSupportEnabled:
 mov dword ptr [PreviousCRC],0 ; zero previouscrc (will be used lAtA lAmErz)
 mov ax,word ptr [PEHeader+6]
 mov word ptr [OBJNUMBA],ax

 mov edi,offset LayerTable      ; memory to fill the layers in
 mov esi,offset Layer_Table_End ; memory to encrypt/decrypt
 mov ecx,(offset REALCODE_CRC_END - offset EncryptLayer3_End)
 jmp SlowMte_Start

EncryptionFinished:

 mov edi,offset output_data
 mov esi,offset LayerTable
 mov ecx,1000 / 4
 rep movsd
 mov edi,offset LayerTable
 mov ecx,1000 / 4
 mov eax,90909090h
 rep stosd

 cmp byte ptr [ANTID],0
 jz NoFuckingAntidebugging

 call Randomize
 mov dword ptr [VALUE4],eax
 mov dword ptr [BLASEN2],eax

 call Randomize
 mov dword ptr [VALUE3],eax
 mov dword ptr [BLASEN],eax

 call Randomize
 mov dword ptr [ENCRYPTV11],eax
 mov edx,eax

 mov esi,offset InCPL3
 mov edi,esi
 mov ecx,(offset EncryptedLayer_4_Start - offset InCPL3) / 4

Encrypt_AD_Block:
 push esi
 push ecx
 mov ecx,offset (offset InCPL3 - offset NoHeuristicAlert) / 4
 mov esi,offset NoHeuristicAlert

GenerateAD_CRC:
 mov eax,[esi]
 xor edx,eax
 xor edx,ecx
 add esi,4
 dec ecx
 jnz GenerateAD_CRC
 pop ecx
 pop esi
 lodsd
 xor eax,edx
 stosd
 inc dword ptr [VALUE3]
 xor edx,dword ptr [VALUE4] ; simple xor but effective ;)
 xor edx,ecx
 dec ecx
 jnz Encrypt_AD_Block

 mov eax,dword ptr [BLASEN]
 mov dword ptr [VALUE3],eax
 mov eax,dword ptr [BLASEN2]
 mov dword ptr [VALUE4],eax

 call Randomize
 mov dword ptr [VALUE5],eax
 mov dword ptr [BLASEN2],eax

 call Randomize
 mov dword ptr [VALUE6],eax
 mov dword ptr [BLASEN],eax

 mov edx,eax
 mov esi,offset CPL0_NOT_ACTIVE
 mov edi,esi
 mov ecx,(offset InCPL3 - offset CPL0_NOT_ACTIVE) / 4
Encrypt_First_Antidebugging_Layer:
 push esi
 push ecx
 mov ecx,(offset EncryptedAntiDebuggingLayer_1_End - offset HeuristicPassed) / 4
 mov esi,offset HeuristicPassed
Generate_CRC_overFirst_Antidebugging_Layer_2:
 mov eax,[esi]
 xor edx,eax
 xor edx,ecx
 add esi,4
 dec ecx
 jnz Generate_CRC_overFirst_Antidebugging_Layer_2
 pop ecx
 pop esi
 rol edx,cl
 rol dword ptr [VALUE6],cl
 xor dword ptr [VALUE5],ecx
 lodsd
 xor eax,edx
 stosd
 inc dword ptr [VALUE5]
 xor dword ptr [VALUE6],ecx
 xor edx,ecx
 dec ecx
 jnz Encrypt_First_Antidebugging_Layer

 mov eax,dword ptr [BLASEN2]
 mov dword ptr [VALUE5],eax

 mov eax,dword ptr [BLASEN]
 mov dword ptr [VALUE6],eax

NoFuckingAntidebugging:
 mov esi,offset output_data
 mov edi,offset LayerTable
 mov ecx,1000 / 4
 rep movsd

 call Randomize
 mov dword ptr [SaveMCRC],eax
 mov dword ptr [MutateCRC1],eax

 call Randomize
 mov dword ptr [SaveMCRC+4],eax
 mov dword ptr [MutateCRC2],eax

 call Randomize
 mov dword ptr [START_VALUE],eax
 mov edx,eax                    

 mov esi,offset Encrypted_Block1_End-1
 mov edi,esi
 mov ecx,(offset Encrypted_Block1_End - offset Encrypted_Block1) / 4
 std    
Decrypt_Block11:
 push esi
 push ecx
 mov ecx,offset (CRC_Block1_End - offset CRC_Block1) / 4
 mov esi,offset CRC_Block1
GenerateFirst_CRC1:
 mov eax,[esi]
 xor edx,eax
 xor edx,ecx
 add esi,4
 dec ecx
 jnz GenerateFirst_CRC1
 pop ecx
 pop esi
 lodsd
 xor eax,edx
 stosd
 inc dword ptr [MutateCRC2]
 rol dword ptr [MutateCRC1],cl
 xor edx,ecx
 dec ecx
 jnz Decrypt_Block11


 cld
 mov eax,dword ptr [SaveMCRC]
 mov dword ptr [MutateCRC1],eax

 mov eax,dword ptr [SaveMCRC+4]
 mov dword ptr [MutateCRC2],eax

 call Randomize
 mov dword ptr [VALUE_THREAD],eax

 cmp byte ptr [EXEFLAGS],1
 jz Thread_Encryption_Finished
 jmp Thread_Encryption_Start

Thread_Encryption_Finished:
 
 mov edx,dword ptr [Offset_NEW]
 add edx,dword ptr [Physical_NEW]
 add edx,dword ptr [PhysSize_New]

 push 4
 push 1000h
 push edx
 push 0
 call VirtualAlloc
 mov dword ptr [MemStart6],eax

 xor ecx,ecx
 mov edx,dword ptr [Offset_NEW]
 call SeekFile
                                   
 mov edx,offset ToAdd
 mov ecx,dword ptr [Physical_NEW]
 call WritetoFile
  
 mov edx,dword ptr [DosHeader+3Ch]
 call SeekFile

 movsx ecx,word ptr [PEHeader+6]  ; get the number of objects
 mov eax,40                       ; in the pefile..and multiply them by
 mul ecx                          ; 40 (length of an obj block)
 add eax,248
 mov edx,offset PEHeader
 mov ecx,eax
 call WritetoFile                 ; write all obj and the peheader to the file

 xor edx,edx
 call SeekFile

 mov edx,dword ptr [MemStart6]
 mov ecx,dword ptr [Offset_NEW]
 add ecx,dword ptr [Physical_NEW]
 add ecx,dword ptr [PhysSize_New]
 Call ReadFromFile

 push dword ptr [Fhandle]
 call CloseHandle

 cmp byte ptr [CheckVInfo],0
 jz DontPatchVersionRVA
 pusha
 mov edx,dword ptr [MemStart6]
 add edx,dword ptr [NewRPos]
 mov eax,dword ptr [Rva_NEW]   ; rva of the new resource object
 add edx,dword ptr [SPointer3]
 add [edx],eax
 popa

DontPatchVersionRVA:

 cmp byte ptr [PatchRrva],0    ; is the internal flag set?
 jz Dont_patchrvas             ; no? then don't patch
 pusha
 mov edx,dword ptr [MemStart6]
 add edx,dword ptr [NewRPos]
 push edx
 mov eax,dword ptr [Rva_NEW]   ; rva of the new resource object


 mov esi,offset IconPointers   ; points to the data stuff
ContinuePatchingRVAS:
 cmp dword ptr [esi],0
 jz FinishedWithPatchingRvas

 mov edi,edx
 add edi,[esi]
 add [edi],eax
 add esi,4
 jmp ContinuePatchingRVAS

FinishedWithPatchingRvas:
 popa
Dont_patchrvas:

 push 0
 push 80h
 push 02
 push 0
 push 03
 push 80000000h+40000000h
 push offset CryptFile
 call CreateFileA
 mov dword ptr [Fhandle],eax

 mov edx,dword ptr [MemStart6]
 mov ecx,dword ptr [PhysicalO]
 add ecx,dword ptr [Physical_NEW]
 sub ecx,dword ptr [Csize]
 call WritetoFile

 mov edx,dword ptr [IconBuffer]
 mov ecx,dword ptr [PhysSize_New]
 call WritetoFile

 cmp dword ptr [OverlaySize],0
 jz NoDamnOverlay
 mov edx,dword ptr [MemStart8]
 mov ecx,dword ptr [OverlaySize]
 call WritetoFile
NoDamnOverlay:
 push dword ptr [Fhandle]
 call CloseHandle

 mov edx,dword ptr [Offset_NEW]
 add edx,dword ptr [Physical_NEW]
 add edx,dword ptr [PhysSize_New]
 Push 2
 push edx
 Push DWord Ptr [MemStart6]
 Call VirtualFree
 or eax,eax
 jne dealloc_error

 cmp byte ptr [OverLay],0
 jz NoFuckingOverLay
 WriteConsole2 <offset OverLayEr>

NoFuckingOverLay:
 cmp byte ptr [CUTDINFO],0
 jz NoCuttedDebugInfo
 WriteConsole2 <offset Baukasten23>

NoCuttedDebugInfo:
 cmp byte ptr [COMPATIBLE],1
 jz NoTLSInformationFound
 cmp dword ptr [PEHeader+192],0
 jz NoTLSInformationFound
 WriteConsole2 <offset Baukasten32>


NoTLSInformationFound:

 mov esi,dword ptr [MemStart7]
 mov ecx,(ToAdd_END - offset CRC_Block1)
 mov edi,offset CRC_Block1
 rep movsb

 mov edi,offset Fhandle
 mov ecx,(offset FICK - offset Fhandle)
 xor al,al
 rep stosb

 Call Memory_DeAlloc
 jmp End_OF_Crypt_Routine

;procedure 2 write some crap in a file
;syntax: like the dos one
;yoo lame bitch, i rule like the mothaaaaffuuuuucccckiiiiing hell :)

WritetoFile proc
 push 0
 push offset Howmuch
 push ecx
 push edx
 push dword ptr [Fhandle]
 call WriteFile
 mov eax,dword ptr [Howmuch]
 xor edx,edx
 xor ecx,ecx
 ret
WritetoFile endp

;returns a great random value ;))

Randomize proc
 push ecx
 call GetTickCount
 xchg eax,ecx
 call GetTickCount
 xor ecx,eax
 call GetTickCount
 xor ecx,eax
 xchg eax,ecx
 pop ecx
 ret
Randomize endp

;Procedure 2 read crap out of a fucking lame file
;syntax: like the dos readfile function :)
;yo man this rocks like the hell

ReadFromFile proc
 push 0
 push offset Howmuch
 push ecx
 push edx
 push dword ptr [Fhandle]
 call ReadFile
 mov eax,dword ptr [Howmuch]
 xor edx,edx
 xor ecx,ecx
 or eax,eax
 jz Errorwhilereading
 ret
Errorwhilereading:
 Call Memory_DeAlloc
 WriteConsole2 <offset Terror1>
 jmp End_OF_Crypt_Routine

ReadFromFile endp

; Procedure 2 seek in a file
; syntax: like ah=42h int 21h :)
; (i'm very lazy hehehe)

SeekFile proc
 push 0
 push 0
 push edx                  ; potato reg = 0 (if potato.kind != siglinde)
 push dword ptr [Fhandle]  ; muhahgagagagagagagahahahahahahhahhahahaha
 Call SetFilePointer
 xor edx,edx
 ret
SeekFile endp

Memory_Alloc Proc
 push esi
 push edi
 push edx
 push ebp
 push 4
 push 1000h
 push eax
 push 0
 call VirtualAlloc
 pop ebp
 pop edx
 pop edi
 pop esi
 ret
Memory_Alloc endp

Memory_DeAlloc Proc
 push dword ptr [Fhandle]
 call CloseHandle


 cmp byte ptr [OverLay],0
 jz NixOverLayDa

 Push 2
 push dword ptr [OverlaySize]
 Push DWord Ptr [MemStart8]    
 Call VirtualFree            
 or eax,eax                  
 jnz dealloc_error           
 mov byte ptr [OverLay],0

NixOverLayDa:
 cmp byte ptr [Dealloc],0
 jz NoPossibleMemoryLeak
 Push 2
 push dword ptr [FileSize]        ; push the filesize (amount of allocated mem)
 Push DWord Ptr [RVA_NEW]         ; push the linear offset
 Call VirtualFree                 ; free  it
 or eax,eax                       ; check for error
 jnz dealloc_error                ; jump on error
NoPossibleMemoryLeak:

 Push 2
 push (ToAdd_END - offset CRC_Block1)
 Push DWord Ptr [MemStart7]
 Call VirtualFree                 ; free  it
 or eax,eax                       ; check for error
 jnz dealloc_error                ; jump on error

 Push 2
 push dword ptr [Phillipsuckt]
 Push DWord Ptr [MemStart]
 Call VirtualFree
 or eax,eax
 jne dealloc_error

 Push 2
 push 1000000
 Push dword Ptr [IconBuffer]
 Call VirtualFree
 or eax,eax
 jne dealloc_error

 Push 2
 push dword ptr [FileSize]
 Push DWord Ptr [MemStart]
 Call VirtualFree
 or eax,eax
 jne dealloc_error
 cmp byte ptr [NoWayassi],1
 jz Ficktmich
 WriteConsole2 <offset MemDeallocated>
Ficktmich:
 ret
dealloc_error:
 WriteConsole2 <offset da_error>
 jmp End_OF_Crypt_Routine
Memory_DeAlloc EndP

End_Of_Cryptor:

; include r-aplib.asm
 include k-menu.inc
 Include r-ieh.inc
 include r-slowmte.inc            ; execute the pseudo mte
 include r-line.inc

End_OF_Crypt_Routine:
 mov ebp,dword ptr [KILLASTINKT]
 mov esp,dword ptr [MONGOKILLA]
 jmp EncryptionFinishedReturn
