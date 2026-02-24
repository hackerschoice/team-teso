;relocation compression 0.2á
;based on a run length encoding range checking :)
;
;0.1á - first beta of this funny code
;0.2á - improved the compression with the apack library

RReloccInc_Start:

 mov edi,dword ptr [MemStart]
 mov esi,edi

 xor ebx,ebx                ; set relocation counter to 0

GetNextRelocation:
 mov eax,[esi]
 mov dword ptr [Paranoia],eax
 mov ecx,dword ptr [esi+4]  ; get the size of this relocation buffa
 sub ecx,8                  ; subtract the header
 shr ecx,1                  ; divide by 2
 dec ecx
 mov dword ptr [esi+4],ecx  ; save it again

 add ebx,8                  ; add 8 ;))

 lodsd
 stosd
 mov dword ptr [NullStellen],edi
 lodsd
 stosd

 lodsw                      ; get the first relocation
 and ax,0FFFh               ; kick the reloc type away ;)
 mov word ptr [RelocCofs],ax ; save the relocation offset
 add ebx,2
 stosw
 cmp ecx,1
 jnz RelocPack
Damnfuckinglamerelocations:
 add esi,2
 add ebx,2
 jmp StuhlGekippt

RelocPack:
 add ebx,2                  ; every damn relocation is 1 word
 lodsw                      ; get a fucking relocation    
 and ax,0FFFh               ; gimme only 12 bits you lamer ;)
 or ax,ax
 jz Fickooon

 push ax
 sub ax,word ptr [RelocCofs] ; subtract for range checking

 cmp ax,127                 ; range smaller than 128?
 ja NotCompressAble         ; if not, not compressable    
 or al,80h
 stosb                      ; save the compressed relocation
 jmp ContinueWithPacking
NotCompressAble:
 inc dword ptr [DamnCrap22]
 pop ax
 push ax
 xchg ah,al
 stosw
 pop ax
 jmp NoDamnWay
Fickooon:
 push esi
 mov esi,dword ptr [NullStellen]
 dec dword ptr [esi]
 pop esi
 jmp StuhlGekippt

ContinueWithPacking:
 pop ax
NoDamnWay:
 mov word ptr [RelocCofs],ax ; save the new relocation offset
StuhlGekippt:
 dec ecx                    ; dec reloccounter
 jnz RelocPack              ; decrease till end
 cmp ebx,dword ptr [RelocLength] ; finished?
 jnz GetNextRelocation           ; if not , continue packing

 sub edi,dword ptr [MemStart]
 mov ecx,edi
 mov dword ptr [RelocSize],ecx   ; save the size before the 2nd compression


 WriteConsole2 <offset Baukasten252>

 mov byte ptr [RelocCCC],1       ; relocation compression is running now (flag)
 jmp CompressThem
ContinueRelocationPacking:

 WriteConsole2 <offset Baukasten253>
 pop esi

 mov eax,dword ptr [CCounter]       ; get the size of the packed relocations
 mov ebp,dword ptr [PEHeader+60] ; and align them
 xor edx,edx                     
 div ebp
 inc eax
 mul ebp
 mov ecx,[esi+16]                 ; get the old value for calculation
 mov [esi+16],eax                 ; write the new physical size value
 mov dword ptr [CCounter],eax     ; save the new size (aligned now)

 sub ecx,eax                     ; calculate the difference
 add dword ptr [Csize],ecx       ; add to the special pack counter of pecrypt


 mov edx,dword ptr [esi+20]      ; seek to the obj start
 call SeekFile


 pushad
 mov edi,offset RELOCSAVE
 mov esi,dword ptr [MemStart]
 mov ecx,5
 rep movsw
 movsb
 mov edi,dword ptr [MemStart]
 xor eax,eax
 stosd
 mov eax,10
 stosd
 xor ax,ax
 stosw
 mov esi,dword ptr [MemStart]
 mov eax,[esi]
 mov dword ptr [SAVEFIRSTRB],eax
 mov [esi],eax
 mov byte ptr [AddNew],1
 popad
 mov dword ptr [PEHeader+164],10

 mov ecx,dword ptr [CCounter]
 mov edx,dword ptr [MemStart]    ; pointer to the packed relocations
 call WritetoFile                ; write the packed relocations 2 disk

RReloccInc_End:

End_Of_RelocCC:
