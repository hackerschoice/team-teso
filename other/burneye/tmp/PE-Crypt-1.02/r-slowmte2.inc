;SlowMutation Engine 0.1á2 (c) random
;-------
;designed for use with the PECRYPT32 api hooking feature ;)
;Usage:
; esi = memory to encrypt
; ecx = size of the memory (how much 2 encrypt/decrypt)
; edi = buffer to fill in the decryption layers


RelocateMteCode:
 call $+5
 pop ebx
 sub ebx,(offset RelocateMteCode - offset ToAdd) + 5

 mov dword ptr [(SAVEESP3 - offset ToAdd) + ebx],esp

 pusha
 mov edi,(offset LayerPointer - offset ToAdd)
 add edi,ebx
 mov ecx,(offset SavedPOS - offset LayerPointer)
 xor al,al
 rep stosb
 popa

 mov dword ptr [(Mem2Encrypt - offset ToAdd) + ebx],esi
 mov dword ptr [(MemSize  - offset ToAdd) + ebx],ecx
 mov dword ptr [(LayerPos - offset ToAdd) + ebx],edi
 mov dword ptr [(TableSize - offset ToAdd) + ebx],edx

 pusha
 mov ecx,[(TableSize - offset ToAdd) + ebx]
 mov al,90h
 mov edi,dword ptr [(LayerPos - offset ToAdd) + ebx]
 rep stosb
 popa

 mov esi,(offset Predefined_Decryption_Layers - offset ToAdd)       ; pointer to the encryption layers
 add esi,ebx

 mov ecx,(offset Predefined_Decryption_Layers_End - offset Predefined_Decryption_Layers)
 mov edi,dword ptr [(LayerBuffer  - offset ToAdd) + ebx]                    ; pointer to the reserved memory
 rep movsb                                          ; copy all layers

 movzx ecx,byte ptr [(HowMuchLayers  - offset ToAdd) + ebx]                  ; get the number of needed layers
 xor edx,edx                                        ; edx = layercounter = 0
Generate_Layer_2:
 push ecx
 push edx
 movzx edi,byte ptr [(NumberOfLayers  - offset ToAdd) + ebx]                ; maximal number of layers
 call RandomizeValue                            ; generate a random value
 pop edx

 mov byte ptr [(Choosed_Layers  - offset ToAdd) + ebx + edx],al               ; write the choosed layer

 mov edi,dword ptr [(LayerSizes - offset ToAdd) + ebx]                     ; get all sizes of all layers
; add edi,(offset LayerTable - offset ToAdd)
; add edi,ebx
 add edi,dword ptr [(LayerPos - offset ToAdd) + ebx]
 mov esi,dword ptr [(Decryption_Layer_Table - offset ToAdd) + ebx + (eax*4)] ; pointer to the layer
 add esi,dword ptr [(LayerBuffer - offset ToAdd) + ebx]                    ; add the memory offset

 movzx ecx,word ptr [(Decryption_Layer_Size  - offset ToAdd) + ebx + (eax*2)] ; get the layer size
 add dword ptr [(LayerSizes - offset ToAdd) + ebx],ecx                     ; add the size 
 rep movsb                                          ; copy the layer in the new buffer

 pop ecx
 inc edx                                            ; increase the layer counter
 dec ecx
 jnz Generate_Layer_2

 push esi
 mov esi,dword ptr [(LayerPos - offset ToAdd) + ebx]
 add esi,dword ptr [(TableSize - offset ToAdd) + ebx]
 sub esi,edi
 add dword ptr [(MemSize - offset ToAdd) + ebx],esi                        ; add it to the memsize
 pop esi

 mov dword ptr [(SavedPOS - offset ToAdd) + ebx],edi                       ; save the pos of the last layer
 movzx ecx,byte ptr [(HowMuchLayers - offset ToAdd) + ebx]                 ; how many layers 2 encrypt?
 mov dword ptr [(LayerSizes - offset ToAdd) + ebx],0                       ; zero layersizes
 dec edx                                            ; decrease the layer pointer
EncryptMemory2:
 pushad
 movzx eax,byte ptr [(Choosed_Layers - offset ToAdd) + ebx + edx]            ; get the choosed layer
 mov ecx,dword ptr [(LayerSizes - offset ToAdd) + ebx]                     ; get the size of all layers

 mov esi,dword ptr [(SavedPOS - offset ToAdd) + ebx]                       ; get the position of the last layer

 push edi
 movzx edi,word ptr [(Decryption_Layer_Size - offset ToAdd) + ebx + (eax*2)] ; get the size of the current
 add dword ptr [(LayerSizes - offset ToAdd) + ebx],edi                     ; add the current size to the layersizes
 add ecx,dword ptr [(MemSize - offset ToAdd) + ebx]                        ; add the size of the mem
 sub dword ptr [(SavedPOS - offset ToAdd) + ebx],edi                       ; calculate the new last pos
 pop edi       

; 0 = 8bit, 1 = 16bit, 2 = 32bit

 push esi
 mov esi,dword ptr [(SavedPOS - offset ToAdd) + ebx]
 add esi,dword ptr [(Size_Patches - offset ToAdd) + ebx + (eax*4)]
 cmp byte ptr [(BitBreite  - offset ToAdd) + ebx + eax],1
 jnz BitBreite82
 shr ecx,1
BitBreite82:
 cmp byte ptr [(BitBreite - offset ToAdd) + ebx + eax],2
 jnz BitBreite8_22
 shr ecx,2
BitBreite8_22:
 mov [esi+1],ecx
 pop esi

 cmp dword ptr [(NebelBomben - offset ToAdd) + ebx + (eax*4)],0
 jz NoNebelBombe_2

 push esi
 mov esi,dword ptr [(SavedPOS - offset ToAdd) + ebx]
 add esi,dword ptr [(NebelBomben - offset ToAdd) + ebx + (eax*4)]
 push eax
 Call Randomize2
 mov byte ptr [esi+2],al
 pop eax
 pop esi
NoNebelBombe_2:

 push esi
 mov esi,dword ptr [(SavedPOS  - offset ToAdd) + ebx]
 cmp dword ptr [(RandomValues - offset ToAdd) + ebx + (eax*4)],0
 jz NoRandomValue2
 add esi,dword ptr [(RandomValues - offset ToAdd) + ebx + (eax*4)]
 push eax
 Call Randomize2
 mov [esi+1],eax
 mov edx,eax
 pop eax
NoRandomValue2:
 pop esi

 shl eax,2   ; multiply eax by 4
 add eax,(offset Encryption_Layer_Table - offset ToAdd)
 add eax,ebx

 mov eax,[eax]
 sub eax,offset ToAdd
 add eax,ebx
 call eax  ; call the encryption routine for this layer

 popad
 dec edx
 dec ecx
 jnz EncryptMemory2
 mov esp,dword ptr [(SAVEESP3 - offset ToAdd) + ebx]
 ret



Predefined_Decryption_Layers:

ELayer1:
 call $+5
 pop edx
 sub edx,5
SizePatch_ELayer1:
 mov ecx,1
 mov esi,(offset ELayer1_End - offset ELayer1)
NebelBombe1:
 F1CKEN 0FFh
 F1CKEN2 0EAh
VxdBombe:
 add esi,edx
Decrypt_Layer1:
 xor [esi],cl
 inc esi
 inc word ptr [VxdBombe-ELayer1+edx]
 dec ecx
 jnz Decrypt_Layer1
ELayer1_End:

ELayer2:
 call $+5
 pop edx
 sub edx,5
 F1CKEN2 0EAh
SizePatch_ELayer2:
 mov ecx,1
 mov esi,(offset ELayer2_End - offset ELayer2)
NebelBombe2:
 F1CKEN 0FFh
 add esi,edx
VxdBombe2:
 F1CKEN2 0EAh
Decrypt_Layer2:
 rol byte ptr [esi],cl
 inc esi
 inc word ptr [VxdBombe2-ELayer2+edx]
 dec ecx
 jnz Decrypt_Layer2
ELayer2_End:

ELayer3:
 call $+5
 pop edx
 sub edx,5
SizePatch_ELayer3:
 mov ecx,1
 F1CKEN2 0EAh
 mov edi,(offset ELayer3_End - offset ELayer3)
NebelBombe3:
 F1CKEN 0EBh
 add edi,edx
Decrypt_Layer3:
 add byte ptr [edi],cl
 inc edi
 dec ecx
 jnz Decrypt_Layer3
ELayer3_End:

ELayer4:
 call $+5
 pop edx
 sub edx,5
SizePatch_ELayer4:
 mov ecx,1
 mov edi,(offset ELayer4_End - offset ELayer4)
 F1CKEN2 0EAh
 add edi,edx
NebelBombe4:
 F1CKEN 0EAh
Decrypt_Layer4:
 mov al,[edi]
 inc al
 xor al,cl
 stosb
 dec ecx
 jnz Decrypt_Layer4
ELayer4_End:

ELayer5:
 call $+5
 pop edx
 F1CKEN2 0EFh
 sub edx,5
SizePatch_ELayer5:
 mov ecx,1
 mov edi,(offset ELayer5_End - offset ELayer5)
 F1CKEN2 0EAh
 add edi,edx
NebelBombe5:
 F1CKEN 0EAh

RandomVPatch:
 mov eax,1
Decrypt_Layer5:
 xor [edi],al
 inc eax
 inc edi
 inc word ptr [RandomVPatch-ELayer5+edx]
 dec ecx
 jnz Decrypt_Layer5
ELayer5_End:

ELayer6:
 call $+5
 pop edx
 sub edx,5
 F1CKEN2 0EFh
SizePatch_ELayer6:
 mov ecx,1
 mov edi,(offset ELayer6_End - offset ELayer6)
NebelBombe6:
 F1CKEN 0EAh
 add edi,edx
RandomVPatch1:
 mov eax,1
 
Decrypt_Layer6:
 xor byte ptr [edi],al
 rol byte ptr [edi],cl
 inc eax
 inc edi
 inc word ptr [RandomVPatch1-ELayer6+edx]
 dec ecx
 jnz Decrypt_Layer6
ELayer6_End:

ELayer7:
 call $+5
 pop edx
 F1CKEN2 0EFh
 sub edx,5
 add edx,(offset ELayer7_End - offset ELayer7)
SizePatch_ELayer7:
 mov ecx,1
NebelBombe7:
 F1CKEN 0EAh
RandomVPatch2:
 mov eax,1
 
Decrypt_Layer7:
 mov al,[edx]
 xor al,cl
 rol al,cl
 xor al,ah
 mov [edx],al
 xor eax,ecx
 inc edx
loop Decrypt_Layer7
ELayer7_End:

ELayer8:
 call $+5
 pop edx
 sub edx,5
 F1CKEN2 0EFh
 add edx,(offset ELayer8_End - offset ELayer8)
SizePatch_ELayer8:
 mov ecx,1
NebelBombe8:
 F1CKEN 0EAh
RandomVPatch3:
 mov eax,1
 mov esi,edx
 F1CKEN2 0FFh
 mov edi,edx
Decrypt_Layer8:
 lodsb
 xor al,cl
 xor al,ah
 stosb
loop Decrypt_Layer8
ELayer8_End:

ELayer9:
 call $+5
 pop edx
 sub edx,5
 F1CKEN2 0C7h
 add edx,(offset ELayer9_End - offset ELayer9)
SizePatch_ELayer9:
 mov ecx,1
NebelBombe9:
 F1CKEN 0EAh
RandomVPatch4:
 mov eax,1
 mov esi,edx
 F1CKEN 0FFh
 mov edi,edx
Decrypt_Layer99:
 lodsw
 xor ax,cx
 stosw
loop Decrypt_Layer99
ELayer9_End:

ELayer10:
 call $+5
 pop edx
 F1CKEN 0FFh
 sub edx,5
 add edx,(offset ELayer10_End - offset ELayer10)
SizePatch_ELayer10:
 mov ecx,1
RandomVPatch5:
 mov edi,1
NebelBombe10:
 F1CKEN 0EAh
 mov esi,edx
Decrypt_Layer10:
 xor [esi],cx
 xor [esi],di
 inc di
 add esi,2
loop Decrypt_Layer10
ELayer10_End:

ELayer11:
 call $+5
 pop esi
 F1CKEN 0FFh
 add esi,(offset ELayer11_End - offset ELayer11)-5
SizePatch_ELayer11:
 mov ecx,1
 jmp $+4
Decrypt_Layer11:
 int 20h
 xor [esi],ecx
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
loop $-18
ELayer11_End:

ELayer12:
 call $+5
 pop esi
 F1CKEN 0FFh
 add esi,(offset ELayer12_End - offset ELayer12)-5
SizePatch_ELayer12:
 mov ecx,1
 jmp $+4
Decrypt_Layer12:
 int 20h
 sub [esi],ecx
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
loop $-18
ELayer12_End:

ELayer13:
 call $+5
 pop edi
 F1CKEN 0FFh
 add edi,(offset ELayer13_End - offset ELayer13)-5
SizePatch_ELayer13:
 mov ecx,1
 jmp $+4
Decrypt_Layer13:
 int 20h
 rol dword ptr [edi],cl
 jmp $+4
 int 20h
 inc edi
 inc edi
 jmp $+4
 int 20h
 inc edi
 inc edi
 jmp $+4
 int 20h
loop $-18
ELayer13_End:

ELayer14:
 call $+5
 pop edx
 F1CKEN2 0EAh
SizePatch_ELayer14:
 mov ecx,1
 add edx,(offset ELayer14_End - offset ELayer14)-5
 jmp $+4
Decrypt_Layer14:
 int 20h
 ror dword ptr [edx],cl
 jmp $+4
 int 20h
 inc edx
 inc edx
 jmp $+4
 int 20h
 inc edx
 inc edx
 jmp $+4
 int 20h
loop $-18
ELayer14_End:

ELayer15:
 call $+5
 pop esi
SizePatch_ELayer15:
 mov ecx,1
 F1CKEN2 0C7h
 add esi,(offset ELayer15_End - offset ELayer15)-5
 jmp $+4
Decrypt_Layer15:
 int 20h
 add [esi],ecx
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
loop $-18
ELayer15_End:

ELayer16:
 call $+5
 pop esi
SizePatch_ELayer16:
 mov ecx,1
 F1CKEN2 0C7h
 add esi,(offset ELayer16_End - offset ELayer16)-5
 jmp $+4
Decrypt_Layer16:
 int 20h
 add [esi],ecx
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
 inc esi
 inc esi
 jmp $+4
 int 20h
loop $-18
ELayer16_End:


Predefined_Decryption_Layers_End:


Predefined_Encryption_Layers:
EncryptLayer1:
 xor [esi],cl
 inc esi
 dec ecx
 jnz EncryptLayer1
 ret
EncryptLayer1_End:

EncryptLayer2:
 ror byte ptr [esi],cl
 inc esi
 dec ecx
 jnz EncryptLayer2
 ret
EncryptLayer2_End:

EncryptLayer3_2:
 sub byte ptr [esi],cl
 inc esi
 dec ecx
 jnz EncryptLayer3_2
 ret

EncryptLayer3_2_End:

EncryptLayer4_2:
 mov al,[esi]
 xor al,cl
 dec al
 mov [esi],al
 inc esi
 dec ecx
 jnz EncryptLayer4_2
 ret
EncryptLayer4_2_End:

EncryptLayer5_2:
 xor [esi],dl
 inc edx
 inc esi
 dec ecx
 jnz EncryptLayer5_2
 ret
EncryptLayer5_2_End:

EncryptLayer6_2:
 ror byte ptr [esi],cl
 xor [esi],dl
 inc edx
 inc esi
 dec ecx
 jnz EncryptLayer6_2
 ret
EncryptLayer6_2_End:

EncryptLayer7_2:
 mov al,[esi]
 xor al,dh
 ror al,cl
 xor al,cl
 mov [esi],al
 xor edx,ecx
 inc esi
 dec ecx
 jnz EncryptLayer7_2
 ret
EncryptLayer7_2_End:

EncryptLayer8_2:
 mov al,[esi]
 xor al,dh
 xor al,cl
 mov [esi],al
 inc esi
 dec ecx
 jnz EncryptLayer8_2
 ret
EncryptLayer8_2_End:

EncryptLayer9_2:
 xor [esi],cx
 inc dx
 add esi,2
 dec ecx
 jnz EncryptLayer9_2
 ret
EncryptLayer9_2_End:

EncryptLayer10_2:
 xor [esi],dx
 xor [esi],cx
 add esi,2
 inc dx
 dec ecx
 jnz EncryptLayer10_2
 ret
EncryptLayer10_2_End:

EncryptLayer11_2:
 xor [esi],ecx
 add esi,4
 dec ecx
 jnz EncryptLayer11_2
 ret
EncryptLayer11_2_End:

EncryptLayer12_2:
 add [esi],ecx
 add esi,4
 dec ecx
 jnz EncryptLayer12_2
 ret
EncryptLayer12_2_End:

EncryptLayer13_2:
 ror dword ptr [esi],cl
 add esi,4
 dec ecx
 jnz EncryptLayer13_2
 ret
EncryptLayer13_2_End:

EncryptLayer14_2:
 rol dword ptr [esi],cl
 add esi,4
 dec ecx
 jnz EncryptLayer14_2
 ret
EncryptLayer14_2_End:

EncryptLayer15_2:
 sub [esi],ecx
 add esi,4
 dec ecx
 jnz EncryptLayer15_2
 ret
EncryptLayer15_2_End:


Predefined_Encryption_Layers_End:

.Data


;Variables of the Slow Mutation Engine
;
  HowMuchLayers db 15  ; number of Decryption layers you want to include ;)
 NumberOfLayers db 16   ; number of all layers

   LayerPointer db 0   ; current selected layer
    Mem2Encrypt dd 0   ; memory 2 encrypt
        MemSize dd 0   ; size of this memory
       LayerPos dd 0   ; position of the layerbuffer
     LayerSizes dd 0   ; = all layersizes together
       SavedPOS dd 0   ; pos of the last layer
      TableSize dd 0   ; table size for the layers

;Tables which includes pointers to different Decryption routines
Decryption_Layer_Table:
  dd 0
  dd offset ELayer1 - offset ELayer1
  dd offset ELayer2 - offset ELayer1
  dd offset ELayer3 - offset ELayer1
  dd offset ELayer4 - offset ELayer1
  dd offset ELayer5 - offset ELayer1
  dd offset ELayer6 - offset ELayer1
  dd offset ELayer7 - offset ELayer1
  dd offset ELayer8 - offset ELayer1
  dd offset ELayer9 - offset ELayer1
  dd offset ELayer10 - offset ELayer1
  dd offset ELayer11 - offset ELayer1
  dd offset ELayer12 - offset ELayer1
  dd offset ELayer13 - offset ELayer1
  dd offset ELayer14 - offset ELayer1
  dd offset ELayer15 - offset ELayer1
  dd 0
  dd 0

Decryption_Layer_Size:
  dw 0
  dw (offset ELayer1_End - offset ELayer1)
  dw (offset ELayer2_End - offset ELayer2)
  dw (offset ELayer3_End - offset ELayer3)
  dw (offset ELayer4_End - offset ELayer4)
  dw (offset ELayer5_End - offset ELayer5)
  dw (offset ELayer6_End - offset ELayer6)
  dw (offset ELayer7_End - offset ELayer7)
  dw (offset ELayer8_End - offset ELayer8)
  dw (offset ELayer9_End - offset ELayer9)
  dw (offset ELayer10_End - offset ELayer10)
  dw (offset ELayer11_End - offset ELayer11)
  dw (offset ELayer12_End - offset ELayer12)
  dw (offset ELayer13_End - offset ELayer13)
  dw (offset ELayer14_End - offset ELayer14)
  dw (offset ELayer15_End - offset ELayer15)
  dw 0

;Table which includes pointers to the different decryption routines
Encryption_Layer_Table:
  dd 0
  dd offset EncryptLayer1
  dd offset EncryptLayer2
  dd offset EncryptLayer3_2
  dd offset EncryptLayer4_2
  dd offset EncryptLayer5_2
  dd offset EncryptLayer6_2
  dd offset EncryptLayer7_2
  dd offset EncryptLayer8_2
  dd offset EncryptLayer9_2
  dd offset EncryptLayer10_2
  dd offset EncryptLayer11_2
  dd offset EncryptLayer12_2
  dd offset EncryptLayer13_2
  dd offset EncryptLayer14_2
  dd offset EncryptLayer15_2
  dd 0
  dd 0

Size_Patches:
  dd 0
  dd offset SizePatch_ELayer1 - offset ELayer1
  dd offset SizePatch_ELayer2 - offset ELayer2
  dd offset SizePatch_ELayer3 - offset ELayer3
  dd offset SizePatch_ELayer4 - offset ELayer4
  dd offset SizePatch_ELayer5 - offset ELayer5
  dd offset SizePatch_ELayer6 - offset ELayer6
  dd offset SizePatch_ELayer7 - offset ELayer7
  dd offset SizePatch_ELayer8 - offset ELayer8
  dd offset SizePatch_ELayer9 - offset ELayer9
  dd offset SizePatch_ELayer10 - offset ELayer10
  dd offset SizePatch_ELayer11 - offset ELayer11
  dd offset SizePatch_ELayer12 - offset ELayer12
  dd offset SizePatch_ELayer13 - offset ELayer13
  dd offset SizePatch_ELayer14 - offset ELayer14
  dd offset SizePatch_ELayer15 - offset ELayer15
  dd 0
  dd 0

RandomValues:
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0
  dd RandomVPatch - offset ELayer5
  dd RandomVPatch1 - offset ELayer6
  dd RandomVPatch2 - offset ELayer7
  dd RandomVPatch3 - offset ELayer8
  dd RandomVPatch4 - offset ELayer9
  dd RandomVPatch5 - offset ELayer10
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0

NebelBomben:
  dd 0 ; remains always empty
  dd NebelBombe1 - offset ELayer1
  dd NebelBombe2 - offset ELayer2
  dd NebelBombe3 - offset ELayer3
  dd NebelBombe4 - offset ELayer4
  dd NebelBombe5 - offset ELayer5
  dd NebelBombe6 - offset ELayer6
  dd NebelBombe7 - offset ELayer7
  dd NebelBombe8 - offset ELayer8
  dd NebelBombe9 - offset ELayer9
  dd NebelBombe10 - offset ELayer10
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0

BitBreite: ; 0 = 8bit, 1 = 16bit, 2 = 32bit
 db 0
 db 0
 db 0
 db 0
 db 0
 db 0
 db 0
 db 0
 db 0
 db 1
 db 1
 db 2
 db 2
 db 2
 db 2
 db 2

Choosed_Layers:
 db 100 dup (0)       




