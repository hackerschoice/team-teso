;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
;                PECRYPT32 1.02 (c) in 1998 by random and acpizer
;컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
;lame crc routine, written in a hurry coz a real crc32 is too slow to use it 
;in every fucking api ;)

Calculate_CRC32:
 shr ecx,2
 push esi
 push ecx
 push edx

Calculate_CRC32_2:
 lodsd
 add edx,eax
 xor edx,ecx
 dec ecx
 jnz Calculate_CRC32_2
 xchg eax,edx
 pop edx
 pop ecx
 pop esi
 ret

