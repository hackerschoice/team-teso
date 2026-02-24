;============================================================
;===== External Functions ===================================

 Extrn   WriteConsoleA               : PROC
 Extrn   WriteFileA                  : PROC
 Extrn   VirtualAlloc                : PROC
 Extrn   VirtualFree                 : PROC
 Extrn   GetTickCount                : PROC
 Extrn   LookupIconIdFromDirectoryEx : PROC
 Extrn   DeleteFileA                 : PROC
 Extrn   LoadLibraryA                : PROC
 Extrn   SetConsoleCursorInfo        : PROC
 Extrn   GetConsoleCursorInfo        : PROC
 Extrn   CreateThread                : PROC
 Extrn   SetThreadPriority           : PROC
 Extrn   GetThreadPriority           : PROC
 Extrn   GetCurrentProcessId         : PROC
 Extrn   GetPriorityClass            : PROC
 Extrn   OpenProcess                 : PROC
 Extrn   SetPriorityClass            : PROC
 Extrn   ResumeThread                : PROC
 Extrn   SuspendThread               : PROC
 Extrn   ExitThread                  : PROC
 Extrn   CreateEventA                : PROC
 Extrn   WaitForSingleObject         : PROC
 Extrn   SetEvent                    : PROC
 Extrn   ResetEvent                  : PROC
 Extrn   GetProcAddress              : PROC

 Extrn   GetThreadContext : PROC
 Extrn   SetThreadContext : PROC
 Extrn   GetCurrentThread : PROC
 extrn _aP_pack            : near



;============================================================
;===== Some Constants =======================================

 PE_CryptVer EQU "version 1.02"
    PE_Build EQU "bugfix & test version (DiSTRiBUTE AND DiE)"
 CR_LF EQU 0dh,0ah

;============================================================
;===== Variables ============================================

 Error1   db "Can't open file!",CR_LF,0
          db "ERROR: Filename incorrect or file is in use by another proccess!",CR_LF,0
 da_error db "ERROR: Error while deallocating memory used by PE-Crypt.",CR_LF
          db "It is RECOMMENDED that you reboot the system ASAP!",CR_LF,0
  a_error db "ERROR: Error while allocating memory, free some!.",CR_LF,0
 Terror1  db "ERROR: Error while reading file!",CR_LF,0
 MemAllocated db "  - Memory allocated...",CR_LF,0

 MemDeallocated db CR_LF,"  - Memory successfully deallocated.",CR_LF
                db "  - Portable Executable file successfully processed. ",CR_LF,0

 NotPE db "ERROR: This file is damaged or not in Portable Executable Format!",CR_LF,0

Displaystring db "     ",0

     String0 db "  - Backup successfully generated.",CR_LF,0
     String1 db "  - Reading Portable Executable header.",CR_LF,0
     String2 db "  - Processing the Portable Executable ObjectTable.",CR_LF,0
   Baukasten db " - OBJECT : ",0
  Baukasten2 db "RVA : ",0
  Baukasten3 db "VSIZE : ",0
  Baukasten4 db "FLAGS : ",0
  Baukasten5 db "    - packing done   ",0
  Baukasten6 db "    - encryption done",0
  Baukasten7 db "Old PhysicalSize : ",0
  Baukasten8 db CR_LF,"                     New PhysicalSize : ",0
  Baukasten9 db CR_LF,"    - Compressionratio : ",0
 Baukasten10 db "    - Encryption successfully finished. ",0
 Baukasten11 db "    - Encryption is finished. (compression ratio too low)",0
 Baukasten12 db "     -- Processing Portable Executable resources.",CR_LF,0
 Baukasten13 db "      - Encrypting resources.",CR_LF,0
 Baukasten14 db "      - Compressing resources.",CR_LF,0
 Baukasten15 db "      - Reading resources.",CR_LF,0
 Baukasten16 db "      - Compression ratio too low.",CR_LF,0
 Baukasten17 db "      - Resource Processing finished.",CR_LF,0
 Baukasten18 db "     -- Processing PE Relocations.",CR_LF,0
 Baukasten19 db "      - Reading relocations.",CR_LF,0
 Baukasten20 db "      - Encrypting relocations (16bit).",CR_LF,0
 Baukasten21 db "      - Encrypting relocations (12bit).",CR_LF,0
 Baukasten22 db "      - Relocation Processing finished.",CR_LF,0
 Baukasten23 db CR_LF,"  - Debug info was removed.",0
 Baukasten24 db CR_LF,"  - Backup generated.",0
 Baukasten25 db "      - Using delta compression for relocations.",CR_LF,0
Baukasten252 db "      - Delta compression finished.",CR_LF
             db "      - Now using normal compression.",CR_LF,0
Baukasten253 db "      - Normal compression finished.",CR_LF,0
 Baukasten26 db "      - Error while parsing the resource data.",CR_LF
             db "      - Report this error to : random__@hotmail.com",CR_LF,0
   OverLayEr db CR_LF,"  - Overlay was successfully transfered.       ",CR_LF
             db "  - File may not work after getting protected. ",0
 Baukasten27 db "    - No Encryption / Packing of this object (object skipped).",CR_LF
             db "      This object can't be encrypted / packed due an internal reason.",CR_LF,0

 Baukasten28 db CR_LF
             db "-=[o]=- PECRYPT32 Internal Version Information -=[ş]=-",CR_LF
             db "ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ",CR_LF,CR_LF
             db "PECRYPT32 VERSION : ",0
 Baukasten29 db "PECRYPT32 BUILD   : ",0
 Baukasten30 db CR_LF
             db "-=[o]=- PECRYPT32 PROTECTOR REPORT -=[ş]=-",CR_LF
             db "ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ",CR_LF,CR_LF,0
 Baukasten32 db CR_LF
             db "  - Thread Local Storage (.tls) section found.",CR_LF
             db "      If the file doesn't run anymore :         ",CR_LF
             db "       DISABLE THE TLS SUPPORT.           ",CR_LF,0
 Baukasten34 db CR_LF
             db "ERROR: Can't create backup file.",CR_LF,0
 Baukasten35 db CR_LF
             db "ERROR: No PE file, or PE Header damaged.",CR_LF,0
 Baukasten36 db "PECRYPT32: ERROR REPORT",0
Baukasten362 db "File is already PECRYPT32 protected.",CR_LF
             db "!API HOOKING DISABLED!",0
Baukasten372 db "Import Merging disabled due to a zero size section.",0

 Baukasten38 db "File is already PECRYPT32 protected.",CR_LF
             db "!IMPORT DESTROYING DISABLED!",0
 Baukasten37 db "ERROR: PECRYPT32 can't handle files with no Entrypoint.",CR_LF,0

   PEVersion db PE_CryptVer,0
     PEBuild db PE_Build,0

 ReturnChars db CR_LF,0
      HTable db "0123456789ABCDEF"
   RVAString db "        h ",0
 VsizeString db "        h ",0
  FlagString db "        h",CR_LF,0
  PhysString db "        h ",0
NewPhysString db "        h ",0
PercentString db "   %",0
   CryptFile db 128 Dup(0)
  BackupFile db 128 dup(0)
     Spaces db "    - processing ..",0

  Contexti db 1000 dup(0)


      NewOBJ db ".ficken",0
VirtualS_NEW dd 0
     RVA_NEW dd 0
Physical_NEW dd 0
  Offset_NEW dd 0
    Reserved dd 0,0,0
   ObjectFla db 40h,0,0,0C0h

     NewOBJ2 db ".icon",0,0,0
   VSize_New dd 0
     Rva_NEW dd 0
PhysSize_New dd 0
  PhysOffset dd 0
             dd 0,0,0
             db 40h,0,0,0C0h

NewRelocString db ".relocp",0
  NewStringi db "   % compression successfully finished."
OrdinalNumba db "    ",0 ; buffer for the ordinal values
 KILLASTINKT dd 0 ; to save ebp for later use
  MONGOKILLA dd 0 ; to save esp
   DontStore db 1 ; Dontstore the damn raw data offsets
   MemStart6 dd 0 ; holds another memory offset (needed for the whole loader.inc)
   MemStart7 dd 0 

     Fhandle dd 0
    Fhandle2 dd 0
         RVA dd 0
   PhysicalO dd 0
   DosHeader db 4000 dup (?)                  ; Dosheader
    PEHeader db 4000 dup (?)
     LastOBJ db 40 dup (?)
     CODEOBJ db 40 dup (?)
 output_data db 1024 dup (?)
  TempBuffer db 2000 dup (?)
  IconBuffer dd 0 ; points to the memory allocated for the icons
   OBJnumber dw 0
 RelocLength dd 0
     TempVar dd 0 ; just a temp variable
    TempVar2 dd 0 ; just another temp variable
    TempVar4 dd 0 ; just another tempvariable
 CryptValue1 dw 0 ; cryptvalue
   RCompress db 0
     DirSize dd 0 ; size of the resource directory
   MemStart8 dd 0 ; holds the overlay stuff
   MemStart2 dd 0 ; 2nd mem variable for the resource compression
   MemStart4 dd 0 ; another pointer for the apack library
   MemStart5 dd 0 ; holds the offset of the offset buffer ;))
    IconSize dd 0 ; size of the icons
    SaveTemp dd 0 ; lame temp variable
      IconID dd 0 ; icon id
   SaveTemp2 dd 0 ; another lame temp variable
   SaveTemp3 dd 0
   SaveTemp4 dd 0
  LastOBJPos dd 0
  VSizeTable db 100 dup (?) ; table for all virtual sizes
    SaveCrap dd 0
 FileNLength dd 0 ; length of the filename
     FCpassd db 0 ; file check passed?
  CurrentRVA dd 0 ; current rva
CurrentVSIZE dd 0 ; current virtualsize
CurrentFLAGS dd 0 ; current Flags
CurrentPhysS dd 0 ; current physicalsize (old)
    NewPhysS dd 0 ; new physicalsize
ResourceInde db 0 ; index for resource crap
CompressRelocsnow db 0 ; internal flag for relocation compression
   RelocCofs dw 0 ; buffer for the reloc offset
       RSize dd 0 ; size of all relocations together
  DamnCrap22 dd 0
 NullStellen dd 0 ; suuuuuuuckkking offset
       Rbyte db 0 ; are the relocations the last object?
   SPointer1 dd 0
   SPointer2 dd 0
   SPointer3 dd 0
     NewRPos dd 0 ; variable for the new relocation pos
   PatchRrva db 0 ; internal variable for icon rvas ;)
   NoWayassi db 0
    LazyNess db 0 ; just another lame internal variable
    SaveMCRC dd 0
             dd 0
   SAVEMCRC2 dd 0
Phillipsuckt dd 0
    Dontsave db 0 ; internal variable for the tls support
    RealSize dd 0 ; the real physical size of an object
  HighOrderF db 0 ; High order word for the filesize function
    FileSize dd 0 ; filesize of this portable executable file
   FileSize2 dd 0 ; another filesize variable
     OverLay db 0 ; internal variable for the overlay detection
 OverlaySize dd 0 ; size of the overlay
   BufferPos dd 0 ; position of the buffer
 InternalRVA dd 0 ; internal import rva (recalculated)
   EsiBuffer dd 0 ; just to save esi ;)
  TextBuffer dd 0 ; offset of the reserved memory
   FunctionC dd 0 ; functioncounter
    SaveEESP dd 0
   OfsAmount dd 0 ; amount of all offsets
      OfsPos dd 0 ; position in the table
   OfsResult dd 0 ; offset result for each round
   EndResult dd 0 ; contains the smallest offset amount
   PosResult dd 0 ; containts the result for each round
   CheckIcon db 0 ; check for icons? (for the readsubdir procedure)
  CheckVInfo db 0 ; check for version information dir entries
NumberofDirs dd 0 ; number of subdirectories in this directory
  IconResult db 0 ; icon found?
       Marki dw 0 ; used for the api hooking
   ImpCounti dd 0 ; counter for the sections in this PEfile
      Impenc dd 0 ; random value for the separate import encryption
     Impenc3 dd 0 ; another random value for the separate import encryption
    InfoSize dd 0 ; needed for the progress bar ;)

   IconPointers db 2000 dup (?) ; 500 icons = maximum!
     IconPointi dd offset IconPointers
CompressCounter dd 0
  CompressBytes dd 0
        HowMany dd 0
       CCounter dd 0
       OrigSize dd 0
        SaveTmp dd 0
   SavePosition dd 0
          Csize dd 0 ; size of the compressed data
         AddNew db 0 ; add a new obj? 1 = yes, 0 = nooooo
      NewOBJPos dd 0 ; new position for the new obj
       NewAlign db 0 ; align it?
       OldHSize dd 0 ; old header size
        Dealloc db 0 ; needed to fix another possible memory leak
         BLASEN dd 0
        BLASEN2 dd 0
        Howmuch dd 0
           FICK dd 0 ; leck mich du drecksprogramm
     WorkMemory dd 0
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;Strings for the Protector Detection
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
; BJFNTString db ".BJFnt" ; detection string for the BJFnt Protector by Marquis
;  BJFMessage db "--[ş] PROTECTOR USED : BJFnt  CODER : MARQUIS:DE:SOIRE",CR_LF,0


;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;Detection strings for the object detection (support for the rva detection)
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ

   TLS_String db ".tls"
 RELOC_String db ".reloc"
DGROUP_String db "DGROUP"
  Icon_String db ".icon"

;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ
;possible options
;ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ

 COMPRESSION db 0 ; 1 = compression on, 0 = only encryption
  ARTOFRELOC db 0 ; 1 = 16bit, 0 = 12bit relocation encryption
RESOURCECOMP db 0 ; 1 = resource compression, 0 = resource encryption,
                  ; 2 = resource compression / encryption = off
   RELOCCOMP db 0 ; 1 = relocation compression
       ANTID db 0 ; 1 = enabled, 0 = disabled
    INFOMODE db 1 ; infomode , 0 = off, 1 = on
  BACKUPMODE db 0 ; backup mode, 0 = off, 1 = on
  VHEURISTIC db 0 ; pseudo pe virus heuristic, 1 = on, 0 = off
        CRCM db 0 ; crc warning 0=off, 1=hangup on error, 2=window with warning
    HOOKFUNC db 0 ; function hooking, 0 = off , 1 = on
       KILLH db 0 ; 0 = off (default) , 1 = on
     IMPORTD db 0 ; enhanced import destroying, 0=off, 1=on
   I_MERGING db 0 ; belongs to the enhanced import destroying
  ANTILOADER db 0 ; 0 = off , 1 = on..anti loader routines (background crc checking)
     ANTIBPX db 0 ; 0 = off , 1 = on..anti bpx routines
  COMPATIBLE db 0 ; 0 = offset, 1 = disables the TLS support

          DData db ".debug",0
     RsrcString db ".rsrc",0

aAplibV0_10bThe	db 0Dh,0Ah		; DATA XREF: _DATA:000000B0o
		db 0Dh,0Ah
		db 'aPLib v0.10b  -  the smaller the better :)',0Dh,0Ah
		db 'Copyright (c) 1998 by  Ä'
		db 0FAh	; ú
		db  4Ah	; J
		db  69h	; i
		db  62h	; b
		db  7Ah	; z
		db 0FAh	; ú
		db 0C4h	; Ä
		db  20h	;
		db  20h	;
		db  41h	; A
		db  6Ch	; l
		db  6Ch	; l
		db  20h	;
		db  52h	; R
		db  69h	; i
		db  67h	; g
		db  68h	; h
		db  74h	; t
		db  73h	; s
		db  20h	;
		db  52h	; R
		db  65h	; e
		db  73h	; s
		db  65h	; e
		db  72h	; r
		db  76h	; v
		db  65h	; e
		db  64h	; d
		db  0Dh	;
		db  0Ah	;
		db  0Dh	;
		db  0Ah	;
		db  54h	; T
		db  68h	; h
		db  69h	; i
		db  73h	; s
		db  20h	;
		db  63h	; c
		db  6Fh	; o
		db  70h	; p
		db  79h	; y
		db  20h	;
		db  6Fh	; o
		db  66h	; f
		db  20h	;
		db  61h	; a
		db  50h	; P
		db  4Ch	; L
		db  69h	; i
		db  62h	; b
		db  20h	;
		db  69h	; i
		db  73h	; s
		db  20h	;
		db  66h	; f
		db  72h	; r
		db  65h	; e
		db  65h	; e
		db  20h	;
		db  66h	; f
		db  6Fh	; o
		db  72h	; r
		db  20h	;
		db  6Eh	; n
		db  6Fh	; o
		db  6Eh	; n
		db  2Dh	; -
		db  70h	; p
		db  72h	; r
		db  6Fh	; o
		db  66h	; f
		db  69h	; i
		db  74h	; t
		db  61h	; a
		db  62h	; b
		db  6Ch	; l
		db  65h	; e
		db  20h	;
		db  75h	; u
		db  73h	; s
		db  65h	; e
		db  2Eh	; .
		db  0Dh	;
		db  0Ah	;
		db  0Dh	;
		db  0Ah	;
		db    0	;

             W?message$npnuc dd offset aAplibV0_10bThe
public W?aP_nexthashentry$ni
       W?aP_nexthashentry$ni dd 1
          public W?aP_R0$nui
             W?aP_R0$nui     dd 0FFFFFFFFh
W?aP_hashtable$npn$aP_HASH$$ dd 0
  public W?aP_lookup$n__pnui
         W?aP_lookup$n__pnui dd 0
                             db 1024 dup (?)
   public W?aP_hashptr$npnuc
          W?aP_hashptr$npnuc dd 0
   public W?aP_hash_base$nui
          W?aP_hash_base$nui dd 0
    public W?aP_output$npnuc
           W?aP_output$npnuc dd 0
     public W?aP_input$npnuc
            W?aP_input$npnuc dd 0
   public W?aP_tagbyte$npnuc
          W?aP_tagbyte$npnuc dd 0
      public W?aP_tagpos$nui
             W?aP_tagpos$nui dd 0
