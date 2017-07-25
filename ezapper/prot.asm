;       E-zapper V1.0   (c) E-genia

;       Yoda's codebase was used for this version

.386
.model flat, stdcall
option casemap:none

include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\shell32.inc
include \masm32\include\imagehlp.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\comdlg32.lib
includelib \masm32\lib\shell32.lib
includelib \masm32\lib\imagehlp.lib

include \masm32\include\windows.inc

;------------ CONST ---------
.const

EZ_CFlag_EH             equ 1
EZ_CFlag_RAPI           equ 2
EZ_CFlag_ASice          equ 4
EZ_CFlag_HCRC           equ 8
EZ_CFlag_DII            equ 16
EZ_CFlag_AD             equ 32

EZ_ErrFileDef           db "Erreur accès fichier",0
EZ_ErrNotPE             db "Fichier EXE non valide",0
EZ_ErrNoMem             db "Pas assez de mémoire",0
EZ_ErrWFsize            db "Taille de fichier : 0",0
EZ_ErrCANSec            db "Impossible de rajouter une section",0
EZ_ErrSecAmntLR         db "Nombre de sections déjà maximal",0
EZ_ErrIID               db "Dépassement de capacités",0

EZ_AlignCR              dd 02000h
EZ_EZSecName            dd ('spze')
EZ_KernelName           db "Kernel32.dLl",0
EZ_LoadLName            db "LoadLibraryA",0
EZ_GetPAName            db "GetProcAddress",0

EZ_ErrMSG               db "ERREUR",0

DMOV    MACRO   INdta, OUTdta
        push    INdta
        pop     OUTdta
ENDM

;------------ DATA ----------
.data

EZ_VSIZECorrection      equ 4000h       ; Use 0x2000 + sizeof AuthorizationModule

EZ_DCSize               equ (offset DepackerCodeEnd - offset DepackerCode)
EZ_CRCss                equ 5
EZ_TLSba                equ (offset TlsBackupLabel - offset DepackerCode)
EZ_CRCaddr              equ (OFFSET ChecksumLabel - OFFSET DepackerCode)
EZ_LLsize               equ (OFFSET LOADER_CRYPT_END - OFFSET EZ_PackerStart)
EZ_LL_OEPjs             equ (OFFSET OEP_JUMP_CODE_END - OFFSET OEP_JUMP_CODE_START)
EZ_ITableSize           equ 060h
EZ_MaxSecAmnt           equ 32
EZ_MaxIIDAmnt           equ 32
EZ_OEPjen               equ 65h
EZ_EZCRCcs              equ (OFFSET OEP_JUMP_CODE_START - OFFSET DepackerCode)

;====== E-zapper data start ==================================================

OFSTRUCT_               equ     1+1+2+2+2+OFS_MAXPATHNAME

EZCtrlFileBRdd          dd      0        ; Bytes readed
EZCtrlFileSReq          equ     278      ; Required key file size
EZCtlrFileH             dd      0
EZCtrlFileSize          dd      0
EZCtrlFileATTR          dd      0
EZCtrlFileName          db      'enc_in.dta',0
EZCtrlFileOS            db      OFSTRUCT_ dup (0)
EZCtrlFileData          db      512 dup (0)      ; Data from host module
                                                 ; 0..254    FileName
                                                 ; 255..255  Control Flags
                                                 ; 256..257  User ID (16 bit)
                                                 ; 258..259  Software ID (16 bit)
                                                 ; 260..261  Vendor ID (16 bit)
                                                 ; 262..265  Random seed (32 bit)
                                                 ; 266..269  Encryptor ID (32 bit)
                                                 ; 270..277  Encryption key

EZ_EZABRead             dd      0
EZ_EZABWritten          dd      0
EZ_EZAPMem              dd      0
EZ_EZAFSize             dd      0
EZ_EZAOPSize            dd      0
EZ_EZANFileEnd          dd      0
EZ_EZANTHAddr           dd      0
EZ_EZASecNum            dd      0
EZ_EZANSecRO            dd      0
EZ_EZAOriginalITRVA     dd      0
EZ_EZAhFile             dd      0

EZ_CFlagsBAK             dd      0

;------------ CODE ----------
.code

main:
;----- Load and process control file -----------------------------------------

        invoke  OpenFile,offset EZCtrlFileName,offset EZCtrlFileOS,0    ; Open file for READ operations
        cmp     eax,-1
        jne     noerrorwithctrlfile

        invoke  ExitProcess,0
noerrorwithctrlfile:
        mov     [EZCtlrFileH],eax
        invoke  GetFileSize,eax,NULL
        cmp     eax,-1
        jz      EZ_FLError
        cmp     eax,EZCtrlFileSReq
        je      noerrorwithctrlfile1
        invoke  ExitProcess,0
noerrorwithctrlfile1:
        mov     [EZCtrlFileSize],eax
        invoke  ReadFile,[EZCtlrFileH],offset EZCtrlFileData,EZCtrlFileSReq,offset EZCtrlFileBRdd,NULL
        invoke  CloseHandle,[EZCtlrFileH]

        ;------ Setup flags
        mov     esi,offset EZCtrlFileData
        movzx   edi,byte ptr [esi+255]

        ;------ Setup additional flags
        or      edi,EZ_CFlag_AD

        ;------ Perform encryption
        push    edi
        pop     EZ_CFlagsBAK

;------ ACTUAL CODE START ----------------------------------------------------

        pushad
;------ Fill loader data with required info

        mov     edx,offset EZCtrlFileData
        add     edx,256
        mov     ax,word ptr [edx]
        mov     [EZUserID],ax
        mov     [USER_ID],ax
        mov     edx,offset EZCtrlFileData
        add     edx,258
        mov     ax,word ptr [edx]
        mov     [EZSoftwareID],ax
        mov     [SOFTWARE_ID],ax
        mov     edx,offset EZCtrlFileData
        add     edx,260
        mov     ax,word ptr [edx]
        mov     [EZVendorID],ax
        mov     [VENDOR_ID],ax

        mov     eax,dword ptr [offset EZCtrlFileData+266]
        mov     [EZEncryptorID],eax
        popad

        ;----- MAP THE FILE -----
        invoke  CreateFile,offset EZCtrlFileData,GENERIC_WRITE + GENERIC_READ,FILE_SHARE_WRITE + FILE_SHARE_READ,\
                           NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
        cmp     eax,INVALID_HANDLE_VALUE
        jz      FileErr
        mov     EZ_EZAhFile,eax
        invoke  GetFileSize,EZ_EZAhFile,0
        .IF eax == 0
            push   EZ_EZAhFile
            call   CloseHandle
            jmp    FsizeErr
        .ENDIF

        mov     EZ_EZAFSize,eax
        mov     eax,EZ_EZAFSize
        add     eax,EZ_ITableSize
        add     eax,EZ_DCSize
        add     eax,EZ_AlignCR
        mov     EZ_EZAOPSize,eax
        push    eax
        push    GMEM_FIXED + GMEM_ZEROINIT
        call    GlobalAlloc

        .IF eax == NULL
            push   EZ_EZAhFile
            call   CloseHandle
            jmp    MemErr
        .ENDIF

        mov     EZ_EZAPMem,eax
        invoke  ReadFile,EZ_EZAhFile,EZ_EZAPMem,EZ_EZAFSize,offset EZ_EZABRead,NULL

        ; ----- check the PE Signature and get some needed values -----
        mov     edi,EZ_EZAPMem
        .IF word ptr [edi] != 'ZM'
            push     EZ_EZAPMem
            call     GlobalFree
            push     EZ_EZAhFile
            call     CloseHandle
            jmp      PEErr
        .ENDIF

        add     edi,[edi+3Ch]
        .IF word ptr [edi] != 'EP'
            push     EZ_EZAPMem
            call     GlobalFree
            push     EZ_EZAhFile
            call     CloseHandle
            jmp      PEErr
        .ENDIF

        mov     EZ_EZANTHAddr,edi

        assume edi : ptr IMAGE_NT_HEADERS

        push    [edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
        pop     EZ_EZAOriginalITRVA
        push    word ptr [edi].FileHeader.NumberOfSections
        pop     word ptr EZ_EZASecNum

        .IF EZ_EZASecNum > EZ_MaxSecAmnt
            jmp          SecNumErr
        .ENDIF

        push    [edi].OptionalHeader.AddressOfEntryPoint
        pop     dwOrgEntryPoint
        push    [edi].OptionalHeader.ImageBase
        pop     dwImageBase

;------ Erase IAT ------------------------------------------------------------

        xor     eax, eax
        mov     ecx, 4
        lea     edi, [edi].OptionalHeader.DataDirectory[11 *SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress

        assume edi : nothing

EZ_DDLoop:
        stosd
        loop    EZ_DDLoop

        push    EZ_EZAOriginalITRVA
        push    EZ_EZAPMem
        call    RVA2Offset
        push    eax
        push    EZ_EZAPMem
        call    EZ_RCROrgIT
        or      eax, eax
        .IF ZERO?
            push        EZ_EZAPMem
            call        GlobalFree
            push        EZ_EZAhFile
            call        CloseHandle
            jmp         IIDErr
        .ENDIF

;------ Create EZapper section -----------------------------------------------

        push    EZ_EZAPMem
        call    EZ_AddSec
        .IF eax == 0
            push   EZ_EZAPMem
            call   GlobalFree
            push   EZ_EZAhFile
            call   CloseHandle
            jmp    EZ_EZANSpaceSecErr
        .ENDIF

;----- Create EZapper IT -----------------------------------------------------

        xchg    eax,esi
        assume esi : ptr IMAGE_SECTION_HEADER
        mov     eax,[esi].PointerToRawData
        mov     EZ_EZANSecRO, eax
        add     eax,EZ_EZAPMem
        push    [esi].VirtualAddress
        push    eax
        call    EZ_CreateIT

;------ Tune up TLS ----------------------------------------------------------

        push    [esi].VirtualAddress
        push    EZ_EZAPMem
        call    EZ_TUTLS

;------ Encryption -----------------------------------------------------------

        pushad
        mov     eax,EZ_EZAPMem
        mov     ebx,0
        call    EZ_PEnc
        popad

        mov     edi,EZ_EZANTHAddr
        assume edi : ptr IMAGE_NT_HEADERS               ; edi -> pointer to PE header
        push    [esi].VirtualAddress
        pop     [edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY].VirtualAddress
        mov     eax,[esi].VirtualAddress
        add     eax,EZ_ITableSize
        mov     [edi].OptionalHeader.AddressOfEntryPoint,eax
        mov     eax,[esi].VirtualAddress
        add     eax,[esi].Misc.VirtualSize
        mov     [edi].OptionalHeader.SizeOfImage,eax
        push    EZ_CFlagsBAK
        pop     EZ_CFlags

        assume esi : nothing
        assume edi : nothing

        mov     eax,EZ_EZANSecRO
        add     eax,EZ_ITableSize
        add     eax,EZ_DCSize
        mov     EZ_EZANFileEnd,eax

;------ Copy EZapper code ----------------------------------------------------

        mov     edi,EZ_EZANSecRO
        add     edi,EZ_ITableSize
        add     edi,EZ_EZAPMem
        mov     esi,offset DepackerCode
        mov     ecx,EZ_DCSize
        rep     movsb

;------ Protect JumpCode -----------------------------------------------------

        mov     edi, EZ_EZAPMem
        add     edi, EZ_EZANSecRO
        add     edi, EZ_ITableSize
        add     edi, (OFFSET OEP_JUMP_CODE_START - OFFSET DepackerCode)
        mov     esi, edi
        mov     ecx, EZ_LL_OEPjs
        xor     ebx, ebx
EZ_EZAOJElp:
        lodsb
        ror     al, 2
        add     al, BL
        xor     al, EZ_OEPjen
        stosb
        inc     ebx
        loop    EZ_EZAOJElp

;------ ENCRYPT EZapper ------------------------------------------------------

        mov     ecx, EZ_LLsize
        sub     ecx, 4
        mov     edi, EZ_EZAPMem
        add     edi, EZ_EZANSecRO
        add     edi, EZ_ITableSize
        add     edi, (OFFSET EZ_PackerStart - OFFSET DepackerCode)
        mov     ecx, EZ_LLsize
        mov     esi, edi
        mov     eax, 81269284h

lcloop: xor     dword ptr [esi],eax
        inc     eax
        rol     eax,1
        xor     eax,91229861h
        dec     ecx
        inc     esi
        cmp     ecx,0
        jne     lcloop

;------ Get CRC --------------------------------------------------------------

        mov     eax,EZ_EZAPMem
        mov     ecx,EZ_EZANFileEnd
        sub     ecx,EZ_CRCss
        call    EZ_CLCCRC
        mov     EZ_OCRC,eax

        mov     eax, EZ_EZAPMem
        add     eax, EZ_ITableSize
        add     eax, EZ_EZANSecRO
        add     eax, EZ_CRCaddr
        mov     edx, EZ_OCRC
        mov     dword ptr [eax], edx

;------ Done :) --------------------------------------------------------------

        invoke  SetFilePointer,EZ_EZAhFile,0,NULL,FILE_BEGIN
        invoke  WriteFile,EZ_EZAhFile,EZ_EZAPMem,EZ_EZAOPSize,offset EZ_EZABWritten,NULL

        invoke  SetFilePointer,EZ_EZAhFile,EZ_EZANFileEnd,NULL,FILE_BEGIN
        invoke  SetEndOfFile,EZ_EZAhFile

        push    EZ_EZAPMem
        call    GlobalFree
        push    EZ_EZAhFile
        call    CloseHandle
EZ_Exit:
        invoke  ExitProcess,0

;------ ERRORS ---------------------------------------------------------------

EZ_FLError:
        invoke  ExitProcess,0
MemErr:
        mov     eax,offset EZ_ErrNoMem
        jmp     EZ_DispErr

PEErr:
        mov     eax,offset EZ_ErrNotPE
        jmp     EZ_DispErr

FileErr:
        mov     eax,offset EZ_ErrFileDef
        jmp     EZ_DispErr

EZ_EZANSpaceSecErr:
        mov     eax,offset EZ_ErrCANSec
        jmp     EZ_DispErr

FsizeErr:
        mov     eax,offset EZ_ErrWFsize
        jmp     EZ_DispErr

SecNumErr:
        mov     eax,offset EZ_ErrSecAmntLR
        jmp     EZ_DispErr

IIDErr:
        mov     eax, OFFSET EZ_ErrIID
        jmp     EZ_DispErr

EZ_DispErr:
        invoke  MessageBox,NULL,eax,offset EZ_ErrMSG,MB_ICONERROR
        jmp     EZ_Exit

;------ FUNCTIONS ------------------------------------------------------------

EZ_EncrSC:
        mov     edi,esi
SecEncryptLoop:
        pushad
        sub     ecx,4

        mov     eax,offset RandomNumber
        mov     esi,offset EZCtrlFileData
        add     esi,262
        mov     ebx,dword ptr [esi]
        mov     dword ptr [eax],ebx
        mov     ebx,offset RandomNumber
        mov     edx,offset EZCtrlFileData
        add     edx,270
        mov     esi,offset DepackerCode

__encrypt:

;------ RND GEN -------------------------------------------
        pushad
        mov     eax,214013
        mov     ecx,offset RandomNumber
        imul    dword ptr [ecx]
        sub     edx, edx
        add     eax, 2531011
        mov     dword ptr [ecx], eax
        popad
;------ END OF RND GEN ------------------------------------

        ;       XOR it by code
        mov     eax,dword ptr [edi]
        xor     eax,dword ptr [esi]
        ;       XOR it by random
        xor     eax,dword ptr [ebx]
        mov     dword ptr [edi],eax
        ;       XOR it by EncryptionKey
        mov     ah,byte ptr [edx]
        xor     byte ptr [edi],ah

        inc     edx
        cmp     edx,offset EZCtrlFileData+278
        jnae    ec_dont_reset_key
        mov     edx,offset EZCtrlFileData+270
ec_dont_reset_key:

        inc     esi
        cmp     esi,offset additional_dc_password_end-4
        jnae    ec_dont_reset_code_ptr
        mov     esi,offset DepackerCode          ; Reset code pointer
ec_dont_reset_code_ptr:
        inc     edi
        dec     ecx
        cmp     ecx,0
        jne     __encrypt

        popad
        ret

;-----------------------------------------------------------------------------
; ADD SECTION RVs
; 0 - Can't add new section
; 1 - Already encrypted
EZ_AddSec PROC USES edi esi ebx ecx edx, EZ_EZAPMem_ : LPVOID
        LOCAL   dwSecNum    : DWORD

        mov     edi,EZ_EZAPMem_
        add     DWORD PTR edi,[edi+03Ch]
        assume edi : ptr IMAGE_NT_HEADERS

;------ Can we add new section ? ---------------------------------------------

        xor     eax,eax
        mov     ax,[edi].FileHeader.NumberOfSections
        mov     dwSecNum,eax
        mov     ecx,SIZEOF IMAGE_SECTION_HEADER
        imul    eax,ecx
        add     eax,SIZEOF IMAGE_SECTION_HEADER
        mov     ecx,edi
        sub     ecx,EZ_EZAPMem_
        add     ecx,eax
        add     ecx,0F8h
        .IF ecx > [edi].OptionalHeader.SizeOfHeaders
            xor   eax,eax
            jmp   @@ExitProc_AS
        .ENDIF

;------ Add one more section to PE -------------------------------------------

        mov     esi,edi
        add     esi,0F8h
        assume esi : ptr IMAGE_SECTION_HEADER

        mov     edx,dwSecNum
        sub     edx,1
        .REPEAT
           mov  eax,[esi].Characteristics
           or   eax,080000000h
           mov  [esi].Characteristics,eax

           add  esi,SIZEOF IMAGE_SECTION_HEADER
           dec  edx
        .UNTIL edx == 0

        mov     edx,esi
        add     edx,SIZEOF IMAGE_SECTION_HEADER
        assume edx : ptr IMAGE_SECTION_HEADER

        mov     eax,[esi].VirtualAddress
        add     eax,[esi].Misc.VirtualSize
        push    01000h
        push    eax
        call    EZ_PEAlign
        mov     [edx].VirtualAddress,eax

;------ Setup correct virtual size -------------------------------------------

        mov     [edx].Misc.VirtualSize,EZ_VSIZECorrection

;------ Setup correct raw size -----------------------------------------------

        mov     eax,EZ_ITableSize
        add     eax,EZ_DCSize
        mov     [edx].SizeOfRawData,eax

        lea     eax,[edx].Name1
        push    EZ_EZSecName
        pop     [eax]
        mov     DWORD PTR [eax+4],0

        mov     [edx].Characteristics,0E00000E0h

        mov     eax,[esi].PointerToRawData
        add     eax,[esi].SizeOfRawData
        push    0200h
        push    eax
        call    EZ_PEAlign
        mov     [edx].PointerToRawData,eax
        mov     eax,edx

        inc     [edi].FileHeader.NumberOfSections

        assume edx : nothing
        assume esi : nothing
        assume edi : nothing
@@ExitProc_AS:
        ret
EZ_AddSec ENDP

EZ_CreateIT PROC USES ebx ecx edx esi edi, EZ_NITAddr : LPVOID, dwNewSectionVA : DWORD

        mov     esi,EZ_NITAddr

        mov     eax,EZ_NITAddr
        mov     ecx,EZ_ITableSize
EZ_ZMem:
        mov     byte ptr [eax],0
        inc     eax
        loop    EZ_ZMem

        mov     ebx,esi
        mov     eax,SIZEOF IMAGE_IMPORT_DESCRIPTOR
        xor     edx,edx
        mov     ecx,2
        mul     ecx
        add     ebx,eax
        assume  esi:ptr IMAGE_IMPORT_DESCRIPTOR
        mov     eax,ebx
        sub     eax,esi
        add     eax,dwNewSectionVA
        mov     [esi].Name1,eax
        push    esi
        mov     esi,offset EZ_KernelName
        mov     edi,ebx

        .REPEAT
           lodsb
           stosb
        .UNTIL byte ptr [esi] == 0

        pop     esi
        mov     ebx,edi
        inc     ebx
        mov     eax,ebx
        sub     eax,esi
        add     eax,dwNewSectionVA
        mov     [esi].FirstThunk,eax
        mov     edx,ebx
        add     edx,10
        mov     eax,edx
        sub     eax,esi
        add     eax,dwNewSectionVA
        mov     [ebx],eax
        add     edx,2
        push    esi
        mov     esi,offset EZ_LoadLName
        mov     edi,edx

        .REPEAT
           lodsb
           stosb
        .UNTIL byte ptr [esi] == 0

        pop     esi
        mov     edx,edi
        add     ebx,4
        mov     eax,edx
        sub     eax,esi
        add     eax,dwNewSectionVA
        mov     [ebx],eax
        add     edx,2
        mov     esi,offset EZ_GetPAName
        mov     edi,edx

        .REPEAT
           lodsb
           stosb
        .UNTIL byte ptr [esi] == 0

        assume esi : nothing
        ret
EZ_CreateIT ENDP

EZ_TUTLS PROC USES edi ebx esi ecx, pFileMem : LPVOID, EZ_EncSecVA : DWORD
        LOCAL   pTlsDirAddr : LPVOID

;------ Check for TLS --------------------------------------------------------

        mov     edi,pFileMem
        add     edi,[edi+03Ch]
        assume edi : ptr IMAGE_NT_HEADERS
        lea     ebx,[edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY * 9].VirtualAddress
        mov     pTlsDirAddr,ebx
        mov     ebx,[ebx]
        assume edi : nothing
        cmp     ebx,0
        jz      EZ_TLSFExit

;------ Get pointer to TLS ---------------------------------------------------

        push    ebx
        push    pFileMem
        call    RVA2Offset
        cmp     eax,0
        jz      EZ_TLSFExit
        mov     esi,pFileMem
        add     esi,eax

;------ Make a copy of TLS for future use ------------------------------------

        mov     edi,offset TlsBackup
        mov     ecx,sizeof IMAGE_TLS_DIRECTORY32
        rep     movsb

;------ FIX TLS --------------------------------------------------------------

        mov     eax,EZ_EncSecVA
        add     eax,EZ_ITableSize
        add     eax,EZ_TLSba
        mov     esi,pTlsDirAddr
        mov     [esi],eax
EZ_TLSFExit:
        ret
EZ_TUTLS ENDP

;-----------------------------------------------------------------------------
; Encrypt names and make a copy of IID
; 1 - OK
; 0 - IID's amount is out of maximum
EZ_RCROrgIT PROC USES edi esi edx, pFileImage : LPVOID, pITBaseRO : LPVOID
        LOCAL dwIIDNum : DWORD

        xor     eax, eax
        mov     edi, OFFSET IIDInfo
        mov     ecx, SIZEOF IIDInfo
EZ_CLRALoop:
        stosb
        loop    EZ_CLRALoop

        INVOKE  GetTickCount
        xor     eax, 19827862h
        mov     edx, eax

        mov     dwIIDNum, 0
        mov     edi, pITBaseRO
        add     edi, pFileImage
        ASSUME edi : PTR IMAGE_IMPORT_DESCRIPTOR
        mov     esi, OFFSET IIDInfo
        ASSUME esi : PTR sItInfo
        .WHILE [edi].Name1
           inc  dwIIDNum
           .IF dwIIDNum == (EZ_MaxIIDAmnt)
               xor      eax, eax
               jmp      POIT_Exit
           .ENDIF

           DMOV  <[edi].Name1>, <[esi].DllNameRVA>
           DMOV  <[edi].OriginalFirstThunk>, <[esi].OrgFirstThunk>
           DMOV  <[edi].FirstThunk>, <[esi].FirstThunk>

           push  [edi].Name1
           push  pFileImage
           call  RVA2Offset
           add   eax, pFileImage
           call  EZ_PRTStr

           push  esi
           mov   esi, [edi].OriginalFirstThunk
           .IF !esi
               mov  esi, [edi].FirstThunk
           .ENDIF
           push  esi
           push  pFileImage
           call  RVA2Offset
           mov   esi, eax
           add   esi, pFileImage
           .WHILE DWORD PTR [esi]
              mov       eax, [esi]
              test      eax,IMAGE_ORDINAL_FLAG32
              jnz       EZ_SAPIStr
              push      eax
              push      pFileImage
              call      RVA2Offset
              or        eax, eax
              jz        EZ_SAPIStr
              add       eax, pFileImage
              add       eax, 2
              call      EZ_PRTStr
EZ_SAPIStr:   add       esi, 4
           .ENDW
           pop esi

           mov  [edi].Name1, edx
           mov  [edi].OriginalFirstThunk, edx
           mov  [edi].FirstThunk, edx
           mov  [edi].TimeDateStamp, edx
           mov  [edi].ForwarderChain, edx

           add  edi,SIZEOF IMAGE_IMPORT_DESCRIPTOR
           add  esi,SIZEOF sItInfo
        .ENDW

        ASSUME esi : NOTHING
        ASSUME edi : NOTHING

        xor     eax, eax
        inc     eax
POIT_Exit:
        ret
EZ_RCROrgIT ENDP

EZ_PEAlign PROC USES ecx edx, dwTarNum : DWORD, dwAlignTo : DWORD
        mov     ecx,dwAlignTo
        mov     eax,dwTarNum
        xor     edx,edx
        div     ecx
        cmp     edx,0
        jz      EZ_SkipAlign
        inc     eax
EZ_SkipAlign:
        mul     ecx
        ret
EZ_PEAlign ENDP

RVA2Offset PROC USES ebx ecx edx, Base : DWORD,dwITRVA : DWORD
        mov     eax,Base
        add     eax,[eax+03Ch]
        invoke  ImageRvaToSection,eax,Base,dwITRVA
        test    eax,eax
        jz      EZ_ExtProc

        xchg    eax,ebx
        assume ebx : ptr IMAGE_SECTION_HEADER
        mov     eax,dwITRVA
        sub     eax,[ebx].VirtualAddress
        add     eax,[ebx].PointerToRawData
        assume ebx : nothing
EZ_ExtProc:
        ret
RVA2Offset ENDP

;------ Actual protector -----------------------------------------------------
DepackerCode:

        xor     eax,eax
        mov     ecx,3F8h
        call    @delta
@delta: pop     ebp
        sub     ebp,offset @delta

;------ Restore protector ----------------------------------------------------
        mov     ecx, EZ_LLsize
        sub     ecx, 4
        lea     edi, [ebp+OFFSET EZ_PackerStart]
        mov     esi, edi
        mov     eax, 81269284h

dcloop: xor     dword ptr [esi],eax
        inc     eax
        rol     eax,1
        xor     eax, 91229861h
        dec     ecx
        inc     esi
        cmp     ecx,0
        jne     dcloop

EZ_PackerStart:

;------ NT ? -----------------------------------------------------------------

        mov     eax, [ESP+020h]
        inc     eax
        JS      NoNT
        mov     dword ptr [EBP+bNT], 1
NoNT:
;------ Check CRC ------------------------------------------------------------

        lea     eax, [EBP+OFFSET DepackerCode]
        mov     ecx, EZ_EZCRCcs
        call    EZ_CLCCRC
        mov     [EBP+EZ_EZCRC], eax

;------ SoftICE check --------------------------------------------------------

        mov     eax, [ebp+EZ_CFlags]
        and     eax, EZ_CFlag_ASice
        jz      SkipSICheck

        lea     esi,[EBP+SEH]
        ASSUME esi : PTR sSEH
        lea     eax, [EBP+OFFSET SICheck1_SP]
        mov     [esi].SaveEip, eax
        ASSUME esi : NOTHING
        mov     edi, EBP
        lea     eax, [EBP+OFFSET SEH_Hnd1]
        xor     ebx, ebx
        push    eax
        ASSUME FS : NOTHING
        push    FS:[ebx]
        mov     FS:[ebx], ESP

        mov     ebp, 04243484Bh
        mov     ax, 04h
        jmp     SM1
        DB      0FFh
SM1:    INT     3

SICheck1_SP:

        mov     EBP, edi

        xor     ebx, ebx
        pop     FS:[ebx]
        add     ESP, 4

        .IF al != 4
;------ SoftICE detected -----------------------------------------------------
           jmp SM2
           DB 0E9h
SM2:       popad
           ret
        .ENDIF
SkipSICheck:

;------ Get API entry points -------------------------------------------------

        mov     eax,[ebp+dwImageBase]
        add     eax,[eax+03Ch]
        add     eax,080h
        mov     ecx,[eax]                                   ; ecx contains the VirtualAddress of the IT
        add     ecx,[ebp+dwImageBase]
        add     ecx,16
        mov     eax,dword ptr [ecx]
        add     eax,[ebp+dwImageBase]
        mov     ebx,dword ptr [eax]
        mov     [ebp+_LoadLibrary],ebx
        add     eax,4
        mov     ebx,dword ptr [eax]
        mov     [ebp+_GetProcAddress],ebx

;------ GET KERNEL32 API ADDRESSES -------------------------------------------

        lea eax,[ebp+offset szKernel32]
        push eax
        call [ebp+_LoadLibrary]
        mov esi,eax
        mov [EBP+dwKernelBase], eax

        lea eax,[ebp+szGetModuleHandle]
        call DoGetProcAddr
        mov [ebp+_GetModuleHandle],eax

        ;   VirtualProtect
        lea eax,[ebp+szVirtualProtect]
        call DoGetProcAddr
        mov [ebp+_VirtualProtect],eax

        ;   GetModuleFileName
        lea eax,[ebp+szGetModuleFileName]
        call DoGetProcAddr
        mov [ebp+_GetModuleFileName],eax

        ;   CreateFile
        lea eax,[ebp+szCreateFile]
        call DoGetProcAddr
        mov [ebp+_CreateFile],eax

        ;   GlobalAlloc
        lea eax,[ebp+szGlobalAlloc]
        call DoGetProcAddr
        mov [ebp+_GlobalAlloc],eax

        ;   GlobalFree
        lea eax,[ebp+szGlobalFree]
        call DoGetProcAddr
        mov [ebp+_GlobalFree],eax

        ;   ReadFile
        lea eax,[ebp+szReadFile]
        call DoGetProcAddr
        mov [ebp+_ReadFile],eax

        ;   GetFileSize
        lea eax,[ebp+szGetFileSize]
        call DoGetProcAddr
        mov [ebp+_GetFileSize],eax

        ;   CloseHandle
        lea eax,[ebp+szCloseHandle]
        call DoGetProcAddr
        mov [ebp+_CloseHandle],eax

        ;   GetWindowsDirectoryA
        lea eax,[ebp+szGetWindowsDirectoryA]
        call DoGetProcAddr
        mov [ebp+_GetWindowsDirectoryA],eax

        ;   GetTempPathA
        lea eax,[ebp+szGetTempPathA]
        call DoGetProcAddr
        mov [ebp+_GetTempPathA],eax

        ;   GetTempFileNameA
        lea eax,[ebp+szGetTempFileNameA]
        call DoGetProcAddr
        mov [ebp+_GetTempFileNameA],eax

        ;   OpenFile
        lea eax,[ebp+szOpenFile]
        call DoGetProcAddr
        mov [ebp+_OpenFile],eax

        ;   WriteFile
        lea eax,[ebp+szWriteFile]
        call DoGetProcAddr
        mov [ebp+_WriteFile],eax

        ;   GetLastError
        lea eax,[ebp+szGetLastError]
        call DoGetProcAddr
        mov [ebp+_GetLastError],eax

        ;   FormatMessageA
        lea eax,[ebp+szFormatMessageA]
        call DoGetProcAddr
        mov [ebp+_FormatMessageA],eax

        ;   GetDiskFreeSpaceA
        lea eax,[ebp+szGetDiskFreeSpaceA]
        call DoGetProcAddr
        mov [ebp+_GetDiskFreeSpaceA],eax

        ;   GetComputerNameA
        lea eax,[ebp+szGetComputerNameA]
        call DoGetProcAddr
        mov [ebp+_GetComputerNameA],eax

        ;   GetTickCount
        lea eax,[ebp+szGetTickCount]
        call DoGetProcAddr
        mov [ebp+_GetTickCount],eax

        ;   GetVolumeInformationA
        lea eax,[ebp+szGetVolumeInformationA]
        call DoGetProcAddr
        mov [ebp+_GetVolumeInformationA],eax

        ;   CreateProcessA
        lea eax,[ebp+szCreateProcessA]
        call DoGetProcAddr
        mov [ebp+_CreateProcessA],eax

        ;   Sleep
        lea eax,[ebp+szSleep]
        call DoGetProcAddr
        mov [ebp+_Sleep],eax

        ;   GetExitCodeProcess
        lea eax,[ebp+szGetExitCodeProcess]
        call DoGetProcAddr
        mov [ebp+_GetExitCodeProcess],eax

        ;   DeleteFileA
        lea eax,[ebp+szDeleteFileA]
        call DoGetProcAddr
        mov [ebp+_DeleteFileA],eax

        ;   ExitProcess
        lea eax,[ebp+szExitProcess]
        call DoGetProcAddr
        mov [ebp+_ExitProcess],eax


;------ GET USER32 API ADDRESSES ---------------------------------------------
        ; get user base
        lea eax,[ebp+offset szUser32]
        push eax
        call [ebp+_LoadLibrary]
        mov esi,eax
        mov [EBP+dwUserBase], eax

        ;   MessageBoxA
        lea eax,[ebp+szMessageBoxA]
        call DoGetProcAddr
        mov [ebp+_MessageBoxA],eax

        ;   wsprintfA
        lea eax,[ebp+szwsprintfA]
        call DoGetProcAddr
        mov [ebp+_wsprintfA],eax

        ; Done
        lea eax, [EBP+OFFSET LoaderContinue1]
        push eax
        ret

DoGetProcAddr:
        push eax
        push esi
        call [ebp+_GetProcAddress]
        ret

LoaderContinue1:

;------ Anti dumping ---------------------------------------------------------

        test    [ebp+EZ_CFlags],EZ_CFlag_AD
        jz      EZ_AllowDumping

        push    fs:[30h]
        pop     eax
        TEST    eax, eax
        JS      fuapfdw_is9x     ; Win 9x
fuapfdw_isNT:
        mov     eax, [eax+0Ch]
        mov     eax, [eax+0Ch]
        mov     dword ptr [eax+20h], 1000h ; Would be better to use some random variable
        jmp     fuapfdw_finished
fuapfdw_is9x:
        push    0
        call    [ebp+_GetModuleHandle]
        TEST    edx, edx
        jns     fuapfdw_finished
        cmp     dword ptr [edx+8], -1
        jne     fuapfdw_finished
        mov     edx, [edx+4]
        mov     dword ptr [edx+50h], 1000h ; Would be better to use some random variable

fuapfdw_finished:
EZ_AllowDumping:

        mov     edi,[ebp+dwImageBase]
        add     edi,[edi+03Ch]
        assume edi : ptr IMAGE_NT_HEADERS
        mov     esi,[ebp+dwImageBase]
        mov     ecx,[edi].OptionalHeader.SizeOfHeaders
        assume edi : nothing

        lea     eax,[ebp+Buff]
        push    eax
        push    PAGE_READWRITE
        push    ecx
        push    [ebp+dwImageBase]
        call    [ebp+_VirtualProtect]

;------ Perform CRC check ----------------------------------------------------

        test    [ebp+EZ_CFlags],EZ_CFlag_HCRC
        jz      EZ_NCRCC

        push    MAX_PATH
        lea     edi,[ebp+Buff]
        push    edi
        push    0
        call    [ebp+_GetModuleFileName]

        push    0
        push    FILE_ATTRIBUTE_NORMAL
        push    OPEN_EXISTING
        push    NULL
        push    FILE_SHARE_READ
        push    GENERIC_READ
        push    edi
        call    [ebp+_CreateFile]
        .IF eax == INVALID_HANDLE_VALUE
            xor    eax,eax
            jmp    EZ_DNTCRCCLC
        .ENDIF
        mov     edi,eax

        push    NULL
        push    edi
        call    [ebp+_GetFileSize]
        sub     eax,EZ_CRCss
        xchg    eax,esi

        push    esi
        push    GMEM_FIXED+GMEM_ZEROINIT
        call    [ebp+_GlobalAlloc]
        .IF eax == NULL
            jmp    EZ_DCCRCClnUP
        .ENDIF
        xchg    eax,ebx

        push    NULL
        lea     eax,[ebp+Buff]
        push    eax
        push    esi
        push    ebx
        push    edi
        call    [ebp+_ReadFile]

        mov     eax,ebx
        mov     ecx,esi
        push    ebx
        push    edi

        call    EZ_CLCCRC
        mov     [ebp+EZ_RsCRC],eax

        pop     edi
        pop     ebx
        lea     eax, [EBP+OFFSET EZ_CRCPrcd]
        push    eax
        ret

EZ_CLCCRC:
        mov     edi,eax
        xor     eax,eax
        xor     ebx,ebx
        xor     edx,edx

EZ_CRCSmLP:
        mov     al,byte ptr [edi]
        mul     edx
        add     ebx,eax
        inc     edx
        inc     edi
        loop    EZ_CRCSmLP
        xchg    eax,ebx
        ret

EZ_CRCPrcd:
        push    ebx
        call    [ebp+_GlobalFree]
        xchg    esi,eax

EZ_DCCRCClnUP:
        push    eax
        push    edi
        call    [ebp+_CloseHandle]
        pop     eax

EZ_DNTCRCCLC:
EZ_NCRCC:

        mov     eax,[ebp+dwImageBase]
        mov     ebx,1
        call    EZ_PEnc
        lea     eax, [EBP+OFFSET EZ_ADclPrcd]
        push    eax
        ret

EZ_PEnc:
        mov     edi,eax
        add     edi,[edi+3Ch]
        assume edi : ptr IMAGE_NT_HEADERS
        mov     esi,edi
        add     esi,0F8h
        assume esi : ptr IMAGE_SECTION_HEADER
        xor     edx,edx
        .REPEAT
           .IF dword ptr [esi].Name1 == ('crsr')
              jmp @@LoopEnd
           .ENDIF
           .IF dword ptr [esi].Name1 == ('rsr.')
              jmp @@LoopEnd
           .ENDIF

;------ Fix section's VirtualSize if required --------------------------------
;           pushad
;           mov    eax,[esi].Misc.VirtualSize
;           cmp    eax,[esi].SizeOfRawData
;           jae    nofixrequired
;           add    eax,[esi].SizeOfRawData
;;           inc    eax
;           mov    [esi].Misc.VirtualSize,eax
;nofixrequired:
;           popad

           .IF dword ptr [esi].Name1 == ('oler')
              jmp @@LoopEnd
           .ENDIF
           .IF dword ptr [esi].Name1 == ('ler.')
              jmp @@LoopEnd
           .ENDIF
           .IF dword ptr [esi].Name1 == ('spze')
              jmp @@LoopEnd
           .ENDIF
           .IF dword ptr [esi].Name1 == ('ade.')
              jmp @@LoopEnd
           .ENDIF
           .IF [esi].PointerToRawData == 0 || [esi].SizeOfRawData == 0
              jmp @@LoopEnd
           .ENDIF

           pushad
           mov    ecx,[esi].SizeOfRawData
           .IF ebx == 0                         ; (ebx is a parameter)
              mov esi,[esi].PointerToRawData
              add esi, eax
              call EZ_EncrSC
           .ELSE
              mov  esi,[esi].VirtualAddress
              add  esi,eax
              call DecryptSec
           .ENDIF
           jmp EZ_SDclCntc1

DecryptSec:
        pushad
        jmp           eseal_menu
STARTUPINFO_          equ       4+4+4+4+4+4+4+4+4+4+4+4+2+2+4+4+4+4

aborted_authorization:
        lea     eax,[ebp+offset EZTempFileBuf]

        push    eax
        call    [ebp+_DeleteFileA]
        push    0
        call    [ebp+_ExitProcess]
        ret

;------ SERIAL GENERATION ROUTINE --------------------------------------------
generate_serial:
; Get total amount of clusters on drive C:

        lea     edx,[ebp+offset EZHDDJunkInfo]
        lea     esi,[ebp+offset EZHDDClsInfoPTH]
        lea     edi,[ebp+offset EZHDDClsAmount]

        push    edi
        push    edx
        push    edx
        push    edx
        push    esi
        call    [ebp+_GetDiskFreeSpaceA]

; Gather PC name

        lea     esi,[ebp+offset EZPCNameLen]
        lea     edi,[ebp+offset EZPCName]
        lea     edi,[ebp+offset EZPCName]

        push    esi
        push    edi
        call    [ebp+_GetComputerNameA]

; Count PCname pseudo-CRC

        lea     esi,[ebp+offset EZPCName]
        lea     edi,[ebp+offset EZPCNameCRC]
cppcrcloop:
        mov     bl,byte ptr [esi]
        cmp     bl,0
        je      cppcrcloopend
        movzx   eax,bl
        shl     dword ptr [edi],2
        add     dword ptr [edi],eax
        inc     esi
        jmp     cppcrcloop
cppcrcloopend:

        lea     edx,[ebp+offset EZHDDClsAmount]
        mov     eax,dword ptr [edi]
        xor     eax,dword ptr [edx]
        mov     dword ptr [edi],eax

        lea     eax,[ebp+offset EZPCNameCRCBAK]    ; Store NameCRC for future use
        mov     ebx,dword ptr [edi]                ; Store NameCRC for future use
        mov     dword ptr [eax],ebx                ; Store NameCRC for future use

; Acquire serial of HDD partition

        lea     eax,[ebp+offset EZHDDPartition]
        lea     edi,[ebp+offset EZSNHDDSerial]

        push    0
        push    NULL
        push    NULL
        push    NULL
        push    edi
        push    0
        push    NULL
        push    eax
        call    [ebp+_GetVolumeInformationA]

        lea     eax,[ebp+offset EZHDDSerialBAK]         ; Store HDDSerial for future use
        lea     edi,[ebp+offset EZSNHDDSerial]          ; Store HDDSerial for future use
        mov     ebx,dword ptr [edi]                     ; Store HDDSerial for future use
        mov     dword ptr [eax],ebx                     ; Store HDDSerial for future use

; Acquire random seed

        call    [ebp+_GetTickCount]
        lea     edi,[ebp+offset EZSNRndSeed]
        mov     dword ptr [edi],eax

; Encrypt SN

        lea     edx,[ebp+offset RandomNumber]
        lea     eax,[ebp+offset EZSNRndSeed]
        mov     ecx,[eax]
        mov     [edx],ecx
        lea     esi,[ebp+offset EZSerialNumber]
        lea     edi,[ebp+offset EZSNCRC]                ; Junk code
        add     esi,6
        xor     eax,eax
        xor     ecx,ecx
esnbrloop:
        call    rnd_gen
        mov     eax,[edx]
        xor     dword ptr [esi],eax
        inc     esi
        inc     ecx
        cmp     ecx,EZSNSize-6-3
        jne     esnbrloop

; Acquire SN CRC

        lea     esi,[ebp+offset EZSerialNumber]
        lea     edi,[ebp+offset EZSNCRC]
        add     esi,2
        xor     ax,ax
        xor     cx,cx
asncrcloop:
        movzx   bx,byte ptr [esi]
        add     ax,bx
        add     ax,cx
        inc     esi
        inc     cx
        cmp     cx,EZSNSize-2
        jne     asncrcloop
        mov     word ptr [edi],ax

; Translate to text

        lea     edi,[ebp+offset ESProvidedSN]
        lea     esi,[ebp+offset EZSerialNumber]
        mov     ecx,EZSNSize
sntttloop:                      ; SerialNumberToTextTranslatinLoop
        mov     al,byte ptr [esi]
        mov     ah,al
        and     ah,15
        add     ah,65
        mov     byte ptr [edi],ah
        inc     edi
        shr     al,4
        add     al,65
        mov     byte ptr [edi],al
        inc     edi
        inc     esi
        dec     ecx
        cmp     ecx,0
        jne     sntttloop

;       Fill <ESTempFileBuf> with key-file location and serial number

        lea     edi,[ebp+offset EZTempFileBuf]
        dec     edi
        ; Search for spaces or 0
sfzloop:
        inc     edi
        cmp     byte ptr [edi],0
        jne     sfzloop
        ; Write key-file name
        mov     byte ptr [edi],32
        lea     esi,[ebp+offset EZKeyFile]
        dec     esi
wkfnloop:
        inc     esi
        inc     edi
        mov     ah,byte ptr [esi]
        mov     byte ptr [edi],ah
        cmp     ah,0
        jne     wkfnloop
        ; Write serial number in temp file
        mov     byte ptr [edi],32
        lea     esi,[ebp+offset ESProvidedSN]
        dec     esi
wsnitfloop:
        inc     esi
        inc     edi
        mov     ah,byte ptr [esi]
        mov     byte ptr [edi],ah
        cmp     ah,0
        jne     wsnitfloop

        jmp     serial_generated

;------ PROCESS LOADED KEY ---------------------------------------------------
ProcessLoadedKey:

        ; Retranslate key back to normal format

        lea     esi,[ebp+offset EZExistedKey]
        lea     edi,[ebp+offset EZExistedKeyFile]
        xor     ecx,ecx
ekrbtnfloop:
        mov     bh,byte ptr [esi]
        sub     bh,65
        inc     esi
        mov     bl,byte ptr [esi]
        sub     bl,65
        shl     bl,4
        add     bl,bh
        mov     [edi],bl
        inc     esi
        inc     edi

        inc     ecx
        cmp     ecx,24
        jne     ekrbtnfloop

        ;       Decrypt it

        lea     esi,[ebp+offset EZUK_SEED]
        lea     edi,[ebp+offset RandomNumber]
        mov     eax,dword ptr [esi]
        mov     dword ptr [edi],eax
        lea     esi,[ebp+offset EZUK_CRC]
        add     esi,6
        xor     ecx,ecx
ekdiloop:
        call    rnd_gen
        mov     eax,dword ptr [edi]
        xor     dword ptr [esi],eax
        inc     esi
        inc     ecx
        cmp     ecx,15
        jne     ekdiloop

        ; Unxor all ID's
        lea     esi,[ebp+offset EZHDDSerialBAK]
        lea     edi,[ebp+offset EZUK_USER]
        mov     eax,dword ptr [esi]
        mov     ebx,dword ptr [edi]
        xor     ebx,eax
        mov     dword ptr [edi],ebx

        lea     esi,[ebp+offset EZPCNameCRCBAK]
        lea     edi,[ebp+offset EZUK_SOFTWARE]
        mov     eax,dword ptr [esi]
        xor     dword ptr [edi],eax

        ; Unxor Decryption key

        lea     esi,[ebp+offset EZHDDSerialBAK]
        lea     edi,[ebp+offset EZUK_DKEY]
        mov     eax,dword ptr [esi]
        xor     dword ptr [edi],eax
        add     edi,4
        lea     esi,[ebp+offset EZPCNameCRCBAK]
        mov     eax,dword ptr [esi]
        xor     dword ptr [edi],eax

        ; Count CRC

        xor     dx,dx                  ; CRC
        xor     cx,cx                  ; Counter

        lea     edi,[ebp+offset EZUK_SEED]
ukccacloop:
        movzx   bx,byte ptr [edi]
        add     dx,bx
        add     dx,cx
        inc     edi
        inc     cx
        cmp     cx,22
        jne     ukccacloop
        ; Check CRC

        lea     edi,[ebp+offset EZUK_CRC]
        cmp     dx,word ptr [edi]
        je      ak_validation000
        lea     edi,[ebp+offset AuthErrsAmount]
        inc     byte ptr [edi]
ak_validation000:
        ; Check for Vendor ID
        lea     esi,[ebp+offset VENDOR_ID]
        lea     edi,[ebp+offset EZUK_VENDOR]
        mov     dx,word ptr [esi]
        cmp     dx,word ptr [edi]
        je      ak_validation001
        lea     edi,[ebp+offset AuthErrsAmount]
        inc     byte ptr [edi]
ak_validation001:
        ; Check for Software ID
        lea     esi,[ebp+offset SOFTWARE_ID]
        lea     edi,[ebp+offset EZUK_SOFTWARE]
        mov     dx,word ptr [esi]
        cmp     dx,word ptr [edi]
        je      ak_validation002
        lea     edi,[ebp+offset AuthErrsAmount]
        inc     byte ptr [edi]
ak_validation002:
        ; Check for User ID
        lea     esi,[ebp+offset USER_ID]
        lea     edi,[ebp+offset EZUK_USER]
        mov     dx,word ptr [esi]
        cmp     dx,word ptr [edi]
        je      ak_validation003
        lea     edi,[ebp+offset AuthErrsAmount]
        inc     byte ptr [edi]
ak_validation003:

        lea     edi,[ebp+offset AuthErrsAmount]
        cmp     byte ptr [edi],0
        jne     AuthKeyError0
        jmp     jumpbackhere

;=============================================================================

rnd_gen:
        pushad
        mov     eax,214013
        lea     ecx,[ebp + offset RandomNumber]
        imul    dword ptr [ecx]
        sub     edx, edx                                ; Divide overflow protection
        add     eax, 2531011
        mov     dword ptr [ecx], eax
        popad
        ret

AuthFileError0:
;        lea     edx,[ebp + offset DefError0]
        jmp     AuthFileErrorOut
AuthFileError1:
;        lea     edx,[ebp + offset DefError1]
        jmp     AuthFileErrorOut
AuthFileError2:
;        lea     edx,[ebp + offset DefError2]
        jmp     AuthFileErrorOut

AuthFileErrorOut:

        lea     edx,[ebp + offset DefError]
        call    [ebp+_GetLastError]
        lea     ebx,[ebp+offset EZErrorMSGBuf]
        mov     byte ptr [ebx],0

        push    4296
        push    NULL
        push    eax
        push    0
        push    ebx
        push    128
        push    NULL
        call    [ebp+_FormatMessageA]

        push    MB_OK
        lea     eax,[ebp+offset EZErrorMSGBuf]
        push    edx
        push    eax
        push    0
        call    [ebp+_MessageBoxA]
        push    0
        call    [ebp+_ExitProcess]              ; close application

AuthKeyError0:
        push    MB_OK
        lea     eax,[ebp+offset EZAErr010]
        push    eax
        push    eax
        push    0
        call    [ebp+_MessageBoxA]

delete_wrong_key_and_restart:
        lea     edi,[ebp+offset AuthErrsAmount]
        mov     byte ptr [edi],0
        ;       Delete wrong keyfile
        lea     eax,[ebp+offset EZKeyFile]
        push    eax
        call    [ebp+_DeleteFileA]
        ;       Reset launch counter
        lea     eax,[ebp+offset EZRunTimes]
        mov     byte ptr [eax],0
        jmp     run_authorization

CRC_ERROR:
        jmp     delete_wrong_key_and_restart

;====== CODE again ===========================================================
;------ Run client software --------------------------------------------------
eseal_menu:

        lea     edx,[ebp + offset run_count]
        inc     dword ptr [edx]
        cmp     dword ptr [edx],1

        jne     proceed

        ;       Prepare key filename
        lea     eax,[ebp+offset EZKeyFile]
        push    255
        push    eax
        call    [ebp+_GetWindowsDirectoryA]
        lea     eax,[ebp+offset EZKeyFile]
kfnsloop:
        cmp     byte ptr [eax],0
        je      kfnsloopend
        inc     eax
        jmp     short kfnsloop
kfnsloopend:
        mov     edi,eax
        lea     esi,[ebp+offset EZKeyFileTmpl]
        ; eax = Pointer to file name
        lea     ebx,[ebp+offset EZUserID]
        movzx   eax,word ptr [ebx]
        push    eax
        lea     ebx,[ebp+offset EZVendorID]
        movzx   eax,word ptr [ebx]
        push    eax
        lea     ebx,[ebp+offset EZSoftwareID]
        movzx   eax,word ptr [ebx]
        push    eax
        push    esi
        push    edi
        call    [_wsprintfA+ebp]
        add     esp, 4*5

        ;       Get temp file
        lea     eax,[ebp+offset EZTempPathBuf]
        push    eax
        push    255
        call    [ebp+_GetTempPathA]
        lea     eax,[ebp+offset EZTempPathBuf]
        lea     ebx,[ebp+offset EZTempPrefix]
        lea     ecx,[ebp+offset EZTempFileBuf]
        push    ecx
        push    0
        push    ebx
        push    eax
        call    [ebp+_GetTempFileNameA]

;------ Write authorization EXE module ---------------------------------------
write_authorization_module:

        lea     eax,[ebp+offset EZTempFileBuf]
        lea     ebx,[ebp+offset EZAuthFileOS]
        push    4113
        push    ebx
        push    eax
        call    [ebp+_OpenFile]                 ; OF_SHARE_EXCLUSIVE+OF_WRITE mode
        cmp     eax,-1
        je      AuthFileError0
        lea     edi,[ebp+offset EZAuthFileH]
        mov     dword ptr [edi],eax

        lea     esi,[ebp+offset FD_authorizer_start]
        lea     edi,[ebp+offset EZAuthFileBWtn]
        push    NULL
        push    edi
        push    FD_authorizer_len
        push    esi
        push    eax
        call    [ebp+_WriteFile]
        cmp     eax,0
        je      AuthFileError1

        lea     esi,[ebp+offset EZAuthFileH]
        mov     eax,dword ptr [esi]
        push    eax
        call    [ebp+_CloseHandle]
        cmp     eax,0
        je      AuthFileError2


;------ Generate serial and run module ---------------------------------------

        jmp     generate_serial
serial_generated:

;------ Try to load existed serial
ttlesentry:

        lea     eax,[ebp+offset EZKeyFile]
        lea     ebx,[ebp+offset EZAuthFileOS]

        push    16
        push    ebx
        push    eax
        call    [ebp+_OpenFile]                 ; OF_SHARE_EXCLUSIVE+OF_READ mode

        cmp     eax,-1
        je      run_authorization               ; File not found
        lea     ebx,[ebp+offset EZEKeyFileHdl]
        mov     [ebx],eax

        lea     esi,[ebp+offset EZEKeyFileBR]
        lea     edi,[ebp+offset EZExistedKey]

        push    0
        push    esi
        push    48
        push    edi
        push    eax
        call    [ebp+_ReadFile]

        lea     esi,[ebp+offset EZEKeyFileBR]
        cmp     dword ptr [esi],48
        jne     AuthFileError2

        lea     esi,[ebp+offset EZEKeyFileHdl]
        mov     eax,dword ptr [esi]
        push    eax
        call    [ebp+_CloseHandle]

;------ Process loaded key ---------------------------------------------------

        jmp     ProcessLoadedKey
jumpbackhere:
        jmp     proceed

;------ Run authorization process --------------------------------------------
run_authorization:

        lea     eax,[ebp+offset EZRunTimes]
        cmp     byte ptr [eax],0
        jne     aborted_authorization
        inc     byte ptr [eax]

        lea     eax,[ebp+offset EZTempFileBuf]
        lea     ebx,[ebp+offset StartupInfo]
        lea     ecx,[ebp+offset ProcessInfo]
        ;       Fill startup info
        ASSUME  ebx : PTR STARTUPINFOA
        mov     [ebx].cb,STARTUPINFO_
        mov     [ebx].lpReserved,NULL
        mov     [ebx].lpDesktop,NULL
        mov     [ebx].lpTitle,NULL
        mov     [ebx].dwX,100
        mov     [ebx].dwY,100
        mov     [ebx].dwXSize,200
        mov     [ebx].dwYSize,200
        mov     [ebx].dwXCountChars,10
        mov     [ebx].dwYCountChars,10
        mov     [ebx].dwFillAttribute,0
        mov     [ebx].dwFlags,0
        mov     [ebx].wShowWindow,0
        mov     [ebx].cbReserved2,0
        mov     [ebx].lpReserved2,0
        mov     [ebx].hStdInput,NULL
        mov     [ebx].hStdOutput,NULL
        mov     [ebx].hStdError,NULL
        ASSUME  ebx : NOTHING

        push    ecx
        push    ebx
        push    NULL
        push    NULL
        push    NORMAL_PRIORITY_CLASS
        push    FALSE
        push    NULL
        push    NULL
        push    eax
        push    NULL
        call    [ebp+_CreateProcessA]

        cmp     eax,0
        je      AuthFileError0

eloop:  nop
        push    100
        call    [ebp+_Sleep]                            ; We do nothing... Why not to give some resources to the system ? ;-)

        lea     eax,[ebp+offset ProcessInfo]
        lea     ebx,[ebp+offset ProcessECode]

        push    ebx
        ASSUME  eax : PTR PROCESS_INFORMATION
        push    [eax].hProcess
        ASSUME  eax : NOTHING
        call    [ebp+_GetExitCodeProcess]

        cmp     eax,0
        je      AuthFileError0

        lea     ebx,[ebp+offset ProcessECode]
        mov     eax,dword ptr [ebx]
        cmp     eax,STILL_ACTIVE
        je      eloop
        lea     eax,[ebp+offset EZTempFileBuf]

        push    eax
        call    [ebp+_DeleteFileA]

        jmp     ttlesentry

;====== Out of here ==========================================================

proceed: nop

                popad
                mov edi,esi
        SecDecryptLoop:

       sub     ecx,4
       ;       Init random
       lea     eax,[ebp+offset RandomNumber]
       lea     esi,[ebp+offset EZUK_SSEED]
       mov     ebx,dword ptr [esi]
       mov     dword ptr [eax],ebx
       lea     ebx,[ebp+offset RandomNumber]
       lea     edx,[ebp+offset EZUK_DKEY]
       lea     esi,[ebp+offset DepackerCode]

__decrypt:
       call    rnd_gen

       ;       XOR it by code
       mov     eax,dword ptr [edi]
       xor     eax,dword ptr [esi]
       ;       XOR it by random
       xor     eax,dword ptr [ebx]
       mov     dword ptr [edi],eax
       ;       XOR it by EncryptionKey
       mov     ah,byte ptr [edx]
       xor     byte ptr [edi],ah
       inc     edx

       lea     eax,[ebp+offset EZUK_DKEY]+8
       cmp     edx,eax
       jnae    dc_dont_reset_key
       lea     edx,[ebp+offset EZUK_DKEY]
dc_dont_reset_key:

       inc     esi
       lea     eax,[ebp+offset additional_dc_password_end]
       sub     eax,4
       cmp     esi,eax
       jnae    dc_dont_reset_code_ptr
       lea     esi,[ebp+offset DepackerCode]       ; Reset code pointer
dc_dont_reset_code_ptr:
       inc     edi
       dec     ecx
       cmp     ecx,0
       jne     __decrypt
       ret

EZ_SDclCntc1:
           popad

           @@LoopEnd:
           add esi,SIZEOF IMAGE_SECTION_HEADER
           inc edx
        .UNTIL dx == [edi].FileHeader.NumberOfSections
        assume esi : nothing
        assume edi : nothing
        ret

EZ_ADclPrcd:

        mov     ebx, [EBP+dwImageBase]
        add     ebx, [EBP+dwOrgEntryPoint]
        ROR     ebx, 7
        mov     [ESP+010h], ebx
        lea     ebx, [EBP+OFFSET SehHandler_OEP_Jump]
        mov     [ESP+01Ch], ebx

;------ Check for TLS --------------------------------------------------------

        mov     edi,[ebp+dwImageBase]
        add     edi,dword ptr [edi+03Ch]
        assume edi : ptr IMAGE_NT_HEADERS
        mov     ebx,[edi].OptionalHeader.DataDirectory[SIZEOF IMAGE_DATA_DIRECTORY * 9].VirtualAddress
        assume edi : nothing
        cmp     ebx,0
        jz      SkipTlsFix
        add     ebx,[ebp+dwImageBase]
        assume ebx : ptr IMAGE_TLS_DIRECTORY32
        mov     eax,[ebx].AddressOfIndex
        mov     dword ptr [eax],0
        assume ebx : nothing

  SkipTlsFix:
        mov eax,[ebp+EZ_RsCRC]
        .IF eax != 0
           .IF eax != [ebp+EZ_OCRC]
              jmp SkipInitIt
           .ENDIF
        .ENDIF

        lea esi, [EBP+OFFSET IIDInfo]
        ASSUME esi : PTR sItInfo

;------ API redirection ------------------------------------------------------
        TEST [EBP+EZ_CFlags], EZ_CFlag_RAPI
        .IF !ZERO?
           push esi
           lea  edi, [EBP+OFFSET Buff]
           ASSUME edi : PTR sReThunkInfo
           xor  ecx, ecx
           .WHILE [esi].FirstThunk
              mov  edx, [esi].FirstThunk
              add  edx, [EBP+dwImageBase]
              .WHILE DWORD PTR [edx]
                 inc  ecx
                 add  edx, 4
              .ENDW
              add  esi, SIZEOF sItInfo
           .ENDW
           xor  edx, edx
           mov  eax, SIZEOF sApiStub
           MUL  ecx
           push eax
           push GMEM_FIXED
           call [EBP+_GlobalAlloc]
           .IF !eax
              add  ESP, 4
              popad
              ret
           .ENDIF
           mov  [edi].ApiStubMemAddr, eax
           mov  [edi].pNextStub, eax
           ASSUME edi : NOTHING
           pop  esi
        .ENDIF

        .WHILE [esi].FirstThunk != 0
           mov ebx,[esi].DllNameRVA
           add ebx,[ebp+dwImageBase]

           mov eax,ebx
           call EZ_PRTStr
           lea eax, [EBP+InitITContinue1]
           push eax
           ret

EZ_PRTStr:
           push  esi
           push  edi
           mov   esi,eax
           mov   edi,eax
DllCryptLoop:
           lodsb
           ror   al,4
           stosb
           cmp   BYTE PTR [edi],0
           jnz   DllCryptLoop
           pop   edi
           pop   esi
           ret

InitITContinue1:
           push  ebx
           call  [ebp+_LoadLibrary]
           test  eax,eax
           jz    SkipInitIt

           push  eax
           test  [ebp+EZ_CFlags],EZ_CFlag_DII
           jz    EZ_DLLNNrmv
           lea   eax, [EBP+OFFSET EZ_DLLNNrmv]
           push  eax
           mov   eax, ebx
           jmp   KillString
EZ_DLLNNrmv:
           pop   ebx

           mov ecx,[esi].OrgFirstThunk
           .IF ecx == 0
              mov ecx,[esi].FirstThunk
           .ENDIF
           add ecx,[ebp+dwImageBase]
           mov edx,[esi].FirstThunk
           add edx,[ebp+dwImageBase]
           .WHILE dword ptr [ecx] != 0
              test dword ptr [ecx],IMAGE_ORDINAL_FLAG32
              jnz @@OrdinalImp

              mov       dword ptr eax,[ecx]
              add       eax,2
              add       eax,[ebp+dwImageBase]
              push      eax
              call      EZ_PRTStr
              pop       eax
              mov       edi,eax
              push      edx
              push      ecx
              push      eax
              push      ebx
              call [ebp+_GetProcAddress]
              .IF eax == NULL
                  pop    ecx
                  pop    edx
                  jmp    SkipInitIt
              .ENDIF
              pop   ecx
              pop   edx
              pushad
              test  [ebp+EZ_CFlags],EZ_CFlag_DII
              JZ    DontKillApiName
              lea   eax, [EBP+OFFSET DontKillApiName]
              push  eax
              mov   eax, edi
              jmp   KillString
   DontKillApiName:
              popad
              mov dword ptr [edx],eax
              jmp @@NextThunkPlease

   @@OrdinalImp:
              push edx
              push ecx
              mov dword ptr eax,[ecx]
              sub eax,080000000h
              push eax
              push ebx
              call [ebp+_GetProcAddress]
              test eax,eax
              jz SkipInitIt
              pop ecx
              pop edx
              mov dword ptr [edx],eax

   @@NextThunkPlease:
              ; eax = Current Api address
              ; ebx = dll base
              ; edx = non-org thunk pointer
              TEST [EBP+EZ_CFlags], EZ_CFlag_RAPI
              .IF !ZERO?
                 .IF [EBP+bNT]
                     .IF ebx < 070000000h || ebx > 077FFFFFFh
                         jmp SkipThunkRed
                     .ENDIF
                 .ELSE
                     .IF ebx < 080000000h
                         jmp SkipThunkRed
                     .ENDIF
                 .ENDIF
                 push edi
                 push esi
                 lea  edi, [EBP+Buff]
                 ASSUME edi : PTR sReThunkInfo
                 mov  esi, [edi].pNextStub
                 mov  [edx], esi
                 sub  eax, esi
                 sub  eax, 5
                 mov  BYTE PTR [esi], 0E9h
                 mov  DWORD PTR [esi+1], eax
                 add  [edi].pNextStub, SIZEOF sApiStub
                 ASSUME edi : NOTHING
                 pop  esi
                 pop  edi
           SkipThunkRed:
              .ENDIF

              add ecx,4
              add edx,4
           .ENDW
           add esi,SIZEOF sItInfo
        .ENDW
        assume esi:nothing
        xor eax,eax
        inc eax
SkipInitIt:

        .IF eax != TRUE
           popad
           ret
        .ENDIF

;------ Remove header --------------------------------------------------------

        test    [ebp+EZ_CFlags],EZ_CFlag_EH
        jz      SkipEraseHeader

        mov     edi,[ebp+dwImageBase]
        add     edi,[edi+03Ch]
        assume edi : ptr IMAGE_NT_HEADERS
        mov     ecx,[edi].OptionalHeader.SizeOfHeaders
        mov     esi,[ebp+dwImageBase]
        assume edi : nothing
ZeroMemLoop:
        mov     byte ptr [esi],0
        inc     esi
        loop    ZeroMemLoop
SkipEraseHeader:

;------ One more CRC check ---------------------------------------------------

        lea     eax, [EBP+DepackerCode]
        mov     ecx, EZ_EZCRCcs
        jmp     SM10
        DB      0E9h
SM10:   call    EZ_CLCCRC
        jmp     SM11
        DB      0C7h
SM11:   mov     ebx, [EBP+EZ_EZCRC]
        xor     eax, ebx
        .IF !ZERO?
            jmp SM12
            DB  02Ch
            SM12: popad
            jmp SM13
            DB  0E8h
            SM13: ret
        .ENDIF

;------ Decrypt EP jump code -------------------------------------------------

        lea     edi, [EBP+OFFSET OEP_JUMP_CODE_START]
        mov     esi, edi
        mov     ecx, EZ_LL_OEPjs
        xor     ebx, ebx
OepJumpDecryptLoop:
        LODSB
        xor     al, EZ_OEPjen
        sub     al, BL
        rol     al, 2
        stosb
        inc     ebx
        loop    OepJumpDecryptLoop

OEP_JUMP_CODE_START:

;------ Debuggers check with API ---------------------------------------------

        lea     eax, [EBP+OFFSET szIsDebuggerPresent]
        push    eax
        push    [EBP+dwKernelBase]
        call    [EBP+_GetProcAddress]
        or      eax, eax
        .IF !ZERO?
            call eax
            or   eax, eax
            .IF  !ZERO?
                 popad
                 ret
            .ENDIF
        .ENDIF

;------ Last SoftICE check ---------------------------------------------------

        TEST    [EBP+EZ_CFlags], EZ_CFlag_ASice
        JZ      SkipSICheck2
        lea     esi,[EBP+SEH]
        ASSUME esi : PTR sSEH
        lea     eax, [EBP+OFFSET SICheck2_SP]
        mov     [esi].SaveEip, eax
        ASSUME esi : NOTHING
        xor     ebx, ebx
        lea     eax, [EBP+OFFSET SEH_Hnd2]
        push    eax
        push    FS:[ebx]
        mov     FS:[ebx], ESP
        mov     edi, EBP

        mov     eax, 4400h
        jmp     SM4
        DB      0C7h
SM4:    INT     68h
SICheck2_SP:
        xor     ebx, ebx
        pop     FS:[ebx]
        add     ESP, 4

        .IF DI == 01297h || DI == 01277h || DI == 01330h
            jmp SM5
            DB 0FFh
            SM5: popad
            jmp SM6
            DB 0E8h
            SM6: ret
        .ENDIF
SkipSICheck2:

        lea     eax, [EBP+OFFSET OepJumpCodeCont]
        push    eax
        ret

;------ Structural Exception Handler -----------------------------------------

SehHandler_OEP_Jump PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD

        push    edi
        mov     eax,pContext
        ASSUME eax : PTR CONTEXT

        mov     edi, [eax].regEsp
        push    [edi]
        xor     edi, edi
        pop     FS:[edi]

        add     [eax].regEsp, 8

        ; set EIP to the OEP

        mov     edi, [eax].regEbx
        rol     edi, 7
        mov     [eax].regEip, edi

        mov     eax,ExceptionContinueExecution
        ASSUME eax : NOTHING
        pop     edi
        ret
SehHandler_OEP_Jump ENDP

OepJumpCodeCont:
;------ Remove protector -----------------------------------------------------

        xor     al,al
        lea     edi, [EBP+OFFSET DepackerCode]
        mov     ecx, (OFFSET SehHandler_OEP_Jump - OFFSET DepackerCode)
LoaderZeroLoop:
        stosb
        loop    LoaderZeroLoop

        lea     edi, [EBP+OFFSET OEP_JUMP_CODE_END]
        mov     ecx, (OFFSET LOADER_CRYPT_END - OFFSET OEP_JUMP_CODE_END)
LoaderVarZeroLoop:
        stosb
        loop    LoaderVarZeroLoop

        popad

        push    eax
        xor     eax, eax
        push    FS:[eax]
        mov     FS:[eax], ESP

        jmp     SM3
        DB   087H
SM3:
OEP_JUMP_CODE_END:

; eax = ASCII string address
KillString:
        .WHILE byte ptr [eax] != 0
           mov byte ptr [eax],0
           inc eax
        .ENDW
        ret

SEH_Hnd1 PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
        push    edi
        mov     eax,pContext
        ASSUME eax : PTR CONTEXT
        mov     edi, [eax].regEdi
        push    [edi+SEH.SaveEip]
        pop     [eax].regEip
        mov     [eax].regEbp, edi
        mov     [eax].regEax, 4            ; SI NOT detected !
        mov     eax,ExceptionContinueExecution
        ASSUME eax : NOTHING
        pop     edi
        ret
SEH_Hnd1 ENDP

SEH_Hnd2 PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
        push    edi
        mov     eax,pContext
        ASSUME eax : PTR CONTEXT
        mov     edi, [eax].regEdi
        push    [edi+SEH.SaveEip]
        pop     [eax].regEip
        mov     [eax].regEbp, edi
        mov     [eax].regEdi, 0            ; SI NOT detected !
        mov     eax,ExceptionContinueExecution
        ASSUME eax : NOTHING
        pop     edi
        ret
SEH_Hnd2 ENDP

additional_dc_password_end:

sItInfo STRUCT
        DllNameRVA       dd ?
        FirstThunk       dd ?
        OrgFirstThunk    dd ?
sItInfo ENDS

sSEH STRUCT
        OrgEsp           dd ?
        OrgEbp           dd ?
        SaveEip          dd ?
sSEH ENDS

sReThunkInfo STRUCT
        ApiStubMemAddr   DD ?
        pNextStub        DD ?
sReThunkInfo ENDS

sApiStub STRUCT
        JumpOpc          DB ?
        JumpAddr         DD ?
sApiStub ENDS

dwImageBase             dd 0
dwOrgEntryPoint         dd 0
EZ_CFlags               dd 0
EZ_RsCRC                dd 0
EZ_EZCRC                dd 0
bNT                     dd 0

IIDInfo                 db (SIZEOF sItInfo * EZ_MaxIIDAmnt) dup (0)

SEH                     sSEH <0>

_LoadLibrary            dd 0
_GetProcAddress         dd 0

; Kernel32 api entries
szKernel32              db "Kernel32.dll",0
dwKernelBase            dd 0
szGetModuleHandle       db "GetModuleHandleA",0
_GetModuleHandle        dd 0
szVirtualProtect        db "VirtualProtect",0
_VirtualProtect         dd 0
szGetModuleFileName     db "GetModuleFileNameA",0
_GetModuleFileName      dd 0
szCreateFile            db "CreateFileA",0
_CreateFile             dd 0
szGlobalAlloc           db "GlobalAlloc",0
_GlobalAlloc            dd 0
szGlobalFree            db "GlobalFree",0
_GlobalFree             dd 0
szReadFile              db "ReadFile",0
_ReadFile               dd 0
szGetFileSize           db "GetFileSize",0
_GetFileSize            dd 0
szCloseHandle           db "CloseHandle",0
_CloseHandle            dd 0
szGetWindowsDirectoryA  db "GetWindowsDirectoryA",0
_GetWindowsDirectoryA   dd 0
szGetTempPathA          db "GetTempPathA",0
_GetTempPathA           dd 0
szGetTempFileNameA      db "GetTempFileNameA",0
_GetTempFileNameA       dd 0
szOpenFile              db "OpenFile",0
_OpenFile               dd 0
szWriteFile             db "WriteFile",0
_WriteFile              dd 0
szGetLastError          db "GetLastError",0
_GetLastError           dd 0
szFormatMessageA        db "FormatMessageA",0
_FormatMessageA         dd 0
szGetDiskFreeSpaceA     db "GetDiskFreeSpaceA",0
_GetDiskFreeSpaceA      dd 0
szGetComputerNameA      db "GetComputerNameA",0
_GetComputerNameA       dd 0
szGetTickCount          db "GetTickCount",0
_GetTickCount           dd 0
szGetVolumeInformationA db "GetVolumeInformationA",0
_GetVolumeInformationA  dd 0
szCreateProcessA        db "CreateProcessA",0
_CreateProcessA         dd 0
szSleep                 db "Sleep",0
_Sleep                  dd 0
szGetExitCodeProcess    db "GetExitCodeProcess",0
_GetExitCodeProcess     dd 0
szDeleteFileA           db "DeleteFileA",0
_DeleteFileA            dd 0
szExitProcess           db "ExitProcess",0
_ExitProcess            dd 0

szIsDebuggerPresent     db "IsDebuggerPresent",0
_IsDebuggerPresent      dd 0

; User32 api entries
szUser32                db "User32.dll",0
dwUserBase              dd 0
szMessageBoxA           db "MessageBoxA",0
_MessageBoxA            dd 0
szwsprintfA             db "wsprintfA",0
_wsprintfA              dd 0
                        dd 0

;====== E-zapper loader data =================================================

;TestingMessage  db "This is just a stupid string :)",0

AuthErrsAmount  db 0
EZRunTimes      db 0
DataDecSeed     dd 0            ; Data decryption seed
RandomNumber    dd 0
run_count       dd 0            ; To avoid mulpiple running

EZHDDClsAmount  dd 0            ; Amount of clusters on disk (PC_NAME crc will be xored by this)
EZHDDJunkInfo   dd 0

EZErrorState    dd 0

ESProvidedSN    db     64  dup(0)
EZPCName        db     32  dup(0)
EZPCNameLen     dd     31

EZEKeyFileHdl   dd     0 ; File handle
EZEKeyFileBR    dd     0 ; Bytes readed

EZAuthFileBWtn  dd     0        ; Bytes writen
EZPrcName       db 'es.tmp',0
EZTempPrefix    db 'esl',0      ; Three bytes
EZHDDPartition  db 'C:\',0
EZHDDClsInfoPTH db 'C:',0       ; Root pathname for GetFreeDiskSpace
EZDecryptionKey db 8 dup (0)    ; Filled from supplied UnlockKey
EZKeyFileTmpl   db "\%x%x%x.esk",0 ;PATH SOFTWARE_ID VENDOR_ID USER_ID
EZAErr010       db "Incorrect authorization key",0
DefError        db "Error",0
EZErrorMSGBuf   db 256 dup(0)
EZKeyDirBuf     db 256 dup(0)
EZTempPathBuf   db 256 dup(0)
EZTempFileBuf   db MAX_PATH+256 dup(0)
EZKeyFile       db 256 dup(0)

ProcessInfo     PROCESS_INFORMATION     <?>
StartupInfo     STARTUPINFO             <?>
ProcessECode    dd ?

EZAuthFileH     dd     0
EZAuthFileOS    db     OFSTRUCT_ dup (0)

; Authorizer module
include                 a_rizer.inc

;====== End of data ==========================================================

LOADER_CRYPT_END:

EZHDDSerialBAK  dd 0
EZPCNameCRCBAK  dd 0

EZExistedKey    db 64  dup(0)   ; Actual key length is 48 bytes

EZSerialNumber:
;============== SERIAL SUBMITTED TO VENDOR
EZSNCRC         dw 0            ; Pseudo-CRC of the encrypted SerialNumber
EZSNRndSeed     dd 0            ; Random seed used to encrypt SerialNumber
EZSNHDDSerial   dd 0
EZPCNameCRC     dd 0
EZUserID        dw 0
EZSoftwareID    dw 0
EZVendorID      dw 0
EZEncryptorID   dd 0
;============== END
EZSNSize        equ     24

EZExistedKeyFile:
;============== EXISTED ON HDD AUTHORIZATION KEY
EZUK_CRC        dw 0            ; CRC of the decrypted key
EZUK_SEED       dd 0            ; Random seed for key decryption
EZUK_SSEED      dd 0            ; Random seed for program decryption
EZUK_USER       dw 0            ; USER_ID of the key
EZUK_SOFTWARE   dw 0            ; SOFTWARE_ID of the key
EZUK_VENDOR     dw 0            ; VENDOR_ID of the key
EZUK_DKEY       db 8 dup(0)     ; Decryption key
;============== END
EZUKSize        equ     24
db              0

; This variables won't be crypted:
USER_ID                 dw 0    ; Constant data
SOFTWARE_ID             dw 0    ; Constant data
VENDOR_ID               dw 0    ; Constant data

TlsBackupLabel:
TlsBackup               IMAGE_TLS_DIRECTORY32 <0>

ChecksumLabel:
EZ_OCRC                 dd 0

Buff                    db 0

DepackerCodeEnd:

end main

