.386
.model flat,stdcall
option casemap:none
WinMain proto :DWORD,:DWORD,:DWORD,:DWORD
include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib

.data
MSGENB                  db "Enabled",0
MSGDB                   db "Disabled",0
WindowCLSName           db "E_seal_wnd",0
ApplicationName         db "E-zapper (c) E-genia",0
ButtonCLSName           db "button",0         ; Done button
StaticCLSName           db "static",0
WriteTextMessage        db "Writing file...",0
RegBTNText              db "Register",0
QuitBTNText             db "Quit",0
EditCLSName             db "edit",0
SNEditDefText           db "Serial number",0
UKEditDefText           db 0
SNInfoText              db "Serial number :",0
UKInfoText              db "Authorization key :",0
CmdArgumentsAmount      dd 0

FileOFStruct            db OFSTRUCT dup (0)
FileHandle              dd 0
FileBytesWritten        dd 0

.data?
hInstance               HINSTANCE       ?
CommandLine             LPSTR           ?
RegButtonHwnd           HWND            ?
QuitButtonHwnd          HWND            ?
SNEditHwnd              HWND            ?
UKEditHwnd              HWND            ?
SNInfoHwnd              HWND            ?
UKInfoHwnd              HWND            ?
CmdParms                db 1024 dup(?)  ; 196 per argument (max 3 arguments)
NewArgFlag              dd ?
ResSN                   dd 128 dup(?)   ; Resulting serial number (with minuses)
buffer                  db 256 dup(?)
OutSerial               db 256 dup(?)
Shit                    dd ?

.const
StaticID                equ 1
SNEditID                equ 3
UKEditID                equ 4
RButtonID               equ 5
QButtonID               equ 6
SNInfoID                equ 7
UKInfoID                equ 8
IDM_HELLO               equ 1
IDM_CLEAR               equ 2
IDM_GETTEXT             equ 3
IDM_EXIT                equ 4

WND_WIDTH               equ 550

.code
start:
        invoke  GetModuleHandle, NULL
        mov     hInstance,eax
        invoke  GetCommandLine
        mov     CommandLine,eax
        call    SolveCMDLine
        invoke  WinMain, hInstance,NULL,CommandLine, SW_SHOWDEFAULT
        invoke  ExitProcess,eax

WinMain proc    hInst:HINSTANCE,hPrevInst:HINSTANCE,CmdLine:LPSTR,CmdShow:DWORD
        LOCAL   wc:WNDCLASSEX
        LOCAL   msg:MSG
        LOCAL   hwnd:HWND
        mov     wc.cbSize,SIZEOF WNDCLASSEX
        mov     wc.style, CS_HREDRAW or CS_VREDRAW
        mov     wc.lpfnWndProc, OFFSET WndProc
        mov     wc.cbClsExtra,NULL
        mov     wc.cbWndExtra,NULL
        push    hInst
        pop     wc.hInstance
        mov     wc.hbrBackground,COLOR_BTNFACE+1
        mov     wc.lpszMenuName,NULL
        mov     wc.lpszClassName,OFFSET WindowCLSName
        invoke  LoadIcon,NULL,IDI_APPLICATION
        mov     wc.hIcon,eax
        mov     wc.hIconSm,eax
        invoke  LoadCursor,NULL,IDC_ARROW
        mov     wc.hCursor,eax
        invoke  RegisterClassEx, addr wc
        INVOKE  CreateWindowEx,WS_EX_TOOLWINDOW or WS_EX_TOPMOST,ADDR WindowCLSName,ADDR ApplicationName,\
                 0,CW_USEDEFAULT,\
                 CW_USEDEFAULT,WND_WIDTH,170,NULL,NULL,\
                 hInst,NULL
        mov     hwnd,eax
        INVOKE  ShowWindow, hwnd,SW_SHOWNORMAL
        INVOKE  UpdateWindow, hwnd
        .WHILE  TRUE
                INVOKE GetMessage, ADDR msg,NULL,0,0
                .BREAK .IF (!eax)
                INVOKE TranslateMessage, ADDR msg
                INVOKE DispatchMessage, ADDR msg
        .ENDW
        mov     eax,msg.wParam
        ret
WinMain endp

WndProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
        .IF uMsg==WM_DESTROY
                invoke PostQuitMessage,NULL
        .ELSEIF uMsg==WM_CREATE
                invoke CreateWindowEx,WS_EX_STATICEDGE, ADDR EditCLSName,NULL,\
                        WS_CHILD or WS_VISIBLE or ES_READONLY or ES_CENTER or ES_LEFT or\
                        ES_AUTOHSCROLL,\
                        8,28,WND_WIDTH-24,20,hWnd,SNEditID,hInstance,NULL
                mov  SNEditHwnd,eax
                invoke SetWindowText,SNEditHwnd,offset ResSN

                invoke CreateWindowEx,WS_EX_STATICEDGE, ADDR EditCLSName,NULL,\
                        WS_CHILD or WS_VISIBLE or ES_UPPERCASE or ES_CENTER or ES_LEFT or\
                        ES_AUTOHSCROLL,\
                        8,84,WND_WIDTH-24,20,hWnd,UKEditID,hInstance,NULL
                mov    UKEditHwnd,eax
                invoke SetWindowText,UKEditHwnd,ADDR UKEditDefText
                invoke SendMessage,UKEditHwnd,EM_LIMITTEXT,48+7,0

                invoke CreateWindowEx,0, ADDR EditCLSName,NULL,\
                       ES_READONLY or WS_CHILD or WS_VISIBLE or ES_CENTER,
                       8,8,WND_WIDTH-24,20,hWnd,SNInfoID,hInstance,NULL
                mov    SNInfoHwnd,eax
                invoke SetWindowText,SNInfoHwnd,ADDR SNInfoText

                invoke CreateWindowEx,0, ADDR EditCLSName,NULL,\
                       ES_READONLY or WS_CHILD or WS_VISIBLE or ES_CENTER,
                       8,64,WND_WIDTH-24,20,hWnd,UKInfoID,hInstance,NULL
                mov    UKInfoHwnd,eax
                invoke SetWindowText,UKInfoHwnd,ADDR UKInfoText

                invoke CreateWindowEx,NULL, ADDR ButtonCLSName,ADDR RegBTNText,\
                        WS_CHILD or WS_VISIBLE or BS_FLAT,\
                        ((WND_WIDTH/2)-150)/2,112,150,25,hWnd,RButtonID,hInstance,NULL
                mov    RegButtonHwnd,eax
                invoke EnableWindow,RegButtonHwnd,0

                invoke CreateWindowEx,NULL, ADDR ButtonCLSName,ADDR QuitBTNText,\
                        WS_CHILD or WS_VISIBLE or BS_FLAT,\
                        ((WND_WIDTH/2)-150)/2+WND_WIDTH/2,112,150,25,hWnd,QButtonID,hInstance,NULL
                mov    QuitButtonHwnd,eax

        .ELSEIF uMsg==WM_COMMAND
                mov eax,wParam
                .IF lParam==0
                        .IF ax==IDM_HELLO
                                invoke SetWindowText,SNEditHwnd,ADDR SNEditDefText
                                invoke SendMessage,SNEditHwnd,WM_KEYDOWN,VK_END,NULL
                        .ELSEIF ax==IDM_CLEAR
                                invoke SetWindowText,SNEditHwnd,NULL
                        .ELSEIF  ax==IDM_GETTEXT
                        .ELSE
                                invoke DestroyWindow,hWnd
                        .ENDIF
                .ELSE
                        .IF ax==UKEditID
                            mov ebx,eax
                            shr ebx,16
                            .IF ebx==EN_CHANGE
                                call validate_key
                                .endif
                            .endif
                        .IF ax==QButtonID
                            invoke ExitProcess,0
                            .endif
                        .IF ax==RButtonID
                            mov ebx,eax
                            shr ebx,16
                                .IF ebx==BN_CLICKED
                                invoke OpenFile,offset CmdParms+196,offset FileOFStruct,OF_CREATE+OF_WRITE
                                mov FileHandle,eax
                                invoke WriteFile,eax,offset OutSerial,48,offset FileBytesWritten,NULL
                                invoke CloseHandle,FileHandle
                                invoke ExitProcess,0
                                .ENDIF
                        .ENDIF
                .ENDIF
        .ELSE
                invoke DefWindowProc,hWnd,uMsg,wParam,lParam
                ret
        .ENDIF
        xor    eax,eax
        ret
WndProc endp

SolveCMDLine:

        mov     esi,eax
        mov     edi,offset CmdParms
        mov     bh,[esi]                ; bh  - char from CMD line
        xor     ecx,ecx                 ; ecx - Number of arguments
        xor     bl,bl                   ; bl  - 'SPACE' flag

        .while  bh != 0
                .if bh == 32
                    .if bl == 0
                        mov   bh,0
                        mov   [edi],bh
                        inc   ecx
                        mov   ax,196
                        cwde
                        mul   ecx
                        mov   edi,offset CmdParms
                        add   edi,eax
                        mov   bl,1
                    .endif
                .else
                    mov bl,0
                    mov [edi],bh
                    inc edi
                .endif
                inc esi
                mov bh,[esi]
        .endw
        mov [edi],bh

        mov esi,offset CmdParms+196*2
        mov edi,offset ResSN
        xor ecx,ecx
        .while byte ptr [esi] != 0
               .if  ecx==6
                    mov byte ptr [edi],45
                    inc edi
                    xor ecx,ecx
                    .endif
               mov  ah,byte ptr [esi]
               mov  byte ptr [edi],ah
               inc  edi
               inc  ecx
               inc  esi
        .endw
        mov  ah,byte ptr [esi]
        mov  byte ptr [edi],ah
        ret

validate_key:
        mov     edi,offset buffer
        mov     word ptr [edi],255
        invoke  SendMessage,UKEditHwnd,EM_GETLINE,0,edi ; Line is stored in buffer
        mov     esi,offset buffer
        mov     edi,offset OutSerial
        xor     ecx,ecx    ; Amount of symbols

        .while  byte ptr [esi]!=0
                .if byte ptr [esi]>=65 && byte ptr [esi]<=80
                    mov bh,byte ptr [esi]
                    mov byte ptr [edi],bh
                    inc ecx
                    inc edi
                .endif
                inc esi
        .endw
        mov byte ptr [edi],0
        cmp     ecx,48
        jne     vk_wrong
        invoke  EnableWindow,RegButtonHwnd,1
        ret
vk_wrong:
        invoke  EnableWindow,RegButtonHwnd,0
        ret
end start
