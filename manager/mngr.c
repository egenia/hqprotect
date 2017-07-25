#define  __VENDOR_ID    0x48A7          // <-- Unique for every Vendor
#define  __ENCR_ID      0x1128

#include "stdafx.h"
#include "resource.h"

#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <direct.h>

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>

#include "manager.h"

#define FLAG_NONE       0
#define FLAG_REMOVEH    1
#define FLAG_RAPI       2
#define FLAG_ASICE      4
#define FLAG_CRC        8
#define FLAG_DIMPORTS   16

#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"comdlg32.lib")

HWND            nu_hwnd;

LPTSTR          cmd_line;
LVCOLUMN        ListColumn;
LVITEM          ListItem;
unsigned int    i,spack_flag;
char            txt_buff[512];

struct  {
        signed int              selected;       // Selected program
        signed int              selected_user;
        } EZM;

typedef struct {
        char                    user_name[128];
        unsigned short          user_id;
        _int64                  dc_key;
        int                     r_seed;
        unsigned char           reserved[32];
        } USER_ITEM_DEF;

typedef struct {
        char                    desc[128];
        char                    path[256];
        unsigned short          sw_id;          // Software ID

        unsigned short          users_amount;
        USER_ITEM_DEF           *user;
        unsigned char           cflags;         // Control flags
        unsigned char           reserved[3];
        } PROGRAM_ITEM_DEF;

struct  {
        unsigned int            amount;
        PROGRAM_ITEM_DEF        *data;
        } Programs;

#pragma pack(1)

struct  {
        char            filename[255];
        unsigned char   flags;
        unsigned short  USER_ID;
        unsigned short  SOFTWARE_ID;
        unsigned short  VENDOR_ID;
        unsigned int    RND_SEED;
        unsigned int    ENCR_ID;        // Encryptor version
        _int64          ENCR_KEY;       // Key used to encrypt data
        } KEY_FILE;

struct  {
        unsigned short  CRC;
        unsigned int    RSEED;
        unsigned int    HDD_SERIAL;
        unsigned int    PN_CRC;         // PC-Name crc
        unsigned short  USER;
        unsigned short  SOFTWARE;
        unsigned short  VENDOR;
        unsigned int    ENC_ID;
        } SERIAL;

struct  {
        unsigned short  CRC;
        unsigned int    KEY_SEED;
        unsigned int    PROGRAM_SEED;
        unsigned short  USER;
        unsigned short  SOFTWARE;
        unsigned short  VENDOR;
        _int64          DECRYPTION_KEY;
        } A_KEY;

struct  {
        unsigned int    id;
        unsigned int    sw_amount;      // Registered software amount
        } DB_HEADER;

#pragma pack()

void    AddUser(int software_number,char *UserName);
void    RefreshUsers();
void    SwitchToProgram(int p_num);

unsigned int            rnum;

void    ProtectExe()
        {
        int                     i1,pstatus;
        char                    outfname[256];
        char                    prot_name[256];
        FILE                    *infile,*outfile;
        unsigned char           *tdata;
        STARTUPINFO             sinfo;
        PROCESS_INFORMATION     pinfo;

        infile=fopen(Programs.data[EZM.selected].path,"rb");
        if (infile==NULL) {
           MessageBox(NULL,"Impossible d'ouvrir le fichier","HQ-Protect personnel",MB_OK);
           return;
           }
        tdata=(unsigned char *)malloc(filelength(fileno(infile)));
        fread(tdata,filelength(fileno(infile)),1,infile);

        i=strlen(Programs.data[EZM.selected].path)-1;
        i1=0;
        while (Programs.data[EZM.selected].path[i]!=92&&i>0)
              i--;
        if (Programs.data[EZM.selected].path[i]==92)
           i++;
        while (Programs.data[EZM.selected].path[i]!=0) {
              outfname[i1]=Programs.data[EZM.selected].path[i];
              i1++;
              i++;
              }
        outfname[i1]=0;

        if (spack_flag==0) {
           sprintf(txt_buff,"%sresult\\%s",cmd_line,outfname);
           } else {
           sprintf(txt_buff,"%sresult\\spack_%d",cmd_line,spack_flag);
           _mkdir(txt_buff);
           sprintf(txt_buff,"%sresult\\spack_%d\\%s",cmd_line,spack_flag,outfname);
           spack_flag++;
           }

        outfile=fopen(txt_buff,"wb");
        if (outfile==NULL) {
           fclose(infile);
           free(tdata);
           MessageBox(NULL,txt_buff,"Impossible d'ouvrir le fichier de sortie...",MB_OK);
           return;
           } else {
           fwrite(tdata,filelength(fileno(infile)),1,outfile);
           }
        fclose(infile);
        fclose(outfile);
        free(tdata);

        strcpy(KEY_FILE.filename,txt_buff);
        KEY_FILE.USER_ID=Programs.data[EZM.selected].user[EZM.selected_user].user_id;
        KEY_FILE.SOFTWARE_ID=Programs.data[EZM.selected].sw_id;
        KEY_FILE.VENDOR_ID=__VENDOR_ID;
        KEY_FILE.RND_SEED=Programs.data[EZM.selected].user[EZM.selected_user].r_seed;
        KEY_FILE.ENCR_ID=__ENCR_ID;
        KEY_FILE.ENCR_KEY=Programs.data[EZM.selected].user[EZM.selected_user].dc_key;
        KEY_FILE.flags=Programs.data[EZM.selected].cflags;

        sprintf(outfname,"%senc_in.dta",cmd_line);
        outfile=fopen(outfname,"wb");
        if (outfile==NULL) {
           MessageBox(NULL,"Impossible d'écrire le fichier de contrôle","HQ-Protect personnel",MB_OK);
           return;
           }
        fwrite(&KEY_FILE,sizeof(KEY_FILE),1,outfile);
        fclose(outfile);

        sinfo.cb=sizeof(STARTUPINFO);
        sinfo.lpReserved=NULL;
        sinfo.lpDesktop=NULL;
        sinfo.lpTitle=NULL;
        sinfo.dwX=100;
        sinfo.dwY=100;
        sinfo.dwXSize=200;
        sinfo.dwYSize=200;
        sinfo.dwXCountChars=80;
        sinfo.dwYCountChars=25;
        sinfo.dwFillAttribute=0;
        sinfo.dwFlags=0;
        sinfo.wShowWindow=0;
        sinfo.cbReserved2=0;
        sinfo.lpReserved2=0;
        sinfo.hStdInput=NULL;
        sinfo.hStdOutput=NULL;
        sinfo.hStdError=NULL;

        sprintf(prot_name,"%sprot.exe",cmd_line);
        CreateProcess(NULL,prot_name,NULL,NULL,FALSE,0,NULL,cmd_line,&sinfo,&pinfo);
        while (!GetExitCodeProcess(pinfo.hProcess,&pstatus)) {
              Sleep(100);
              }
        Sleep(100);
        sprintf(outfname,"%senc_in.dta",cmd_line);
        remove(outfname);
        Sleep(100);             // Have to wait some time because of WriteCache in windows
        }

void    CreateSPack()
        {
        int sp_amount,sp_i;

        SendDlgItemMessage(md_hwnd,IDC_EDIT2,EM_GETLINE,0,(LPARAM)(&txt_buff[0]));
        sp_amount=atoi(txt_buff);
        if (sp_amount<=3) {
           MessageBox(NULL,"Spécifiez au minimum 4 copies","HQ-Protect personnel",MB_OK);
           return;
           }
        if (sp_amount+Programs.data[EZM.selected].users_amount>32768) {
           MessageBox(NULL,"Un maximum de 32768 va être dépassé. Spécifiez moins de copies.","HQ-Protect personnel",MB_OK);
           return;
           }

        spack_flag=1;
        SendDlgItemMessage(md_hwnd,IDC_PROGRESS1,PBM_SETRANGE,0,MAKELPARAM(0,sp_amount));
        for (sp_i=0;sp_i<(unsigned int)sp_amount;sp_i++) {
            AddUser(EZM.selected,"Utilisateur d'un jeu de copies");
            EZM.selected_user=Programs.data[EZM.selected].users_amount-1;
            ProtectExe();
            SendDlgItemMessage(md_hwnd,IDC_PROGRESS1,PBM_SETPOS,(WPARAM)(sp_i+1),0);
            }
        RefreshUsers();
        }

void    rnd_gen()
        {
        rnum=214013*rnum+2531011;
        }

void    SN_Error(HWND e_box)
        {
        SetDlgItemText(e_box,IDC_EDIT2,"Inconnu");
        SetDlgItemText(e_box,IDC_EDIT3,"Inconnu");
        SetDlgItemText(e_box,IDC_EDIT4,"Numéro de série invalide");
        }

void    CheckSerial(HWND e_box)
        {
        int             i1,kd_offset;
        char            serial_txt[256];
        unsigned char   key_data[256];
        unsigned char   pdata;
        unsigned short  k_crc;
        unsigned char   *sn_ptr;
        unsigned int    *dc_key_ptr;

        unsigned int    done_flag,flag;
        unsigned int    sw_num;
        unsigned int    ui_num;

        SendDlgItemMessage(e_box,IDC_EDIT1,EM_GETLINE,0,(LPARAM)(&txt_buff[0]));
        i1=0;
        for (i=0;i<strlen(txt_buff)&&i<256;i++) {
            if (txt_buff[i]>='A'&&txt_buff[i]<='P') {
               serial_txt[i1]=txt_buff[i];
               i1++;
               }
            }
        if (i1!=48) {
           SN_Error(e_box);
           return;
           }

        // Retranslate serial to normal form
        kd_offset=0;
        for (i=0;i<48;i++) {
            if (serial_txt[i]>=65&&serial_txt[i]<=80) {
               pdata=serial_txt[i]-65;
               i++;
               pdata|=(serial_txt[i]-65)<<4;
               key_data[kd_offset]=pdata;
               kd_offset++;
               }
            }
        memcpy(&SERIAL,key_data,24);
        // Count CRC
        k_crc=0;
        for (i=2;i<24;i++) {
            k_crc+=key_data[i]+i-2;
            }
        if (k_crc!=SERIAL.CRC) {
           SN_Error(e_box);
           return;
           }

        // Decrypt key
        rnum=SERIAL.RSEED;
        sn_ptr=(unsigned char *)(&SERIAL);
        sn_ptr+=6;
        for (i=6;i<21;i++) {
            rnd_gen();
            *(unsigned int *)sn_ptr^=rnum;
            sn_ptr++;
            }

        // Try to match serial
        if (SERIAL.VENDOR!=__VENDOR_ID) {
           SN_Error(e_box);
           return;
           }
        done_flag=0;
        sw_num=0;
        ui_num=0;
        for (i=0;i<Programs.amount;i++) {
            if (SERIAL.SOFTWARE==Programs.data[i].sw_id) {
               for (i1=0;i1<Programs.data[i].users_amount;i1++) {
                   if (SERIAL.USER==Programs.data[i].user[i1].user_id) {
                      done_flag=1;
                      sw_num=i;
                      ui_num=i1;
                      }
                   }
               }
            }
        if (done_flag!=1) return;
        A_KEY.DECRYPTION_KEY=Programs.data[sw_num].user[ui_num].dc_key;
        A_KEY.PROGRAM_SEED=Programs.data[sw_num].user[ui_num].r_seed;
        A_KEY.VENDOR=__VENDOR_ID;
        A_KEY.SOFTWARE=Programs.data[sw_num].sw_id;
        A_KEY.USER=Programs.data[sw_num].user[ui_num].user_id;
        A_KEY.KEY_SEED=GetTickCount()^0x72F10554;

        A_KEY.CRC=0;
        sn_ptr=(unsigned char *)(&A_KEY.KEY_SEED);
        for (i=0;i<22;i++) {
            A_KEY.CRC+=((unsigned char *)sn_ptr)[i];
            A_KEY.CRC+=i;
            }

        dc_key_ptr=(unsigned int *)(&A_KEY.USER);
        dc_key_ptr[0]^=SERIAL.HDD_SERIAL;
        dc_key_ptr=(unsigned int *)(&A_KEY.SOFTWARE);
        dc_key_ptr[0]^=SERIAL.PN_CRC;

//      Encrypt decryption key
        dc_key_ptr=(unsigned int *)(&A_KEY.DECRYPTION_KEY);
        dc_key_ptr[0]^=SERIAL.HDD_SERIAL;
        dc_key_ptr[1]^=SERIAL.PN_CRC;


//      Encrypt key
        rnum=A_KEY.KEY_SEED;
        sn_ptr=(unsigned char *)(&A_KEY);
        sn_ptr+=6;
        for (i=6;i<21;i++) {
            rnd_gen();
            *(unsigned int *)sn_ptr^=rnum;
            sn_ptr++;
            }

//      Output key
        flag=i1=0;
        sn_ptr=(unsigned char *)(&A_KEY);
        for (i=0;i<24;i++) {
            if (flag==3) {
               txt_buff[i1]='-';
               i1++;
               flag=0;
               }
            txt_buff[i1]=(sn_ptr[i]&15)+65;
            i1++;
            txt_buff[i1]=(sn_ptr[i]>>4)+65;
            i1++;
            flag++;
            }
        txt_buff[i1]=0;

        SetDlgItemText(e_box,IDC_EDIT2,Programs.data[sw_num].path);
        SetDlgItemText(e_box,IDC_EDIT3,Programs.data[sw_num].user[ui_num].user_name);
        SetDlgItemText(e_box,IDC_EDIT4,txt_buff);
        }

BOOL    WINAPI EZ_Authorization(HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam)
        {
        switch (message)
               {
               case WM_CLOSE:
                    EndDialog(hwnd,0);
                    break;
               case WM_COMMAND:
                    switch (LOWORD (wParam))
                           {
                           case IDC_EDIT1:
                                switch (HIWORD (wParam))
                                       {
                                       case EN_CHANGE:
                                            CheckSerial(hwnd);
                                            break;
                                       }
                                break;
                           default:
                                return FALSE;
                           }
                    break;
               default:
                    return FALSE;
               }
        return TRUE;
        };

BOOL    WINAPI EZ_NewUser(HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam)
        {
        switch (message)
               {
               case WM_COMMAND:
                    SendDlgItemMessage(nu_hwnd,IDC_EDIT1,EM_LIMITTEXT,(WPARAM)192,0);
                    switch (LOWORD (wParam))
                           {
                           case IDC_BUTTON1:        // Cancel
                                EndDialog(hwnd,0);
                                break;
                           case IDC_BUTTON5:        // Done
                                txt_buff[0]=0;
                                SendDlgItemMessage(hwnd,IDC_EDIT1,EM_GETLINE,0,(LPARAM)(&txt_buff[0]));
                                if (strlen(txt_buff)==0) {
                                   MessageBox(NULL,"Informations sur la version ou utilisateur","HQ-Protect personnel",MB_OK);
                                   } else {
                                   AddUser(EZM.selected,txt_buff);
                                   RefreshUsers();
                                   EndDialog(hwnd,0);
                                   }
                                break;
                           default:
                                return FALSE;
                           }
                    break;
               default:
                    return FALSE;
               }
        return TRUE;
        };

void    SaveDatabase()
        {
        int i1;
        FILE *outfile;

        sprintf(txt_buff,"%sdb.dat",cmd_line);
//        MessageBox(NULL,txt_buff,"Quit",MB_OK);

        DB_HEADER.id=666;
        DB_HEADER.sw_amount=Programs.amount;
        outfile=fopen(txt_buff,"wb");
        if (Programs.amount<=0) {
           fclose(outfile);
           return;
           }
        fwrite(&DB_HEADER,sizeof(DB_HEADER),1,outfile);
        for (i=0;i<Programs.amount;i++) {
            fwrite(&Programs.data[i],sizeof(PROGRAM_ITEM_DEF),1,outfile);
            for (i1=0;i1<Programs.data[i].users_amount;i1++) {
                fwrite(&Programs.data[i].user[i1],sizeof(USER_ITEM_DEF),1,outfile);
                }
            }
        fclose(outfile);
        }

void    LoadDatabase()
        {
        FILE *infile;

        sprintf(txt_buff,"%sdb.dat",cmd_line);
        infile=fopen(txt_buff,"rb");
        if (infile==NULL) {
           return;
           }
        if (filelength(fileno(infile))==0) {
           MessageBox(NULL,"Fichier manquant","Chargement en cours...",MB_OK);
           return;
           }

        fread(&DB_HEADER,sizeof(DB_HEADER),1,infile);
        Programs.data=NULL;
        Programs.amount=DB_HEADER.sw_amount;
        for (i=0;i<DB_HEADER.sw_amount;i++) {
            Programs.data=realloc(Programs.data,sizeof(PROGRAM_ITEM_DEF)*(i+1));
            fread(&Programs.data[i],sizeof(PROGRAM_ITEM_DEF),1,infile);
            Programs.data[i].user=(USER_ITEM_DEF *)malloc(Programs.data[i].users_amount*sizeof(USER_ITEM_DEF));
            fread(Programs.data[i].user,Programs.data[i].users_amount*sizeof(USER_ITEM_DEF),1,infile);


            ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
            ListItem.iItem=0;
            ListItem.iSubItem=0;
            ListItem.stateMask=0;
            ListItem.pszText=(LPTSTR)(Programs.data[i].path);
            SendDlgItemMessage(md_hwnd,IDC_LIST1,LVM_INSERTITEM,0,(LPARAM)(&ListItem));

            ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
            ListItem.iItem=0;
            ListItem.iSubItem=1;
            ListItem.stateMask=0;
            sprintf(txt_buff,"0x%X",Programs.data[i].sw_id);
            ListItem.pszText=(LPTSTR)(txt_buff);
            SendDlgItemMessage(md_hwnd,IDC_LIST1,LVM_SETITEM,0,(LPARAM)(&ListItem));
            }
        fclose(infile);
        SwitchToProgram(0);
        RefreshUsers();
        }

BOOL    WINAPI EVE_MainProc(HWND hwnd,UINT message,WPARAM wParam,LPARAM lParam)
        {
        switch (message)
               {
               case WM_DESTROY:
                    SaveDatabase();
                    PostQuitMessage(0);
                    break;
               default:
                    return DefWindowProc(hwnd,message,wParam,lParam);
               };
        return(0);
        };

BOOL    EVE_InitApplication(HINSTANCE hInst)
        {
        WNDCLASS wc;

        wc.style                = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc          = (WNDPROC)EVE_MainProc;
        wc.cbClsExtra           = 0;
        wc.cbWndExtra           = 0;
        wc.hInstance            = hInst;
        wc.hIcon                = LoadIcon (NULL,IDI_APPLICATION);
        wc.hCursor              = LoadCursor (NULL,IDC_ARROW);
        wc.hbrBackground        = (HBRUSH)(COLOR_APPWORKSPACE+1);
        wc.lpszMenuName         = NULL;
        wc.lpszClassName        = szClassName;

        return RegisterClass(&wc);
        };

BOOL    EVE_InitInstance(HINSTANCE hInstance,int nCmdShow)
        {
        hWnd = CreateWindow(szClassName,
                            szTitle,
                            WS_OVERLAPPED|WS_SYSMENU|WS_MINIMIZEBOX,
                            CW_USEDEFAULT,
                            CW_USEDEFAULT,
                            CW_USEDEFAULT,
                            CW_USEDEFAULT,
                            NULL,
                            NULL,
                            hInstance,
                            NULL);
        if (!hWnd)
           return (FALSE);
        ShowWindow(hWnd,nCmdShow);
        UpdateWindow(hWnd);

        return (TRUE);
        };

void    RefreshUsers()
        {
        SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_DELETEALLITEMS,0,0);
        if (Programs.data[EZM.selected].users_amount<=0) {
           return;
           }

        for (i=0;i<Programs.data[EZM.selected].users_amount;i++) {
            ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
            ListItem.iItem=0;
            ListItem.iSubItem=0;
            ListItem.stateMask=0;
            ListItem.pszText=(LPTSTR)(Programs.data[EZM.selected].user[i].user_name);
            SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_INSERTITEM,0,(LPARAM)(&ListItem));

            sprintf(txt_buff,"0x%X",Programs.data[EZM.selected].user[i].user_id);
            ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
            ListItem.iItem=0;
            ListItem.iSubItem=1;
            ListItem.stateMask=0;
            ListItem.pszText=(LPTSTR)(txt_buff);
            SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_SETITEM,0,(LPARAM)(&ListItem));

            sprintf(txt_buff,"%i64",Programs.data[EZM.selected].user[i].dc_key);
            ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
            ListItem.iItem=0;
            ListItem.iSubItem=2;
            ListItem.stateMask=0;
            ListItem.pszText=(LPTSTR)(txt_buff);
            SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_SETITEM,0,(LPARAM)(&ListItem));

            sprintf(txt_buff,"0x%X",Programs.data[EZM.selected].user[i].r_seed);
            ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
            ListItem.iItem=0;
            ListItem.iSubItem=3;
            ListItem.stateMask=0;
            ListItem.pszText=(LPTSTR)(txt_buff);
            SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_SETITEM,0,(LPARAM)(&ListItem));
            }
        }

void    SwitchToProgram(int p_num)
        {
        EZM.selected=Programs.amount-1-p_num;
        EZM.selected_user=-1;

        if (Programs.data[EZM.selected].cflags&FLAG_REMOVEH)
           CheckDlgButton(md_hwnd,IDC_CHECK6,BST_CHECKED);
           else
           CheckDlgButton(md_hwnd,IDC_CHECK6,BST_UNCHECKED);

        if (Programs.data[EZM.selected].cflags&FLAG_RAPI)
           CheckDlgButton(md_hwnd,IDC_CHECK5,BST_CHECKED);
           else
           CheckDlgButton(md_hwnd,IDC_CHECK5,BST_UNCHECKED);

        if (Programs.data[EZM.selected].cflags&FLAG_ASICE)
           CheckDlgButton(md_hwnd,IDC_CHECK1,BST_CHECKED);
           else
           CheckDlgButton(md_hwnd,IDC_CHECK1,BST_UNCHECKED);

        if (Programs.data[EZM.selected].cflags&FLAG_CRC)
           CheckDlgButton(md_hwnd,IDC_CHECK2,BST_CHECKED);
           else
           CheckDlgButton(md_hwnd,IDC_CHECK2,BST_UNCHECKED);

        if (Programs.data[EZM.selected].cflags&FLAG_DIMPORTS)
           CheckDlgButton(md_hwnd,IDC_CHECK3,BST_CHECKED);
           else
           CheckDlgButton(md_hwnd,IDC_CHECK3,BST_UNCHECKED);

        RefreshUsers();
        }

void    AddUser(int software_number,char *UserName)
        {
        int             cu;
        int             rflag;
        _int64          dc_key;
        int             rseed;
        unsigned short  UserID;

        cu=Programs.data[software_number].users_amount;
        Programs.data[software_number].user=(USER_ITEM_DEF *)realloc(Programs.data[software_number].user,sizeof(USER_ITEM_DEF)*(Programs.data[software_number].users_amount+1));
        strcpy(Programs.data[software_number].user[cu].user_name,UserName);

        {   // Assign R SEED
        srand(GetTickCount());
        rseed=rand();
        for (rflag=0;rflag<500+rand();rflag++)
            rseed+=rand();
        rflag=0;
        if (cu>0)
        while (rflag==0) {
              rseed+=rand();
              rflag=1;
              for (i=0;i<Programs.data[EZM.selected].users_amount&&rflag;i++)
                  if (rseed==Programs.data[software_number].user[i].r_seed)
                     rflag=0;
              }
        }

        {   // Assign USER ID
        UserID=rand();
        for (rflag=0;rflag<500+rand();rflag++)
            UserID+=rand();
        rflag=0;
        if (cu>0)
        while (rflag==0) {
              UserID+=rand();
              rflag=1;
              for (i=0;i<Programs.data[EZM.selected].users_amount&&rflag;i++)
                  if (UserID==Programs.data[software_number].user[i].user_id)
                     rflag=0;
              }
        }

        {   // Assign DC KEY
        dc_key=0x1a47a84dda4ba74c;
        for (rflag=0;rflag<1000+rand();rflag++)
            dc_key+=(rand()^0x521A)*rflag;
        rflag=0;
        if (cu>0)
        while (rflag==0) {
              dc_key+=rand()^0x521A;
              rflag=1;
              for (i=0;i<Programs.data[EZM.selected].users_amount&&rflag;i++)
                  if (dc_key==Programs.data[software_number].user[i].dc_key)
                     rflag=0;
              }
        }

        EZM.selected_user=cu;
        Programs.data[software_number].user[cu].r_seed=rseed;
        Programs.data[software_number].user[cu].user_id=UserID;
        Programs.data[software_number].user[cu].dc_key=dc_key;
        Programs.data[software_number].users_amount++;
        }

void    AddProgram()
        {
        ZeroMemory(&ofn, sizeof(OPENFILENAME));
        ofn.lStructSize = sizeof(OPENFILENAME);
        ofn.hwndOwner = hWnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "Fichiers Exe (*.exe)\0*.exe\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrFileTitle = NULL;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = NULL;
        ofn.Flags = OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST;
        // Display the Open dialog box.

        if (GetOpenFileName(&ofn)) {
           int sw_id;

           ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
           ListItem.iItem=0;
           ListItem.iSubItem=0;
           ListItem.stateMask=0;
           ListItem.pszText=(LPTSTR)(ofn.lpstrFile);
           SendDlgItemMessage(md_hwnd,IDC_LIST1,LVM_INSERTITEM,0,(LPARAM)(&ListItem));

           Programs.data=(PROGRAM_ITEM_DEF *)realloc(Programs.data,sizeof(PROGRAM_ITEM_DEF)*(Programs.amount+1));
           Programs.data[Programs.amount].users_amount=0;
           Programs.data[Programs.amount].user=NULL;
           strcpy(Programs.data[Programs.amount].path,ofn.lpstrFile);
           srand(GetTickCount());
           if (Programs.amount>0) {
              int ready;

              ready=0;
              while (ready==0) {
                    ready=1;
                    sw_id=rand()^0x1842;
                    for (i=0;i<Programs.amount;i++) {
                        if (Programs.data[i].sw_id==sw_id)
                           ready=0;
                        }
                    }
              } else {
              sw_id=rand()^0x18429;
              }
           Programs.data[Programs.amount].sw_id=sw_id;

           ListItem.mask=LVIF_DI_SETITEM|LVIF_TEXT;
           ListItem.iItem=0;
           ListItem.iSubItem=1;
           ListItem.stateMask=0;
           sprintf(txt_buff,"0x%X",sw_id);
           ListItem.pszText=(LPTSTR)(txt_buff);
           SendDlgItemMessage(md_hwnd,IDC_LIST1,LVM_SETITEM,0,(LPARAM)(&ListItem));
           } else {
           return;
           }

        EZM.selected=Programs.amount;
        Programs.amount++;
        if (EZM.selected>=0) {
           sprintf(txt_buff,"Utilisateur par défaut de %s",Programs.data[EZM.selected].path);
           AddUser(Programs.amount-1,txt_buff);
           }
        SwitchToProgram(0);
        }

void    FillProgramList()
        {
        Programs.amount=0;
        Programs.data=NULL;
        }

void    CreateControls()
        {
        // Create software list
        ListColumn.mask=LVCF_WIDTH|LVCF_TEXT|LVCF_FMT;
        ListColumn.fmt=0;
        ListColumn.cx=843;
        ListColumn.pszText=(LPTSTR)("Program file");
        SendDlgItemMessage(md_hwnd,IDC_LIST1,LVM_INSERTCOLUMN,(WPARAM)(1),(LPARAM)(&ListColumn));

        ListColumn.mask=LVCF_WIDTH|LVCF_TEXT|LVCF_FMT;
        ListColumn.fmt=0;
        ListColumn.cx=98;
        ListColumn.pszText=(LPTSTR)("Program ID");
        SendDlgItemMessage(md_hwnd,IDC_LIST1,LVM_INSERTCOLUMN,(WPARAM)(3),(LPARAM)(&ListColumn));

        // Create users list
        ListColumn.mask=LVCF_WIDTH|LVCF_TEXT|LVCF_FMT;
        ListColumn.fmt=0;
        ListColumn.cx=645;
        ListColumn.pszText=(LPTSTR)("User name");
        SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_INSERTCOLUMN,(WPARAM)(1),(LPARAM)(&ListColumn));

        ListColumn.mask=LVCF_WIDTH|LVCF_TEXT|LVCF_FMT;
        ListColumn.fmt=0;
        ListColumn.cx=70;
        ListColumn.pszText=(LPTSTR)("User ID");
        SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_INSERTCOLUMN,(WPARAM)(3),(LPARAM)(&ListColumn));

        ListColumn.mask=LVCF_WIDTH|LVCF_TEXT|LVCF_FMT;
        ListColumn.fmt=0;
        ListColumn.cx=130;
        ListColumn.pszText=(LPTSTR)("DC KEY");
        SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_INSERTCOLUMN,(WPARAM)(3),(LPARAM)(&ListColumn));

        ListColumn.mask=LVCF_WIDTH|LVCF_TEXT|LVCF_FMT;
        ListColumn.fmt=0;
        ListColumn.cx=98;
        ListColumn.pszText=(LPTSTR)("RS");
        SendDlgItemMessage(md_hwnd,IDC_USERSLIST,LVM_INSERTCOLUMN,(WPARAM)(3),(LPARAM)(&ListColumn));

        CheckDlgButton(md_hwnd,IDC_CHECK1,BST_UNCHECKED);
        CheckDlgButton(md_hwnd,IDC_CHECK2,BST_UNCHECKED);
        CheckDlgButton(md_hwnd,IDC_CHECK3,BST_UNCHECKED);
        CheckDlgButton(md_hwnd,IDC_CHECK5,BST_UNCHECKED);
        CheckDlgButton(md_hwnd,IDC_CHECK6,BST_UNCHECKED);

        SendDlgItemMessage(md_hwnd,IDC_EDIT2,EM_LIMITTEXT,(WPARAM)5,0);

        FillProgramList();
        }

int     APIENTRY WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
        {
        MSG msg;

        quitflag=0;

        cmd_line=GetCommandLine();
        i=strlen(cmd_line);
        while (cmd_line[i]!=92&&i>0)
              i--;
        cmd_line[i+1]=0;
        if (cmd_line[0]==34)
           memmove(cmd_line,cmd_line+1,strlen(cmd_line));
        if (strlen(cmd_line)<=2) {
           cmd_line[0]='.';
           cmd_line[1]=92;
           cmd_line[2]=0;
           }


        sprintf(txt_buff,"%sresult",cmd_line);
        mkdir(txt_buff);

        InitCommonControls();
        EZM.selected=-1;
        EZM.selected_user=-1;

        if (!EVE_InitApplication(hInstance))
           return(FALSE);
        if (!EVE_InitInstance(hInstance,nCmdShow))
           return(FALSE);

        md_hwnd = NULL;
        hInst2 = (HINSTANCE) GetWindowLong( hWnd, GWL_HINSTANCE );
        md_hwnd = CreateDialog( hInst2, MAKEINTRESOURCE(IDD_DIALOG1),
                                hWnd, (DLGPROC) MainDlgProc );
        UpdateWindow(md_hwnd);
        SetActiveWindow(md_hwnd);

        rect.top=0;
        rect.left=0;
        rect.right=645;
        rect.bottom=330;
        MapDialogRect(md_hwnd,&rect);
        SetWindowPos(hWnd,HWND_TOP,CW_USEDEFAULT,CW_USEDEFAULT,rect.right+12,rect.bottom+31,SWP_NOMOVE);

        CreateControls();

        LoadDatabase();

        while (GetMessage(&msg,NULL,0,0)&&quitflag==0) {
              RedrawWindow(md_hwnd,NULL,NULL,RDW_ERASE);
              TranslateMessage(&msg);
              DispatchMessage(&msg);
              };

        return (msg.wParam);
        }

INT_PTR CALLBACK MainDlgProc(HWND hdlg,UINT message,WPARAM wparam,LPARAM lparam)
        {
        switch (message)
               {
               case WM_INITDIALOG:
                    return FALSE;
               case WM_COMMAND:
                    switch (LOWORD(wparam))
                           {
                           case IDC_APPBROWSE:
                                AddProgram();
                                break;
                           case IDC_CHECK6:     // Remove header
                                if (EZM.selected!=-1) {
                                   switch (IsDlgButtonChecked(hdlg,IDC_CHECK6)) {
                                          case BST_CHECKED:
                                               Programs.data[EZM.selected].cflags|=FLAG_REMOVEH;
                                               break;
                                          case BST_UNCHECKED:
                                               if (Programs.data[EZM.selected].cflags&FLAG_REMOVEH)
                                                  Programs.data[EZM.selected].cflags^=FLAG_REMOVEH;
                                               break;
                                          }
                                   } else {
                                   MessageBox(NULL,"You need to select software first","E-zapper",MB_OK);
                                   }
                                break;
                           case IDC_CHECK5:     // Redirect API
                                if (EZM.selected!=-1) {
                                   switch (IsDlgButtonChecked(hdlg,IDC_CHECK5)) {
                                          case BST_CHECKED:
                                               Programs.data[EZM.selected].cflags|=FLAG_RAPI;
                                               break;
                                          case BST_UNCHECKED:
                                               if (Programs.data[EZM.selected].cflags&FLAG_RAPI)
                                                  Programs.data[EZM.selected].cflags^=FLAG_RAPI;
                                               break;
                                          }
                                   } else {
                                   MessageBox(NULL,"You need to select software first","E-zapper",MB_OK);
                                   }
                                break;
                           case IDC_CHECK1:     // Anti SoftIce
                                if (EZM.selected!=-1) {
                                   switch (IsDlgButtonChecked(hdlg,IDC_CHECK1)) {
                                          case BST_CHECKED:
                                               Programs.data[EZM.selected].cflags|=FLAG_ASICE;
                                               break;
                                          case BST_UNCHECKED:
                                               if (Programs.data[EZM.selected].cflags&FLAG_ASICE)
                                                  Programs.data[EZM.selected].cflags^=FLAG_ASICE;
                                               break;
                                          }
                                   } else {
                                   MessageBox(NULL,"You need to select software first","E-zapper",MB_OK);
                                   }
                                break;
                           case IDC_CHECK2:     // CRC check
                                if (EZM.selected!=-1) {
                                   switch (IsDlgButtonChecked(hdlg,IDC_CHECK2)) {
                                          case BST_CHECKED:
                                               Programs.data[EZM.selected].cflags|=FLAG_CRC;
                                               break;
                                          case BST_UNCHECKED:
                                               if (Programs.data[EZM.selected].cflags&FLAG_CRC)
                                                  Programs.data[EZM.selected].cflags^=FLAG_CRC;
                                               break;
                                          }
                                   } else {
                                   MessageBox(NULL,"You need to select software first","E-zapper",MB_OK);
                                   }
                                break;
                           case IDC_CHECK3:     // Delete imports
                                if (EZM.selected!=-1) {
                                   switch (IsDlgButtonChecked(hdlg,IDC_CHECK3)) {
                                          case BST_CHECKED:
                                               Programs.data[EZM.selected].cflags|=FLAG_DIMPORTS;
                                               break;
                                          case BST_UNCHECKED:
                                               if (Programs.data[EZM.selected].cflags&FLAG_DIMPORTS)
                                                  Programs.data[EZM.selected].cflags^=FLAG_DIMPORTS;
                                               break;
                                          }
                                   } else {
                                   MessageBox(NULL,"Vous devez sélectionner un logiciel","HQ-Protect",MB_OK);
                                   }
                                break;
                           case IDC_BUTTON3:
                                if (EZM.selected!=-1) {
                                   DialogBox((HINSTANCE)GetModuleHandle(NULL),MAKEINTRESOURCE(IDD_DIALOG2),hWnd,(DLGPROC)EZ_NewUser);
                                   } else {
                                   MessageBox(NULL,"Vous devez ajouter un utilisateur","HQ-Protect",MB_OK);
                                   }
                                break;
                           case IDC_BUTTON1:
                                if (Programs.amount<=0) {
                                   MessageBox(NULL,"Aucun programme dans la base","HQ-Protect",MB_OK);
                                   } else {
                                   DialogBox((HINSTANCE)GetModuleHandle(NULL),MAKEINTRESOURCE(IDD_DIALOG3),hWnd,(DLGPROC)EZ_Authorization);
                                   }
                                break;
                           case IDC_BUTTON4:    // Protect
                                if (EZM.selected_user!=-1&&EZM.selected!=-1) {
                                   spack_flag=0;
                                   ProtectExe();
                                   } else {
                                   MessageBox(NULL,"Sélectionnez le logiciel et l'utilisateur","HQ-Protect personnel",MB_OK);
                                   }
                                break;
                           case IDC_BUTTON2:    // Create shuffle pack
                                if (EZM.selected!=-1)
                                   CreateSPack();
                                   else
                                   MessageBox(NULL,"Sélectionnez d'abord le logiciel","HQ-Protect personnel",MB_OK);
                                break;
                           default:
                                return FALSE;
                           };
                    break;
               case WM_NOTIFY:
                    switch (LOWORD(wparam))
                           {
                           case IDC_LIST1:
                                switch (((LPNMHDR) lparam)->code)
                                       {
                                       case NM_CLICK:
                                            if (((LPNMITEMACTIVATE)lparam)->iItem>=0&&((LPNMITEMACTIVATE)lparam)->iItem<Programs.amount)
                                               SwitchToProgram(((LPNMITEMACTIVATE)lparam)->iItem);
                                            return TRUE;
                                            break;
                                       }
                                break;
                           case IDC_USERSLIST:
                                switch (((LPNMHDR) lparam)->code)
                                       {
                                       case NM_CLICK:
                                            if (EZM.selected==-1)
                                               MessageBox(NULL,"Sélectionnez le logiciel","HQ-Protect personnel",MB_OK);
                                               else
                                            if (((LPNMITEMACTIVATE)lparam)->iItem>=0&&((LPNMITEMACTIVATE)lparam)->iItem<Programs.data[EZM.selected].users_amount) {
                                               EZM.selected_user=Programs.data[EZM.selected].users_amount-1-((LPNMITEMACTIVATE)lparam)->iItem;
                                               }
                                            return TRUE;
                                            break;
                                       }
                                break;
                           default:
                                return FALSE;
                           }
                    break;
               default:
                    return FALSE;
               };
        return TRUE;
        };



