#define MNG_TRUE        1
#define MNG_FALSE       0

int             quitflag=0;
LPCSTR          szClassName = "MNG Class";
LPCSTR          szTitle = "HQ-Protect personnel";
OPENFILENAME    ofn;
char            szFile[260];

HWND            hwndOwner,md_hwnd,hWnd;
HINSTANCE       hInst2;

RECT      rect;

INT_PTR CALLBACK MainDlgProc(HWND hdlg,UINT message,WPARAM wparam,LPARAM lparam);

