/*****************************************************************************
 * winvlc.c: the Windows VLC media player
 *****************************************************************************
 * Copyright (C) 1998-2011 the VideoLAN team
 *
 * Authors: Vincent Seguin <seguin@via.ecp.fr>
 *          Samuel Hocevar <sam@zoy.org>
 *          Gildas Bazin <gbazin@videolan.org>
 *          Derk-Jan Hartman <hartman at videolan dot org>
 *          Lots of other people, see the libvlc AUTHORS file
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef UNICODE
#define UNICODE
#endif

#include <vlc/vlc.h>
#include <windows.h>
#include <tchar.h>
#include <shellapi.h>

#ifndef _WIN32_IE
#  define  _WIN32_IE 0x501
#endif
#include <fcntl.h>
#include <io.h>
#include <shlobj.h>
#include <wininet.h>
#define PSAPI_VERSION 1
#include <psapi.h>
#define HeapEnableTerminationOnCorruption (HEAP_INFORMATION_CLASS)1
static void check_crashdump(void);
LONG WINAPI vlc_exception_filter(struct _EXCEPTION_POINTERS *lpExceptionInfo);
static const wchar_t *crashdump_path;

DWORD GetCurrentFolder(TCHAR* szFolderPath);
VOID  RefreshWin();

static char *FromWide (const wchar_t *wide)
{
    size_t len;
    len = WideCharToMultiByte (CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);

    char *out = (char *)malloc (len);
    if (out)
        WideCharToMultiByte (CP_UTF8, 0, wide, -1, out, len, NULL, NULL);
    return out;
}

typedef struct _My_Windows {
    HWND myself;
    HWND parent;
} MyWindows, *PMyWindows;
HWND g_myself = NULL;

BOOL CALLBACK EnumChildProc(HWND hWnd,LPARAM lParam)  
{  
	TCHAR temp1[256] = {NULL};
    GetWindowText(hWnd,temp1,255);
    if (wcscmp(L"网络影院", temp1) == 0)
    {
        g_myself = hWnd;
    }
    
    return true;
}
 
DWORD WINAPI ListenParentWindows (LPARAM param)
{
    if (param == NULL)
    {
        return -1;
    }
    PMyWindows pMyWindows = (PMyWindows)param;
    DWORD dwProcessID;
    GetWindowThreadProcessId(pMyWindows->parent, &dwProcessID);

    TCHAR msg[MAX_PATH] = {NULL};
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);

    EnumChildWindows(pMyWindows->parent, EnumChildProc, NULL);

    wsprintf(msg, L"HWND %d, Id %d, Proc %d      myself %d.", pMyWindows->parent, dwProcessID, hProcess, pMyWindows->myself);
    //MessageBox( NULL, msg, NULL, 0 );



    if (hProcess != INVALID_HANDLE_VALUE)
    {
        //MessageBox( NULL, L"start", NULL, 0);
        WaitForSingleObject(hProcess, INFINITE);
        //MessageBox( NULL, L"end 11", NULL, 0);
        
        //PostMessage(g_myself, WM_CLOSE, NULL, NULL);
        HANDLE hParent = GetCurrentProcess();
        TerminateProcess(hParent, 0);
    }
    free(pMyWindows);
    return 0;
}


int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine,
                    int nCmdShow )
{
    int argc;

    // liyl
    HWND hParent = NULL;

	// chenyj set to only one instance
	HANDLE hMutex = CreateMutex(0, true, "{E9114565-4592-43ba-912E-E7EA72B73C09}");
	if ( hMutex )
	{ 
		if(GetLastError() == ERROR_ALREADY_EXISTS) 
		{
			fprintf(stderr, "There has an instance, so return\n");
			return 0;
		}
	}

	//CheckIsCloudMode();
	TCHAR szCurrentDir[MAX_PATH] = { NULL };
	GetCurrentFolder(szCurrentDir);

	if (0 != _tcslen(szCurrentDir))
	{
		SetCurrentDirectory(szCurrentDir); //设置
	}
	

    /* VLC does not change the thread locale, so gettext/libintil will use the
     * user default locale as reference. */
    /* gettext versions 0.18-0.18.1 will use the Windows Vista locale name
     * if the GETTEXT_MUI environment variable is set. If not set or if running
     * on Windows 2000/XP/2003 an hard-coded language ID list is used. This
     * putenv() call may become redundant with later versions of gettext. */
    putenv("GETTEXT_MUI=1");
#ifdef TOP_BUILDDIR
    putenv("VLC_PLUGIN_PATH=Z:"TOP_BUILDDIR"/modules");
    putenv("VLC_DATA_PATH=Z:"TOP_SRCDIR"/share");
#endif

    SetErrorMode(SEM_FAILCRITICALERRORS);
    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    /* SetProcessDEPPolicy */
    HINSTANCE h_Kernel32 = LoadLibraryW(L"kernel32.dll");
    if(h_Kernel32)
    {
        BOOL (WINAPI * mySetProcessDEPPolicy)( DWORD dwFlags);
        BOOL (WINAPI * mySetDllDirectoryA)(const char* lpPathName);
# define PROCESS_DEP_ENABLE 1

        mySetProcessDEPPolicy = (BOOL (WINAPI *)(DWORD))			// sunqueen modify
                            GetProcAddress(h_Kernel32, "SetProcessDEPPolicy");
        if(mySetProcessDEPPolicy)
            mySetProcessDEPPolicy(PROCESS_DEP_ENABLE);

        /* Do NOT load any library from cwd. */
        mySetDllDirectoryA = (BOOL (WINAPI *)(const char *))			// sunqueen modify
                            GetProcAddress(h_Kernel32, "SetDllDirectoryA");
        if(mySetDllDirectoryA)
            mySetDllDirectoryA("");

        FreeLibrary(h_Kernel32);
    }

    /* Args */
    wchar_t **wargv = CommandLineToArgvW (GetCommandLine (), &argc);
    if (wargv == NULL)
        return 1;

//    char *argv[argc + 3];
    char **argv = (char **)malloc((argc + 3) * sizeof(char *));			// sunqueen modify
    BOOL crash_handling = TRUE;
    int j = 0;
    char *lang = NULL;

    argv[j++] = FromWide( L"--media-library" );
    argv[j++] = FromWide( L"--no-ignore-config" );
    for (int i = 1; i < argc; i++)
    {
        if(!wcscmp(wargv[i], L"--no-crashdump"))
        {
            crash_handling = FALSE;
            continue; /* don't give argument to libvlc */
        }
        if (!wcsncmp(wargv[i], L"--language", 10) )
        {
            if (i < argc - 1 && wcsncmp( wargv[i + 1], L"--", 2 ))
                lang = FromWide (wargv[++i]);
            continue;
        }

        argv[j++] = FromWide (wargv[i]);
    }

    argc = j;
    argv[argc] = NULL;
    LocalFree (wargv);

    if(crash_handling)
    {
        static wchar_t path[MAX_PATH];
        if( S_OK != SHGetFolderPathW( NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                    NULL, SHGFP_TYPE_CURRENT, path ) )
            fprintf( stderr, "Can't open the vlc conf PATH\n" );
        _snwprintf( path+wcslen( path ), MAX_PATH,  L"%s", L"\\vlc\\crashdump" );
        crashdump_path = &path[0];

        check_crashdump();
        SetUnhandledExceptionFilter(vlc_exception_filter);
    }

    _setmode( STDIN_FILENO, _O_BINARY ); /* Needed for pipes */

    /* */
    if (!lang)
    {
        HKEY h_key;
        if( RegOpenKeyEx( HKEY_CURRENT_USER, TEXT("Software\\VideoLAN\\VLC\\"), 0, KEY_READ, &h_key )
                == ERROR_SUCCESS )
        {
            TCHAR szData[256];
            DWORD len = 256;
            if( RegQueryValueEx( h_key, TEXT("Lang"), NULL, NULL, (LPBYTE) &szData, &len ) == ERROR_SUCCESS )
                lang = FromWide( szData );
        }
    }

    if (lang && strncmp( lang, "auto", 4 ) )
    {
        char tmp[11];
        snprintf(tmp, 11, "LANG=%s", lang);
        putenv(tmp);
    }
    free(lang);

    /* Initialize libvlc */
    libvlc_instance_t *vlc;
    vlc = libvlc_new (argc, (const char **)argv);
    if (vlc != NULL)
    {
        libvlc_set_app_id (vlc, "org.VideoLAN.VLC", PACKAGE_VERSION,
                           PACKAGE_NAME);
        libvlc_set_user_agent (vlc, "VLC media player", "VLC/"PACKAGE_VERSION);
        libvlc_add_intf (vlc, "hotkeys,none");
        libvlc_add_intf (vlc, "globalhotkeys,none");
        libvlc_add_intf (vlc, NULL);
        libvlc_playlist_play (vlc, -1, 0, NULL);

		// liyl
 		// 1 add Citrix
		// 2 del MinBox
		HWND hMyself = FindWindow(L"QWidget", L"网络影院");
		if (hMyself && hParent)
		{
			SetParent(hMyself, hParent);
			LONG style=GetWindowLong(hMyself,GWL_STYLE);
			style&=~WS_MINIMIZEBOX;
			SetWindowLong(hMyself,GWL_STYLE,style);

			PMyWindows pMyWindows = (PMyWindows)malloc(sizeof(MyWindows));
			if (pMyWindows != NULL)
			{
				pMyWindows->myself = hMyself;
				pMyWindows->parent = hParent;

				if (NULL == CreateThread(NULL, 0, ListenParentWindows, pMyWindows, 0, NULL))
				{
					MessageBox( NULL, L"create thread fail.", NULL, 0 );
				}
				else
				{
					//MessageBox( NULL, L"create thread success.", NULL, 0 );
				}
			}
		}

        libvlc_wait (vlc);

		//cjh 由于直接关闭有时候会有残影，所以先隐藏窗口再销毁
		if (NULL != hMyself)
		{
			ShowWindow(hMyself, SW_HIDE);
		}

        libvlc_release (vlc);

		//cjh 刷新下界面
		RefreshWin();
    }
    else
        MessageBox (NULL, TEXT("VLC media player could not start.\nEither the command line options were invalid or no plugins were found.\n"),
                    TEXT("VLC media player"),
                    MB_OK|MB_ICONERROR);


    for (int i = 0; i < argc; i++)
        free (argv[i]);
	free(argv);			// sunqueen add

    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

	if (hMutex)
	{
		CloseHandle(hMutex);
	}

    return 0;
}

/* Crashdumps handling */
static void check_crashdump(void)
{
    wchar_t mv_crashdump_path[MAX_PATH];
    wcscpy (mv_crashdump_path, crashdump_path);
    wcscat (mv_crashdump_path, L".mv");

    if (_wrename (crashdump_path, mv_crashdump_path))
        return;

    FILE * fd = _wfopen ( mv_crashdump_path, L"r, ccs=UTF-8" );
    if( !fd )
        return;
    fclose( fd );

    int answer = MessageBox( NULL, L"Ooops: VLC media player just crashed.\nWould you like to send a bug report to the developers team?",
    L"VLC crash reporting", MB_YESNO);

    if(answer == IDYES)
    {
        HINTERNET Hint = InternetOpen(L"VLC Crash Reporter",
                INTERNET_OPEN_TYPE_PRECONFIG, NULL,NULL,0);
        if(Hint)
        {
            HINTERNET ftp = InternetConnect(Hint, L"crash.videolan.org",
                        INTERNET_DEFAULT_FTP_PORT, NULL, NULL,
                        INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
            if(ftp)
            {
                SYSTEMTIME now;
                GetSystemTime(&now);
                wchar_t remote_file[MAX_PATH];
                _snwprintf(remote_file, MAX_PATH,
                        L"/crashes-win32/%04d%02d%02d%02d%02d%02d",
                        now.wYear, now.wMonth, now.wDay, now.wHour,
                        now.wMinute, now.wSecond );

                if( FtpPutFile( ftp, mv_crashdump_path, remote_file,
                            FTP_TRANSFER_TYPE_BINARY, 0) )
                    MessageBox( NULL, L"Report sent correctly. Thanks a lot for the help.", L"Report sent", MB_OK);
                else
                    MessageBox( NULL, L"There was an error while transferring the data to the FTP server.\nThanks a lot for the help.",
                                L"Report sending failed", MB_OK);
                InternetCloseHandle(ftp);
            }
            else
            {
                MessageBox( NULL, L"There was an error while connecting to the FTP server. Thanks a lot for the help.",
                                L"Report sending failed", MB_OK);
                fprintf(stderr,"Can't connect to FTP server 0x%08lu\n",
                        (unsigned long)GetLastError());
            }
            InternetCloseHandle(Hint);
        }
        else
        {
              MessageBox( NULL, L"There was an error while connecting to the Internet.\nThanks a lot for the help anyway.",
                                L"Report sending failed", MB_OK);
        }
    }

    _wremove(mv_crashdump_path);
}

/*****************************************************************************
 * vlc_exception_filter: handles unhandled exceptions, like segfaults
 *****************************************************************************/
LONG WINAPI vlc_exception_filter(struct _EXCEPTION_POINTERS *lpExceptionInfo)
{
    if(IsDebuggerPresent())
    {
        //If a debugger is present, pass the exception to the debugger
        //with EXCEPTION_CONTINUE_SEARCH
        return EXCEPTION_CONTINUE_SEARCH;
    }
    else
    {
        fprintf( stderr, "unhandled vlc exception\n" );

        FILE * fd = _wfopen ( crashdump_path, L"w, ccs=UTF-8" );

        if( !fd )
        {
            fprintf( stderr, "\nerror while opening file" );
            exit( 1 );
        }

        OSVERSIONINFO osvi;
        ZeroMemory( &osvi, sizeof(OSVERSIONINFO) );
        osvi.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
        GetVersionEx( &osvi );

        fwprintf( fd, L"[version]\nOS=%d.%d.%d.%d.%s\nVLC=%s",
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
                osvi.dwPlatformId, osvi.szCSDVersion, VERSION_MESSAGE);			// sunqueen modify

        const CONTEXT *const pContext = (const CONTEXT *)
            lpExceptionInfo->ContextRecord;
        const EXCEPTION_RECORD *const pException = (const EXCEPTION_RECORD *)
            lpExceptionInfo->ExceptionRecord;
        /* No nested exceptions for now */
        fwprintf( fd, L"\n\n[exceptions]\n%08x at %px",
                pException->ExceptionCode, pException->ExceptionAddress );

        for( unsigned int i = 0; i < pException->NumberParameters; i++ )
            fwprintf( fd, L" | %p", pException->ExceptionInformation[i] );

#ifdef _WIN64
        fwprintf( fd, L"\n\n[context]\nRDI:%px\nRSI:%px\n" \
                    "RBX:%px\nRDX:%px\nRCX:%px\nRAX:%px\n" \
                    "RBP:%px\nRIP:%px\nRSP:%px\nR8:%px\n" \
                    "R9:%px\nR10:%px\nR11:%px\nR12:%px\n" \
                    "R13:%px\nR14:%px\nR15:%px\n",
                        pContext->Rdi,pContext->Rsi,pContext->Rbx,
                        pContext->Rdx,pContext->Rcx,pContext->Rax,
                        pContext->Rbp,pContext->Rip,pContext->Rsp,
                        pContext->R8,pContext->R9,pContext->R10,
                        pContext->R11,pContext->R12,pContext->R13,
                        pContext->R14,pContext->R15 );
#else
        fwprintf( fd, L"\n\n[context]\nEDI:%px\nESI:%px\nEBX:%px\nEDX:%px\nECX:%px\nEAX:%px\nEBP:%px\nEIP:%px\nESP:%px\n",
                        pContext->Edi,pContext->Esi,pContext->Ebx,
                        pContext->Edx,pContext->Ecx,pContext->Eax,
                        pContext->Ebp,pContext->Eip,pContext->Esp );
#endif

        fwprintf( fd, L"\n[stacktrace]\n#EIP|base|module\n" );

#ifdef _WIN64
        LPCVOID caller = (LPCVOID)pContext->Rip;
        LPVOID *pBase  = (LPVOID*)pContext->Rbp;
#else
        LPVOID *pBase  = (LPVOID*)pContext->Ebp;
        LPCVOID caller = (LPCVOID)pContext->Eip;
#endif
        for( unsigned frame = 0; frame <= 100; frame++ )
        {
            MEMORY_BASIC_INFORMATION mbi;
            wchar_t module[ 256 ];
            VirtualQuery( caller, &mbi, sizeof( mbi ) ) ;
            GetModuleFileName( mbi.AllocationBase, module, 256 );
            fwprintf( fd, L"%p|%ls\n", caller, module );

            if( IsBadReadPtr( pBase, 2 * sizeof( void* ) ) )
                break;

            /*The last BP points to NULL!*/
            caller = *(pBase + 1);
            if( !caller )
                break;
            pBase = *pBase;
            if( !pBase )
                break;
        }

        HANDLE hpid = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                        FALSE, GetCurrentProcessId());
        if (hpid) {
            HMODULE mods[1024];
            DWORD size;
            if (EnumProcessModules(hpid, mods, sizeof(mods), &size)) {
                fwprintf( fd, L"\n\n[modules]\n" );
                for (unsigned int i = 0; i < size / sizeof(HMODULE); i++) {
                    wchar_t module[ 256 ];
                    GetModuleFileName(mods[i], module, 256);
                    fwprintf( fd, L"%p|%ls\n", mods[i], module);
                }
            }
            CloseHandle(hpid);
        }

        fclose( fd );
        fflush( stderr );
        exit( 1 );
    }
}





DWORD GetCurrentFolder(TCHAR* szFolderPath)
{
	TCHAR szModuleFileName[MAX_PATH] = { NULL }; // 全路径名
	TCHAR drive[_MAX_DRIVE] = { NULL };          // 盘符名称，比如说C盘啊，D盘啊
	TCHAR dir[_MAX_DIR] = { NULL };              // 目录
	TCHAR fname[_MAX_FNAME] = { NULL };          // 进程名字
	TCHAR ext[_MAX_EXT] = { NULL };              //后缀，一般为exe或者是dll

	GetModuleFileName(NULL, szModuleFileName, MAX_PATH);
	_tsplitpath(szModuleFileName, drive, dir, fname, ext);  //分割该路径，得到盘符，目录，文件名，后缀名

	_stprintf_s(szFolderPath, MAX_PATH, _T("%s%s"), drive, dir);

	return 0;
}


VOID  RefreshWin()
{
	//cjh 刷先下wcad，因为这个界面经常会有残影出现
	HWND hWcad = FindWindow(L"QWidget", L"首页");
	if (NULL != hWcad && IsWindow(hWcad))
	{
		RECT wcadRect;
		GetWindowRect(hWcad, &wcadRect);

		InvalidateRect(hWcad, &wcadRect, TRUE);
		UpdateWindow(hWcad);
	}

	HWND hForegroundWnd = GetForegroundWindow();
	if (NULL != hForegroundWnd  && IsWindow(hForegroundWnd))
	{
		RECT rect;
		GetWindowRect(hForegroundWnd, &rect);
		InvalidateRect(hForegroundWnd, &rect, TRUE);
		UpdateWindow(hForegroundWnd);

		HWND hChildWnd = GetTopWindow(hForegroundWnd);
		if (NULL != hChildWnd && IsWindow(hChildWnd))
		{
			GetWindowRect(hChildWnd, &rect);
			InvalidateRect(hChildWnd, &rect, TRUE);
			UpdateWindow(hChildWnd);
		}
	}

	HWND hWebWnd = FindWindow(L"Internet Explorer_Server", NULL);
	if (NULL != hWebWnd  && IsWindow(hWebWnd))
	{
		RECT rect;
		GetWindowRect(hWebWnd, &rect);
		InvalidateRect(hWebWnd, &rect, TRUE);
		UpdateWindow(hWebWnd);
	}

	HWND hDesktopWnd = GetDesktopWindow();
	if (NULL != hDesktopWnd && IsWindow(hWebWnd))
	{
		RECT rect;
		GetWindowRect(hDesktopWnd, &rect);
		InvalidateRect(hDesktopWnd, &rect, TRUE);
		UpdateWindow(hDesktopWnd);
	}
}