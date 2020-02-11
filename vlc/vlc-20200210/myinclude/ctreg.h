/**-----------------------------------------------------------------------------
 * @file     CTReg.h
 *
 * @author   yangrz@centerm.com.cn
 *
 * @date     2011/2/4
 *
 * @brief    ×¢²á±í²Ù×÷º¯Êý
 *
 * @version
 *
 *----------------------------------------------------------------------------*/

#ifndef __CTREG_H__
#define __CTREG_H__

#include <string.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>

#include <winsock2.h>
#include <windows.h>

// ÉùÒô
#define REGPATH_VOLUME_PATH	        "Software\\Centerm\\TeacherClient"
#define REGPATH_VOLUME_KEY	        "VlcVolume"

LONG CTRegReadString(HKEY hKey, const char *subkeyname, const char *valueName, char *val, const char *defaultVal);
DWORD ReadDwordFromRegedit(HKEY hKeyParent, LPCTSTR lpszKeyName, LPCTSTR lpszValueName, DWORD &dwValue);

DWORD WriteStringToRegedit(HKEY hKeyParent, LPCTSTR lpszKeyName, LPCTSTR lpszValueName, LPCTSTR lpszValue);
DWORD WriteDwordToRegedit(HKEY hKeyParent, LPCTSTR lpszKeyName, LPCTSTR lpszValueName, DWORD dwValue);

/**
 * @brief
 *
 * @param[in]	strServerAddr  ,eg: http://192.168.4.13:8001 ?http://ivycloud-local.com
 * @param[out]	strBroadIp     ,eg:  239.1.4.13
 * @return	TRUE
 *          FALSE

 * @note
 */
static BOOL
GetBroadIpFromDomain(char *strServerAddr, char *strBroadIp);



#endif
