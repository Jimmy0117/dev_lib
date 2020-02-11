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
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
/*
static inline LONG
CTRegReadDword(HKEY hKey, const char *subkeyname, const char *valueName, DWORD *val, DWORD defaultVal)
{
    HKEY  hk;
    LONG  ret;

    if ( subkeyname == NULL || valueName == NULL || val == NULL )
    {
        return ERROR_INVALID_PARAMETER;
    }
    *val = defaultVal;

    ret = RegOpenKeyEx(hKey, subkeyname, 0, KEY_READ, &hk);
    if ( ret == ERROR_SUCCESS )
    {
        DWORD data, type;
        DWORD size = sizeof(DWORD);

        ret = RegQueryValueEx(hk, valueName, NULL, &type, (BYTE*)&data, &size);
        RegCloseKey(hk);
        if ( ret == ERROR_SUCCESS && type == REG_DWORD )
        {
            *val = data;
        }
        else
        {
            return ret;
        }
    }

    return ret;
}
*/

/**
 * @brief ¶ÁÈ¡×¢²á±í, Èç¹ûÊ§°ÜÔòÊ¹ÓÃÄ¬ÈÏÖµ, REG_SZÀàÐÍ
 *
 * @param[in] hKey          ¸ù¼üÖµ£¬¿ÉÑ¡Öµ:     \n
 *                          HKEY_CLASSES_ROOT   \n
 *                          HKEY_CURRENT_USER   \n
 *                          HKEY_LOCAL_MACHINE  \n
 *                          HKEY_USERS 
 * @param[in]  subkeyname   ×Ó¼üÃû
 * @param[in]  valueName    ÏîÃû×Ö
 * @param[out] val          Öµ
 * @param[in]  defaultVal   Ä¬ÈÏÖµ
 *
 * @return
 *      ERROR_SUCCESS: ¶ÁÈ¡³É¹¦\n
 *      ÆäËûÖµ:        Ê¹ÓÃÄ¬ÈÏÖµ
 */
static inline LONG
CTRegReadString(HKEY hKey, const char *subkeyname, const char *valueName, 
                char *val, const char *defaultVal)
{
    HKEY  hk = NULL;
    LONG  ret;
    DWORD type;
    DWORD size;
    char *data = NULL;

	strcpy(val, defaultVal);
    if ( subkeyname == NULL || valueName == NULL )
    {
        return ERROR_INVALID_PARAMETER;
    }

	SYSTEM_INFO si;   
	GetNativeSystemInfo(&si);   

	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||  
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 )   
	{   
		ret = RegOpenKeyExA(hKey, subkeyname, 0, KEY_READ|KEY_WOW64_64KEY, &hk);
		if ( ret != ERROR_SUCCESS )
		{
			ret = RegOpenKeyExA(hKey, subkeyname, 0, KEY_READ|KEY_WOW64_32KEY, &hk);
			if ( ret != ERROR_SUCCESS )
			{
				return ret;
			}
			
		} 
	}  
	else
	{
		ret = RegOpenKeyExA(hKey, subkeyname, 0, KEY_READ, &hk);
		if ( ret != ERROR_SUCCESS )
		{
			return ret;
		}
	}

    size = 0;
    ret = RegQueryValueExA(hk, valueName, NULL, &type, NULL, &size);
    if ( ret != ERROR_MORE_DATA && ret != ERROR_SUCCESS )
    {
        goto EXIT;
    }
    if ( type != REG_SZ )
    {
        ret  = ERROR_INVALID_DATA;
    }

    data = (char *)malloc(size);
    if ( data == NULL )
    {
        ret = ERROR_INSUFFICIENT_BUFFER;
        goto EXIT;
    }
    ret = RegQueryValueExA(hk, valueName, NULL, &type, (LPBYTE)data, &size);
    if ( ret == ERROR_SUCCESS )
    {
        if ( type == REG_SZ )
        {
			strcpy(val, data);
        }
        else
        {
            ret = ERROR_INVALID_DATA;
        }
    }

EXIT:
    RegCloseKey(hk);
    if ( data )
    {
        free(data);
    }
    return ret;
}

/**
 * @brief  ¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿
 *
 * @param[in]	strServerAddr  ¿¿¿¿¿¿¿¿¿¿¿¿,eg: http://192.168.4.13:8001 ¿ http://ivycloud-local.com
 * @param[out]	strBroadIp     ¿¿¿¿,eg:  239.1.4.13
 * @return	TRUE   ¿¿
 *          FALSE  ¿¿

 * @note
 */
BOOL GetBroadIpFromDomain(char *strServerAddr, char *strBroadIp)
{
	BOOL bRet = FALSE;
	struct hostent *remoteHost;         
	struct in_addr addr; 
	char *cTempBegin = NULL;
	char *cTempMao = NULL;
	char *cTempDou = NULL;
	char strTempTrap[256] = "239.1.1.1";

	if(NULL == strServerAddr || NULL == strBroadIp){
		goto T_OUT;
	}

	cTempBegin = strstr(strServerAddr, "http://");
	if(NULL == cTempBegin)
	{
		cTempBegin = strServerAddr;
	}
	else
	{
		cTempBegin += strlen("http://");
	}

	if (NULL != cTempBegin)
	{
		if (NULL != (cTempMao = strstr(cTempBegin, ":")))
		{
			strncpy(strTempTrap, cTempBegin, cTempMao - cTempBegin);
			strTempTrap[cTempMao - cTempBegin] = '\0';
		}
		else
		{
			OutputDebugStringA("mao is null");
			strcpy(strTempTrap, cTempBegin);
		}
	}
	else
	{
		OutputDebugStringA("mao is null");
	}

	remoteHost = gethostbyname(strTempTrap);
	if(remoteHost == NULL)
	{
		printf("gethostbyname failed\n");
		goto T_OUT;
	}
	else
	{
		for( int i = 0; ; i++ )
		{
			if(remoteHost->h_addr_list[i] != 0)
			{	
				addr.s_addr = *(u_long*)remoteHost->h_addr_list[i];  
				strcpy(strTempTrap, inet_ntoa(addr));

				if (NULL != (cTempDou = strstr((char*)strTempTrap, ".")))
				{
					if (NULL != (cTempDou = strstr(cTempDou + 1, ".")))
					{
						sprintf(strBroadIp, "239.1.%s", cTempDou + 1);
					}
				}

				break;
			}
		}
	}

	bRet = TRUE;
T_OUT:

	return bRet;
}

#endif
