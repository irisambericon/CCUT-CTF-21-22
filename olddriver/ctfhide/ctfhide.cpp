#include <Windows.h>
#include <stdio.h>
#include <objbase.h>
#include "resource.h"

void FreeRes_ShowError(char* pszText)
{
	LPWSTR szErr = { 0 };
	LPCWSTR formatStr = L"%s Error[%d]\n";
	::wsprintf(szErr, formatStr, pszText, ::GetLastError());
}


BOOL FreeMyResource(UINT uiResouceName, LPCWSTR lpszResourceType, char* lpszSaveFileName)
{
	HRSRC hRsrc = ::FindResource(NULL, MAKEINTRESOURCE(uiResouceName), lpszResourceType);
	if (NULL == hRsrc)
	{
		FreeRes_ShowError((char *)"FindResource");
		return FALSE;
	}
	DWORD dwSize = ::SizeofResource(NULL, hRsrc);
	if (0 >= dwSize)
	{
		FreeRes_ShowError((char *)"SizeofResource");
		return FALSE;
	}
	HGLOBAL hGlobal = ::LoadResource(NULL, hRsrc);
	if (NULL == hGlobal)
	{
		FreeRes_ShowError((char *)"LoadResource");
		return FALSE;
	}
	LPVOID lpVoid = ::LockResource(hGlobal);
	if (NULL == lpVoid)
	{
		FreeRes_ShowError((char *)"LockResource");
		return FALSE;
	}

	FILE* fp = NULL;
	fopen_s(&fp, lpszSaveFileName, "wb+");
	if (NULL == fp)
	{
		FreeRes_ShowError((char *)"LockResource");
		return FALSE;
	}
	fwrite(lpVoid, sizeof(char), dwSize, fp);
	fclose(fp);

	return TRUE;
}



#define  CWK_DVC_SEND_PID \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x914,METHOD_BUFFERED, \
	FILE_WRITE_DATA)


#define  CWK_DVC_RECV_STR \
	(ULONG)CTL_CODE( \
	FILE_DEVICE_UNKNOWN, \
	0x895,METHOD_BUFFERED, \
	FILE_READ_DATA)

#define CWK_DEV_SYM L"\\\\.\\n0val1s_2780f9d7"

int main() {
	puts("i have a companion.pay more attension on him!\n");
	puts("but i am quite significant too...");

	//GUID guid1;
	//char guid_buf[64] = { 0 };

	//if (::CoCreateGuid(&guid1)) {
	//	printf("gen guid error!\n");
	//	exit(0);
	//}
	//snprintf(guid_buf, sizeof(guid_buf),
	//	"%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X",
	//	guid1.Data1, guid1.Data2, guid1.Data3,
	//	guid1.Data4[0], guid1.Data4[1], guid1.Data4[2],
	//	guid1.Data4[3], guid1.Data4[4], guid1.Data4[5],
	//	guid1.Data4[6], guid1.Data4[7]);

	//printf("guid: %s\n", guid_buf);


	char szSaveName[20] = "hidden.txt";
	LPCWSTR resType = L"CTFRES";
	BOOL bRet = FreeMyResource(IDR_CTFRES2, resType, szSaveName);
	if (FALSE == bRet)
	{
		puts("release secret error!\n");
		exit(0);
	}




	DWORD pid = 0;
	pid = ::GetCurrentProcessId();
	LPVOID lpPid = &pid;
	printf("pid:%d\n", pid);


	//Sleep(5000);

	HANDLE device = NULL;
	ULONG ret_len;
	int ret = 0;


	while (1) {
		device = CreateFile(CWK_DEV_SYM, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
		if (device == INVALID_HANDLE_VALUE)
		{
			printf("Open device failed...\r\n");
			//return -1;
		}
		else
			printf("[+]Open device successful!\r\n");


		if (!DeviceIoControl(device, CWK_DVC_SEND_PID, lpPid, sizeof(lpPid), NULL, 0, &ret_len, 0))
		{
			printf("Send pid failed...\r\n");
			//ret = -2;
		}
		else {
			printf("[+]Send pid successful!\r\n");
			break;
		}
	}
	CloseHandle(device);

	system("pause");
	return 0;
}