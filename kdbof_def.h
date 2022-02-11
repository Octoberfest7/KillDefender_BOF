#pragma once
#include <windows.h>

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char * string1, const char * string2);
WINBASEAPI int __cdecl MSVCRT$sprintf(char * string1, const char * format, ...);


//KERNEL32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();



//ADVAPI32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid); //LookupPrivilegeValueW? shouldn't matter because first param we always call Null.
WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
WINADVAPI BOOL WINAPI ADVAPI32$SetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength);
WINADVAPI DWORD WINAPI ADVAPI32$GetLengthSid(PSID pSid); //DECLSPEC_IMPORT


//typedef struct _TOKEN_MANDATORY_LABEL	TOKEN_MANDATORY_LABEL;
/*
typedef struct _TOKEN_MANDATORY_LABEL {
	SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, * PTOKEN_MANDATORY_LABEL;
/*
typedef struct SID {
	BYTE                     Revision;
	BYTE                     SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
#if ...
	DWORD* SubAuthority[];
#else
	DWORD                    SubAuthority[ANYSIZE_ARRAY];
#endif
} SID, * PISID;
*/