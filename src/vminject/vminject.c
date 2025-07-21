/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <psapi.h>
#include <conio.h>

#include "..\common\common.h"

#pragma comment(lib, "shlwapi.lib")

#define MAX_VM_NAME_LEN         256
#define MAX_MOD_NAME_LEN        256


//
// EnableDebugPrivileges
//
_Success_(return)
_Check_return_
BOOLEAN
EnableDebugPrivileges(
    void
    )
{
    TOKEN_PRIVILEGES priv = { 0 };
    LUID privId = { 0 };
    HANDLE token = NULL;
    BOOLEAN res = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
    {
        printf("[ERROR] OpenProcessToken failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privId))
    {
        printf("[ERROR] LookupPrivilegeValue failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }

    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = privId;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &priv, sizeof(priv), NULL, NULL))
    {
        printf("[ERROR] AdjustTokenPrivileges failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }

    res = TRUE;

cleanup_and_exit:
    if (NULL != token)
    {
        CloseHandle(token);
    }

    return res;
}


//
// CheckVmwpProcess
//
_Success_(return)
_Check_return_
BOOLEAN
CheckVmwpProcess(
    _In_ const char *VmName,
    _In_ DWORD Pid,
    _In_ HANDLE Process
)
{
    wchar_t modName[MAX_MOD_NAME_LEN] = { 0 };
    wchar_t target[MAX_VM_NAME_LEN + 16] = { 0 };
    size_t targetLen;

    DWORD ret = GetProcessImageFileNameW(Process, modName, ARRAYSIZE(modName));
    if (ret == 0)
    {
        return FALSE;
    }

    if (NULL == StrStrNIW(modName, u"Windows\\System32\\vmwp.exe", ARRAYSIZE(modName)))
    {
        return FALSE;
    }

    if (0 == MultiByteToWideChar(CP_UTF8, 0, VmName, -1, target, MAX_VM_NAME_LEN))
    {
        printf("[ERROR] Could not convert VM name to unicode!\n");
        return FALSE;
    }

    if (0 != wcscat_s(target, ARRAYSIZE(target), u":PIC"))
    {
        return FALSE;
    }

    targetLen = wcsnlen_s(target, ARRAYSIZE(target)) * 2;


    printf("[INFO] Will search for: '%S' in process %u...\n", target, Pid);

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    for (UINT64 ptr = 0x10000; ; ptr += mbi.RegionSize)
    {
        if (!VirtualQueryEx(Process, (LPCVOID)ptr, &mbi, sizeof(mbi)))
        {
            break;
        }

        if (mbi.RegionSize == 0)
        {
            break;
        }

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_EXECUTE_READ)
        {
            continue;
        }


        // Read the entire memory region, and search for the VM name.
        PBYTE p = malloc(mbi.RegionSize);
        if (NULL == p)
        {
            break;
        }

        if (!ReadProcessMemory(Process, (LPCVOID)ptr, p, mbi.RegionSize, NULL) &&
            GetLastError() != ERROR_PARTIAL_COPY)
        {
            free(p);
            continue;
        }

        for (SIZE_T i = 0; i < mbi.RegionSize - targetLen; i++)
        {
            if (0 == memcmp((wchar_t *)(p + i), target, targetLen))
            {
                free(p);
                return TRUE;
            }
        }

        free(p);
    }

    return FALSE;
}


//
// FindVmwpProcess
//
DWORD 
FindVmwpProcess(
    _In_ const char *VmName
    )
{
    DWORD *pids = NULL, vmwpPid = 0, cb = 100, cnt = 0;

    // Enumerate all the running processes.
    while (TRUE)
    {
        cb *= 2;

        if (NULL != pids)
        {
            free(pids);

            pids = NULL;
        }

        pids = (DWORD *)calloc(cb, sizeof(DWORD));
        if (NULL == pids)
        {
            printf("[ERROR] calloc failed for %d entries!\n", cb);
            return 0;
        }

        if (!EnumProcesses(pids, cb, &cnt))
        {
            printf("[ERROR] EnumProcesses failed: 0x%08x!\n", GetLastError());
            return 0;
        }

        if (cnt < cb)
        {
            // Returned size less than allocated size, we've got all the processes.
            cnt = cnt / 4;
            break;
        }
    }

    printf("[INFO] Got %d processes; searching for vmwp.exe...\n", cnt);

    // Search for the vmwp.exe process that runs the target virtual machine.
    for (DWORD i = 0; i < cnt; i++)
    {
        HANDLE hProc;

        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
        if (NULL == hProc)
        {
            continue;
        }

        BOOLEAN res = CheckVmwpProcess(VmName, pids[i], hProc);

        CloseHandle(hProc);

        if (res)
        {
            vmwpPid = pids[i];
            break;
        }
    }

    free(pids);

    return vmwpPid;
}


//
// main
//
int main(
    int argc, 
    char *argv[]
    )
{
    HANDLE hProcess, hThread;
    FARPROC pProc;
    SIZE_T written;
    PVOID pRemoteAddress, pMod;
    PBYTE pArgument;
    DWORD pid, tid, injPid;
    MODULEINFO modInfo;
    VMINJECT_PARAMETER param = { 0 };
    const char *vmName = NULL;
    int exitcode = -1;

    // preinit vars.
    hProcess = hThread = NULL;
    pRemoteAddress = NULL;
    pArgument = NULL;
    written = 0;
    pProc = NULL;

    if (argc < 2)
    {
        printf("Usage: vminject VM PID\n");
        printf("        * VM  is the name of the target Virtual Machine.\n");
        printf("        * PID is the ID of the process running inside the VM, inside which the injection will be performed.\n");
        printf("NOTE: the target VM must already be running.\n");
        return -1;
    }

    // Get the target PID for injection, inside the VM.
    vmName = argv[1];

    if (strlen(vmName) >= MAX_VM_NAME_LEN)
    {
        printf("[ERROR] VM name is too long! Must be less than 256 characters.\n");
        return -1;
    }

    injPid = atoi(argv[2]);

    printf("[INFO] Will inject code inside process PID %u inside the VM...\n", injPid);

    // Copy parameters.
    param.Pid = injPid;


    //
    // Enable debug privilege.
    //
    if (!EnableDebugPrivileges())
    {
        printf("[ERROR] EnableDebugPrivileges failed!\n");
        return -1;
    }


    //
    // Find a vmwp.exe process. Note that we expect a single vmwp.exe process to be present - if multiple such
    // processes are present, one should find out which process belongs to which VM.
    //
    pid = FindVmwpProcess(vmName);
    if (0 == pid)
    {
        printf("[ERROR] Could not find a vmwp.exe process!");
        return -1;
    }

    printf("[INFO] vmwp.exe found, PID %d\n", pid);


    //
    // Open the virtual machine worker process.
    //
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    if (NULL == hProcess)
    {
        printf("[ERROR] OpenProcess failed: 0x%08x!\n", GetLastError());
        return -1;
    }


    //
    // Load vminjectdll.dll in our VA space.
    //
    pMod = LoadLibraryA("vminjectdll.dll");
    if (NULL == pMod)
    {
        printf("[ERROR] LoadLibraryA failed forvminjectdll.dll: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }

    printf("[INFO] Loaded vminjectdll module at: 0x%016llx\n", (SIZE_T)pMod);


    //
    // Get module information.
    //
    if (!GetModuleInformation(GetCurrentProcess(), pMod, &modInfo, sizeof(modInfo)))
    {
        printf("[ERROR] GetModuleInformation failed for vminjectdll.dll: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }


    //
    // Get the main injection function address. This will carry out the injection inside vmwp.exe process.
    //
    pProc = GetProcAddress(pMod, "Inject");
    if (NULL == pProc)
    {
        printf("[ERROR] GetProcAddress failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }
    
    
    //
    // Alloc memory at the same address inside the vmwp.exe process. This may fail sometimes, but it's good enough for a PoC.
    // This allows us to just copy our instance of the vminjectdll inside the vmwp.exe process, without worrying about
    // relocations.
    //
    pRemoteAddress = VirtualAllocEx(hProcess, pMod, modInfo.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NULL == pRemoteAddress)
    {
        printf("[ERROR] VirtualAllocEx for load failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }
    
    printf("[INFO] Allocated memory for module at: 0x%016llx\n", (UINT64)pRemoteAddress);
    
    if (!WriteProcessMemory(hProcess, pMod, pMod, modInfo.SizeOfImage, &written))
    {
        printf("[ERROR] WriteProcessMemory for load failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }


    //
    // Alloc memory & write the target PID. This works as the parameter for the remote thread we're about to create.
    //
    pArgument = VirtualAllocEx(hProcess, NULL, sizeof(VMINJECT_PARAMETER), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pArgument)
    {
        printf("[ERROR] VirtualAllocEx for argument failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }

    printf("[INFO] Allocated memory for argument at: 0x%016llx\n", (UINT64)pArgument);

    if (!WriteProcessMemory(hProcess, pArgument, &param, sizeof(param), &written))
    {
        printf("[ERROR] WriteProcessMemory for argument failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }


    //
    // Call the injection function.
    //
    printf("[INFO] Starting thread at: 0x%016llx\n", (UINT64)pProc);

    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pProc, pArgument, 0, NULL, &tid);
    if (NULL == hThread)
    {
        printf("[ERROR] CreateRemoteThreadEx failed: 0x%08x!\n", GetLastError());
        goto cleanup_and_exit;
    }


    //
    // Wait for injection to finish.
    //
    printf("[INFO] Waiting for the thread to finish...\n");
    
    WaitForSingleObject(hThread, INFINITE);

    Sleep(1000);

    exitcode = 0;


cleanup_and_exit:
    if (hThread != NULL)
    {
        CloseHandle(hThread);
    }

    if (pArgument != NULL)
    {
        VirtualFreeEx(hProcess, pArgument, 0, MEM_RELEASE);
    }

    if (pRemoteAddress != NULL)
    {
        VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
    }

    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
    }

    printf("[INFO] Done: %d!\n", exitcode);

    return exitcode;
}
