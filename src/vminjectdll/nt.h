/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef NT_H_
#define NT_H_

#include <Windows.h>

#define MAX_EXPORT_NAME_LEN     64

typedef struct SYSCALLS
{
    UINT64      ZwOpenProcess;
    UINT64      ZwAllocateVirtualMemory;
    UINT64      ZwWriteVirtualMemory;
    UINT64      ZwCreateThreadEx;
} SYSCALLS;


_Success_(return)
_Check_return_
BOOLEAN
NtoskrnlInit(
    _In_ UINT64 Address,
    _In_ UINT64 Cr3
);

void
NtoskrnlUninit(
    void
);

_Success_(return)
_Check_return_
BOOLEAN
NtoskrnlFindExportByName(
    _In_z_ const char *ExportName,
    _Out_ DWORD *ExportRva
);

_Success_(return)
_Check_return_
BOOLEAN
NtoskrnlFindSyscalls(
    _Out_ SYSCALLS *Syscalls
);

_Success_(return)
_Check_return_
UINT64
NtoskrnlFindHookableInstruction(
    void
);

_Success_(return)
_Check_return_
UINT64
NtoskrnlFindSlackSpace(
    _In_ DWORD Size
);

#endif // NT_H_
