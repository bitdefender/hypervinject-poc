/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef MEMORY_H_
#define MEMORY_H_

#include <Windows.h>

_Success_(return)
BOOLEAN
MemReadWritePhysicalMemory(
    _In_ UINT64 PhysicalAddress,
    _In_ DWORD Size,
    _When_(!Write, _Out_) _When_(Write, _In_) PVOID Buffer,
    _In_ BOOLEAN Write
);

_Success_(return)
BOOLEAN
MemTranslateLinearAddress(
    _In_ UINT64 LinearAddress,
    _In_ UINT64 Cr3,
    _Out_ UINT64 *PhysicalAddress
);

_Success_(return)
BOOLEAN
MemReadWriteVirtuallMemory(
    _In_ UINT64 VirtualAddress,
    _In_ UINT64 Cr3,
    _In_ DWORD Size,
    _When_(!Write, _Out_) _When_(Write, _In_) PVOID Buffer,
    _In_ BOOLEAN Write
);

#endif // MEMORY_H_