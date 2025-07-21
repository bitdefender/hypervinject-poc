/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "cr3.h"
#include "memory.h"

#define MIN_CR3_SCAN                        0x0010000
#define MAX_CR3_SCAN                        0x1000000


//
// Cr3PageHasSelfMap
//
_Use_decl_annotations_
BOOLEAN
Cr3PageHasSelfMap(
    _In_ UINT64 Page
)
{
    UINT64 page[0x1000 / 8];

    Page = Page & 0x000FFFFFFFFFF000;

    // We detect a valid CR3 by looking after the self-map entry.
    UINT64 self = Page | 0x8000000000000063;

    if (!MemReadWritePhysicalMemory(Page, 0x1000, (PBYTE)page, FALSE))
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < sizeof(page) / 8; i++)
    {
        if (page[i] == self)
        {
            return TRUE;
        }
    }

    return FALSE;
}


//
// Cr3FindSystem
//
_Use_decl_annotations_
UINT64
Cr3FindSystem(
    void
)
{
    for (UINT64 addr = MIN_CR3_SCAN; addr < MAX_CR3_SCAN; addr += 0x1000)
    {
        if (Cr3PageHasSelfMap(addr))
        {
            return addr;
        }
    }

    return 0;
}
