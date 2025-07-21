/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "memory.h"
#include "vid.h"

extern UINT64 gPtHandle;
extern UINT64 gMbHandle;

#define PML5_INDEX(gla)         (((gla) >> (12 + 9 + 9 + 9 + 9) & 0x1FF))
#define PML4_INDEX(gla)         (((gla) >> (12 + 9 + 9 + 9) & 0x1FF))
#define PDP_INDEX(gla)          (((gla) >> (12 + 9 + 9) & 0x1FF))
#define PD_INDEX(gla)           (((gla) >> (12 + 9) & 0x1FF))
#define PT_INDEX(gla)           (((gla) >> (12) & 0x1FF))
#define CLEAN_PHYS(gpa)         ((gpa) & 0x000FFFFFFFFFF000)

//
// ReadWritePhysicalMemory
//
_Use_decl_annotations_
BOOLEAN 
MemReadWritePhysicalMemory(
    UINT64 PhysicalAddress,
    DWORD Size,
    PVOID Buffer,
    BOOLEAN Write
    )
{
    BYTE page[0x1000];
    DWORD offset = (DWORD)(PhysicalAddress & 0xFFF);
    UINT64 mbi;

    if (PhysicalAddress < 0x100000000)
    {
        mbi = gMbHandle;
    }
    else
    {
        mbi = gMbHandle + 1;
        PhysicalAddress -= 0x100000000;
    }

    if (offset + Size > 0x1000)
    {
        return FALSE;
    }

    // Read page contents. It seems that the memory block index 1 works fine for most addresses, but not if the address is above 4G?
    if (!VidReadMemoryBlockPageRange(gPtHandle, mbi, PhysicalAddress >> 12, 1, page, sizeof(page)))
    {
        return FALSE;
    }

    if (!Write)
    {
        memcpy(Buffer, page + offset, Size);
    }
    else
    {
        memcpy(page + offset, Buffer, Size);

        if (!VidWriteMemoryBlockPageRange(gPtHandle, mbi, PhysicalAddress >> 12, 1, page, sizeof(page)))
        {
            return FALSE;
        }
    }

    return TRUE;
}


//
// TranslateLinearAddress
//
_Use_decl_annotations_
BOOLEAN
MemTranslateLinearAddress(
    UINT64 LinearAddress,
    UINT64 Cr3,
    UINT64 *PhysicalAddress
    )
{
    UINT64 pml4, pdp, pd, pt, pf;
    UINT64 pml4e, pdpe, pde, pte;

    // PML4
    pml4 = CLEAN_PHYS(Cr3);

    if (!MemReadWritePhysicalMemory(pml4 + PML4_INDEX(LinearAddress) * 8, 8, (PBYTE)&pml4e, FALSE))
    {
        return FALSE;
    }

    if (0 == (pml4e & 1))
    {
        return FALSE;
    }

    // PDP
    pdp = CLEAN_PHYS(pml4e);

    if (!MemReadWritePhysicalMemory(pdp + PDP_INDEX(LinearAddress) * 8, 8, (PBYTE)&pdpe, FALSE))
    {
        return FALSE;
    }

    if (0 == (pdpe & 1))
    {
        return FALSE;
    }

    // PD
    pd = CLEAN_PHYS(pdpe);


    if (0 != (pdpe & 0x80))
    {
        *PhysicalAddress = (pd & ~0x3FFFFFFFULL) + (LinearAddress & 0x3FFFFFFFULL);
        return TRUE;
    }

    if (!MemReadWritePhysicalMemory(pd + PD_INDEX(LinearAddress) * 8, 8, (PBYTE)&pde, FALSE))
    {
        return FALSE;
    }

    if (0 == (pde & 1))
    {
        return FALSE;
    }

    // PT
    pt = CLEAN_PHYS(pde);

    if (0 != (pde & 0x80))
    {
        *PhysicalAddress = (pt & ~0x1FFFFFULL) + (LinearAddress & 0x1FFFFFULL);
        return TRUE;
    }

    if (!MemReadWritePhysicalMemory(pt + PT_INDEX(LinearAddress) * 8, 8, (PBYTE)&pte, FALSE))
    {
        return FALSE;
    }

    pf = CLEAN_PHYS(pte) + (LinearAddress & 0xFFFULL);

    *PhysicalAddress = pf;

    return TRUE;
}


//
// ReadWriteVirtuallMemory
//
_Use_decl_annotations_
BOOLEAN
MemReadWriteVirtuallMemory(
    UINT64 VirtualAddress,
    UINT64 Cr3,
    DWORD Size,
    PVOID Buffer,
    BOOLEAN Write
)
{
    DWORD read = 0;

    while (read < Size)
    {
        UINT64 phys;
        DWORD toRead = min(Size - read, 0x1000 - (VirtualAddress & 0xFFF));

        // Translate the linear address to a physical address.
        if (!MemTranslateLinearAddress(VirtualAddress, Cr3, &phys))
        {
            return FALSE;
        }

        // Read from/write to the translated physical address.
        if (!MemReadWritePhysicalMemory(phys, toRead, (PBYTE)Buffer + read, Write))
        {
            return FALSE;
        }

        read += toRead;
        VirtualAddress += toRead;
    }

    return TRUE;
}
