/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "vid.h"
#include "log.h"

PFUNC_VidReadMemoryBlockPageRange VidReadMemoryBlockPageRange;
PFUNC_VidWriteMemoryBlockPageRange VidWriteMemoryBlockPageRange;
PFUNC_VidGetVirtualProcessorState VidGetVirtualProcessorState;

_Use_decl_annotations_
BOOLEAN
VidInit(
    void
)
{
    HANDLE hVid;

    hVid = GetModuleHandleA("vid.dll");
    if (NULL == hVid)
    {
        LogValue("[ERROR] Could not find vid.dll: ", GetLastError());
        return FALSE;
    }

    VidReadMemoryBlockPageRange = (PFUNC_VidReadMemoryBlockPageRange)GetProcAddress(hVid, "VidReadMemoryBlockPageRange");
    if (NULL == VidReadMemoryBlockPageRange)
    {
        LogValue("[ERROR] Could not find VidReadMemoryBlockPageRange: ", GetLastError());
        return FALSE;
    }

    VidWriteMemoryBlockPageRange = (PFUNC_VidWriteMemoryBlockPageRange)GetProcAddress(hVid, "VidWriteMemoryBlockPageRange");
    if (NULL == VidWriteMemoryBlockPageRange)
    {
        LogValue("[ERROR] Could not find VidWriteMemoryBlockPageRange: ", GetLastError());
        return FALSE;
    }

    VidGetVirtualProcessorState = (PFUNC_VidGetVirtualProcessorState)GetProcAddress(hVid, "VidGetVirtualProcessorState");
    if (NULL == VidGetVirtualProcessorState)
    {
        LogValue("[ERROR] Could not find VidGetVirtualProcessorState: ", GetLastError());
        return FALSE;
    }

    return TRUE;
}


//
// VidUninit
//
void
VidUninit(
    void
)
{

}
