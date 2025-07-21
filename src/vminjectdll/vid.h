/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef VID_H_
#define VID_H_

#include <Windows.h>

typedef union _REGISTER_VALUE
{
    UINT64  Reg128[2];
    UINT64  Reg64;
    UINT32  Reg32;
    UINT16  Reg16;
    UINT8   Reg8;
} REGISTER_VALUE;


typedef BOOL 
(WINAPI *PFUNC_VidReadMemoryBlockPageRange)(
    UINT64 Partition,
    UINT64 MemoryBlock,
    UINT64 PageFrame,
    UINT64 PageCount,
    PVOID  Buffer,
    UINT64 BufferSize
    );

typedef BOOL 
(WINAPI *PFUNC_VidWriteMemoryBlockPageRange)(
    UINT64 Partition,
    UINT64 MemoryBlock,
    UINT64 PageFrame,
    UINT64 PageCount,
    PVOID  Buffer,
    UINT64 BufferSize
    );

typedef BOOL 
(WINAPI *PFUNC_VidGetVirtualProcessorState)(
    UINT64 Partition,
    UINT64 VpIndex,
    UINT32 *ProcessorStateCodeArray,
    UINT8 ProcessorStateCodeCount,
    REGISTER_VALUE *ProcessorStateOutputArray
    );


// Required VID API.
extern PFUNC_VidReadMemoryBlockPageRange VidReadMemoryBlockPageRange;
extern PFUNC_VidWriteMemoryBlockPageRange VidWriteMemoryBlockPageRange;
extern PFUNC_VidGetVirtualProcessorState VidGetVirtualProcessorState;


_Success_(return)
BOOLEAN
VidInit(
    void
);

void
VidUninit(
    void
);

#endif // VID_H_
