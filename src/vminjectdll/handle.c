/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "handle.h"
#include <winternl.h>

typedef NTSTATUS 
(NTAPI *PFUNC_NtQueryObject)(
    HANDLE, DWORD, PVOID, ULONG, PULONG
);

typedef struct _OBJECT_TYPE_INFORMATION 
{
    UNICODE_STRING TypeName;
} OBJECT_TYPE_INFORMATION;


//
// HandleIsFile
//
_Use_decl_annotations_
BOOLEAN
HandleIsFile(
    _In_ HANDLE Handle
)
{
    BYTE buffer[1024] = { 0 };
    ULONG retLen = 0;

    NTSTATUS status = NtQueryObject(Handle, ObjectTypeInformation, buffer, sizeof(buffer), &retLen);
    if (0 != status)
    {
        return FALSE;
    }

    OBJECT_TYPE_INFORMATION *obtype = (OBJECT_TYPE_INFORMATION *)buffer;

    if (obtype->TypeName.Length != 8)
    {
        return FALSE;
    }

    if (0 != memcmp(obtype->TypeName.Buffer, u"File", 8))
    {
        return FALSE;
    }

    return TRUE;
}
