/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "nt.h"
#include "log.h"
#include "memory.h"

// SYSCALL bindings.
typedef struct SYSCALL_DESCRIPTOR
{
    const char *Name;               // SYSCALL name.
    DWORD       Rva;                // RVA inside ntoskrnl.exe

    struct
    {
        DWORD   NtBuildNumberMin;   // Minimum NtBuildNumber the SYSCALL number applies to.
        DWORD   NtBuildNumberMax;   // Maximum NtBuildNumber the SYSCALL number applies to.
        DWORD   SyscallNumber;      // SYSCALL number.
    } Build[16];
} SYSCALL_DESCRIPTOR;

static SYSCALL_DESCRIPTOR gSyscalls[] = 
{
    {
        .Name = "ZwOpenProcess",
        .Build = {
            {
                .NtBuildNumberMin = 10240,
                .NtBuildNumberMax = 26100,
                .SyscallNumber = 0x26
            },

            {
                .NtBuildNumberMin = 9600,
                .NtBuildNumberMax = 9600,
                .SyscallNumber = 0x25
            },
        },
    },

    {
        .Name = "ZwAllocateVirtualMemory",
        .Build = {
            {
                .NtBuildNumberMin = 10240,
                .NtBuildNumberMax = 26100,
                .SyscallNumber = 0x18,
            },

            {
                .NtBuildNumberMin = 9600,
                .NtBuildNumberMax = 9600,
                .SyscallNumber = 0x17,
            },
        },
    },

    {
        .Name = "ZwWriteVirtualMemory",
        .Build = {
            {
                .NtBuildNumberMin = 10240,
                .NtBuildNumberMax = 26100,
                .SyscallNumber = 0x3A,
            },

            {
                .NtBuildNumberMin = 9600,
                .NtBuildNumberMax = 9600,
                .SyscallNumber = 0x39,
            },
        }
    },

    {
        .Name = "ZwCreateThreadEx",
        .Build = {
            {
                .NtBuildNumberMin = 26100,
                .NtBuildNumberMax = 30000,
                .SyscallNumber = 0xC9,
            },

            {
                .NtBuildNumberMin = 22621,
                .NtBuildNumberMax = 22631,
                .SyscallNumber = 0xC7,
            },

            {
                .NtBuildNumberMin = 22000,
                .NtBuildNumberMax = 22000,
                .SyscallNumber = 0xC6,
            },

            {
                .NtBuildNumberMin = 19044,
                .NtBuildNumberMax = 19045,
                .SyscallNumber = 0xC2,
            },

            {
                .NtBuildNumberMin = 19041,
                .NtBuildNumberMax = 19043,
                .SyscallNumber = 0xC1,
            },

            {
                .NtBuildNumberMin = 18362,
                .NtBuildNumberMax = 18363,
                .SyscallNumber = 0xBD,
            },

            {
                .NtBuildNumberMin = 17763,
                .NtBuildNumberMax = 17763,
                .SyscallNumber = 0xBC,
            },

            {
                .NtBuildNumberMin = 17134,
                .NtBuildNumberMax = 17134,
                .SyscallNumber = 0xBB,
            },

            {
                .NtBuildNumberMin = 16299,
                .NtBuildNumberMax = 16299,
                .SyscallNumber = 0xBA,
            },

            {
                .NtBuildNumberMin = 15063,
                .NtBuildNumberMax = 15063,
                .SyscallNumber = 0xB9,
            },

            {
                .NtBuildNumberMin = 14393,
                .NtBuildNumberMax = 14393,
                .SyscallNumber = 0xB6,
            },

            {
                .NtBuildNumberMin = 10586 ,
                .NtBuildNumberMax = 10586 ,
                .SyscallNumber = 0xB4,
            },

            {
                .NtBuildNumberMin = 10240,
                .NtBuildNumberMax = 10240,
                .SyscallNumber = 0xB3,
            },

            {
                .NtBuildNumberMin = 9600,
                .NtBuildNumberMax = 9600,
                .SyscallNumber = 0xB0,
            },
        },
    },
};


// Basic nt information.
UINT64 gNtoskrnlBase;
DWORD gNtoskrnlSize;
PBYTE gNtoskrnlBuffer;

// MZ/PE data structures.
IMAGE_DOS_HEADER gDosHeader;
IMAGE_NT_HEADERS gNthHeader;
IMAGE_SECTION_HEADER gSecHeaders[64];
IMAGE_EXPORT_DIRECTORY gExportDirectory;
WORD gSecCount;


//
// NtoskrnlInit
//
_Use_decl_annotations_
BOOLEAN
NtoskrnlInit(
    _In_ UINT64 Address,
    _In_ UINT64 Cr3
)
{
    //
    // Read the DOS header.
    //
    if (!MemReadWriteVirtuallMemory(Address, Cr3, sizeof(gDosHeader), &gDosHeader, FALSE))
    {
        return FALSE;
    }

    if (gDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }


    //
    // Read the NT headers.
    //
    if (!MemReadWriteVirtuallMemory(Address + gDosHeader.e_lfanew, Cr3, sizeof(gNthHeader), &gNthHeader, FALSE))
    {
        return FALSE;
    }

    if (gNthHeader.Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }


    //
    // Read the export directory.
    //
    DWORD expRva, expSize;

    expRva  = gNthHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    expSize = gNthHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (expRva == 0 || expSize == 0)
    {
        return FALSE;
    }

    if (!MemReadWriteVirtuallMemory(Address + expRva, Cr3, sizeof(gExportDirectory), &gExportDirectory, FALSE))
    {
        return FALSE;
    }


    //
    // Read the export DLL name.
    //
    if (gExportDirectory.Name == 0)
    {
        return FALSE;
    }

    char name[32] = { 0 };

    // Read te name & make sure it's "ntoskrnl.exe".
    if (!MemReadWriteVirtuallMemory(Address + gExportDirectory.Name, Cr3, sizeof(name), &name, FALSE))
    {
        return FALSE;
    }

    if (0 != memcmp(name, "ntoskrnl.exe", sizeof("ntoskrnl.exe")))
    {
        return FALSE;
    }


    //
    // Read the first few section headers.
    //
    DWORD secRva = gDosHeader.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + gNthHeader.FileHeader.SizeOfOptionalHeader;

    gSecCount = min(ARRAYSIZE(gSecHeaders), gNthHeader.FileHeader.NumberOfSections);

    if (!MemReadWriteVirtuallMemory(Address + secRva, Cr3, sizeof(IMAGE_SECTION_HEADER) * gSecCount, &gSecHeaders, FALSE))
    {
        return FALSE;
    }


    //
    // Initialize global data & read the entire image.
    //
    gNtoskrnlBase = Address;
    gNtoskrnlSize = gNthHeader.OptionalHeader.SizeOfImage;

    gNtoskrnlBuffer = (PBYTE)VirtualAlloc(NULL, gNtoskrnlSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NULL == gNtoskrnlBuffer)
    {
        LogValue("[ERROR] Could not allocate memory for ntoskrnl.exe buffer: ", gNtoskrnlSize);
        return FALSE;
    }

    for (UINT64 addr = Address; addr < Address + gNtoskrnlSize; addr += 0x1000)
    {
        // We don't care about failures. Some reads WILL fail, if the pages are swapped out.
        MemReadWriteVirtuallMemory(addr, Cr3, 0x1000, &gNtoskrnlBuffer[addr - Address], FALSE);
    }

    LogValue("[INFO] ntoskrnl.exe base: ", gNtoskrnlBase);
    LogValue("[INFO] ntoskrnl.exe size: ", gNtoskrnlSize);

    return TRUE;
}


//
// NtoskrnlUninit
//
void
NtoskrnlUninit(
    void
)
{
    if (NULL != gNtoskrnlBuffer)
    {
        VirtualFree(gNtoskrnlBuffer, 0, MEM_RELEASE);
        gNtoskrnlBuffer = NULL;
    }
}


//
// NtoskrnlFetchData
//
_Success_(return)
_Check_return_
static BOOLEAN
NtoskrnlFetchData(
    _In_ UINT64 Rva,
    _In_ SIZE_T Size,
    _Out_ PVOID Buffer
)
{
    if (Rva >= gNtoskrnlSize)
    {
        return FALSE;
    }

    if (Size > gNtoskrnlSize)
    {
        return FALSE;
    }

    if (Rva + Size > gNtoskrnlSize)
    {
        return FALSE;
    }

    memcpy(Buffer, gNtoskrnlBuffer + Rva, Size);

    return TRUE;
}


//
// NtoskrnlFindExportByName
//
_Use_decl_annotations_
BOOLEAN
NtoskrnlFindExportByName(
    _In_z_ const char *ExportName,
    _Out_ DWORD *ExportRva
)
{
    size_t expNameLen = strlen(ExportName);
    if (expNameLen >= MAX_EXPORT_NAME_LEN)
    {
        return FALSE;
    }

    if (NULL == gNtoskrnlBuffer)
    {
        return FALSE;
    }

    // A binary search would be faster.
    for (UINT64 i = 0; i < gExportDirectory.NumberOfNames; i++)
    {
        DWORD rva;
        WORD ordinal;
        char expName[MAX_EXPORT_NAME_LEN];

        // Read current name RVA.
        if (!NtoskrnlFetchData(gExportDirectory.AddressOfNames + i * 4ull, 4, &rva))
        {
            return FALSE;
        }

        // Read the name.
        if (!NtoskrnlFetchData(rva, sizeof(expName), (PBYTE)&expName))
        {
            return FALSE;
        }

        if (0 != memcmp(expName, ExportName, expNameLen + 1))
        {
            continue;
        }

        // Get export ordinal.
        if (!NtoskrnlFetchData(gExportDirectory.AddressOfNameOrdinals + i * 2ull, sizeof(ordinal), &ordinal))
        {
            return FALSE;
        }

        // Read the address of export.
        if (!NtoskrnlFetchData(gExportDirectory.AddressOfFunctions + ordinal * 4ull, sizeof(rva), &rva))
        {
            return FALSE;
        }

        *ExportRva = rva;

        return TRUE;
    }

    return FALSE;
}


//
// FindSyscalls
//
_Use_decl_annotations_
BOOLEAN
NtoskrnlFindSyscalls(
    _Out_ SYSCALLS *Syscalls
)
{
    PIMAGE_SECTION_HEADER pSecText = NULL;
    DWORD count = 0, ntBuildNumber;

    if (NULL == gNtoskrnlBuffer)
    {
        return FALSE;
    }

    //
    // Get NtBuildNumber export RVA.
    //
    if (!NtoskrnlFindExportByName("NtBuildNumber", &ntBuildNumber))
    {
        LogMessage("[ERROR] Could not locate the NtBuildNunber export!\n");
        return FALSE;
    }

    if (!NtoskrnlFetchData(ntBuildNumber, 4, &ntBuildNumber))
    {
        LogMessage("[ERROR] Could not read the NtBuildNunber value!\n");
        return FALSE;
    }

    ntBuildNumber &= 0xFFFF;

    LogValue("[INFO] NtBuildNumber: ", ntBuildNumber);


    //
    // Get the .text section.
    //
    for (WORD i = 0; i < gSecCount; i++)
    {
        if (0 == memcmp(gSecHeaders[i].Name, ".text\0\0\0", 8))
        {
            pSecText = &gSecHeaders[i];
            break;
        }
    }

    if (NULL == pSecText)
    {
        LogMessage("[ERROR] Could not locate the .text section!\n");
        return FALSE;
    }

    LogValue("[INFO] Found .text section at RVA: ", pSecText->VirtualAddress);


    //
    // Find KiServiceLinkage stubs.
    //
    for (DWORD addr = pSecText->VirtualAddress, size = 0; size < pSecText->Misc.VirtualSize; addr += 0x10, size += 0x10)
    {
        const BYTE targetPattern[] = {
            0x48, 0x8b, 0xc4, 0xfa, 0x48, 0x83, 0xec, 0x10, 
            0x50, 0x9c, 0x6a, 0x10,
        };

        BYTE data[0x20];

        // This is the pattern we expect to find:
        // fffff806`c0ea20f0 488bc4          mov     rax,rsp
        // fffff806`c0ea20f3 fa              cli
        // fffff806`c0ea20f4 4883ec10        sub     rsp,10h
        // fffff806`c0ea20f8 50              push    rax
        // fffff806`c0ea20f9 9c              pushfq
        // fffff806`c0ea20fa 6a10            push    10h
        // fffff806`c0ea20fc 488d053d4a0000  lea     rax,[nt!KiServiceLinkage (fffff806`c0ea6b40)]
        // fffff806`c0ea2103 50              push    rax
        // fffff806`c0ea2104 b8c9000000      mov     eax,0C9h
        // fffff806`c0ea2109 e9b25f0100      jmp     nt!KiServiceInternal (fffff806`c0eb80c0)  Branch

        if (!NtoskrnlFetchData(addr, sizeof(data), data))
        {
            continue;
        }

        if (memcmp(data, targetPattern, sizeof(targetPattern)))
        {
            continue;
        }

        DWORD syscall = *((DWORD *)&data[0x15]);

        for (DWORD i = 0; i < ARRAYSIZE(gSyscalls); i++)
        {
            for (DWORD j = 0; j < ARRAYSIZE(gSyscalls[i].Build); j++)
            {
                if (ntBuildNumber < gSyscalls[i].Build[j].NtBuildNumberMin ||
                    ntBuildNumber > gSyscalls[i].Build[j].NtBuildNumberMax)
                {
                    continue;
                }

                if (syscall == gSyscalls[i].Build[j].SyscallNumber)
                {
                    gSyscalls[i].Rva = addr;
                    count++;
                }
            }
        }

        if (count == ARRAYSIZE(gSyscalls))
        {
            Syscalls->ZwOpenProcess = gNtoskrnlBase + gSyscalls[0].Rva;
            Syscalls->ZwAllocateVirtualMemory = gNtoskrnlBase + gSyscalls[1].Rva;
            Syscalls->ZwWriteVirtualMemory = gNtoskrnlBase + gSyscalls[2].Rva;
            Syscalls->ZwCreateThreadEx = gNtoskrnlBase + gSyscalls[3].Rva;

            return TRUE;
        }
    }

    return FALSE;
}


//
// NtoskrnlFindHookableInstruction
//
_Use_decl_annotations_
UINT64
NtoskrnlFindHookableInstruction(
    void
)
{
    if (NULL == gNtoskrnlBuffer)
    {
        return 0;
    }

    for (DWORD addr = 0x1000; addr < gNtoskrnlSize; addr++)
    {
        BYTE pattern[5] = { 0 };

        if (!NtoskrnlFetchData(addr, sizeof(pattern), pattern))
        {
            continue;
        }

        // Searching for the following sequence:
        // 48 8B 55 C0      mov         rdx, qword [rbp - 0x40]
        // FB               sti
        if (pattern[0] == 0x48 &&
            pattern[1] == 0x8B &&
            pattern[2] == 0x55 &&
            pattern[3] == 0xC0 &&
            pattern[4] == 0xFB)
        {
            return gNtoskrnlBase + addr;
        }
    }

    return 0;
}


//
// NtoskrnlFindSlackSpace
//
_Use_decl_annotations_
UINT64 
NtoskrnlFindSlackSpace(
    _In_ DWORD Size
)
{
    if (NULL == gNtoskrnlBuffer)
    {
        return 0;
    }

    for (DWORD i = 0; i < gSecCount; i++)
    {
        if ((gSecHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (gSecHeaders[i].Characteristics & IMAGE_SCN_MEM_NOT_PAGED) &&
            (gNthHeader.OptionalHeader.SectionAlignment - (gSecHeaders[i].Misc.VirtualSize & 0xFFF) >= Size))
        {
            return gNtoskrnlBase + gSecHeaders[i].VirtualAddress + gSecHeaders[i].Misc.VirtualSize;
        }
    }

    return 0;
}
