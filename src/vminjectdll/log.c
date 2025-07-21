/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "log.h"

#define LOG_FILE    "d:\\hypervinject\\hypervinject.log"

HANDLE gLog = INVALID_HANDLE_VALUE;


//
// LogInit
//
_Use_decl_annotations_
BOOLEAN
LogInit(
    void
)
{
    gLog = CreateFileA(LOG_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    return TRUE;
}


//
// LogUninit
//
void
LogUninit(
    void
)
{
    if (gLog != INVALID_HANDLE_VALUE)
    {
        CloseHandle(gLog);
    }
}


//
// LogMessage
//
_Use_decl_annotations_
void
LogMessage(
    _In_z_ const char *Message
)
{
    DWORD written;

    // Skip logging if we couldn't create the log file.
    if (gLog == INVALID_HANDLE_VALUE)
    {
        return;
    }

    WriteFile(gLog, Message, (DWORD)strlen(Message), &written, NULL);

    FlushFileBuffers(gLog);
}


//
// LogValue
//
_Use_decl_annotations_
void
LogValue(
    _In_z_ const char *Message,
    _In_ UINT64 Value
    )
{
    DWORD written;
    char val[32] = { 0 };
    char lut[16] =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    // Skip logging if we couldn't create the log file.
    if (gLog == INVALID_HANDLE_VALUE)
    {
        return;
    }

    WriteFile(gLog, Message, (DWORD)strlen(Message), &written, NULL);

    for (int i = 0; i < 16; i++)
    {
        val[16 - i - 1] = lut[Value & 0xF];

        Value >>= 4;
    }

    val[16] = '\r';
    val[17] = '\n',

    WriteFile(gLog, val, (DWORD)strlen(val), &written, NULL);

    FlushFileBuffers(gLog);
}
