/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef LOG_H_
#define LOG_H_

#include <Windows.h>

_Success_(return)
BOOLEAN
LogInit(
    void
);

void
LogUninit(
    void
);

void
LogMessage(
    _In_z_ const char *Message
);

void
LogValue(
    _In_z_ const char *Message,
    _In_ UINT64 Value
);

#endif // LOG_H_
