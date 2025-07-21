/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef HANDLE_H_
#define HANDLE_H_

#include <Windows.h>

_Success_(return)
BOOLEAN
HandleIsFile(
    _In_ HANDLE Handle
);

#endif // HANDLE_H_
