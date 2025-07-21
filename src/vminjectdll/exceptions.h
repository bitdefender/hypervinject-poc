/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef EXCEPTIONS_H_
#define EXCEPTIONS_H_

#include <Windows.h>

_Success_(return)
BOOLEAN
ExceptionsInit(
    void
);

void
ExceptionsUninit(
    void
);

#endif // EXCEPTIONS_H_
