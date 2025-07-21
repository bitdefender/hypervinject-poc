/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef CR3_H_
#define CR3_H_

#include <Windows.h>

_Success_(return)
BOOLEAN
Cr3PageHasSelfMap(
    _In_ UINT64 Page
);

_Success_(return)
UINT64
Cr3FindSystem(
    void
);

#endif // CR3_H_
