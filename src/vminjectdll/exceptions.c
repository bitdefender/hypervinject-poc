/*
 * Copyright (c) 2025 Bitdefender
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "exceptions.h"


static PVOID gExceptionHandler;


//
// ExceptionHander
//
LONG CALLBACK
ExceptionHander(
    PEXCEPTION_POINTERS ExceptionInfo
) 
{
    if (STATUS_INVALID_HANDLE == ExceptionInfo->ExceptionRecord->ExceptionCode) 
    {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


//
// ExceptionsInit
//
_Use_decl_annotations_
BOOLEAN
ExceptionsInit(
    void
)
{
    gExceptionHandler = AddVectoredExceptionHandler(1, ExceptionHander);

    return gExceptionHandler != NULL;
}


//
// ExceptionsUninit
//
void
ExceptionsUninit(
    void
)
{
    if (NULL != gExceptionHandler)
    {
        RemoveVectoredExceptionHandler(gExceptionHandler);
    }
}
