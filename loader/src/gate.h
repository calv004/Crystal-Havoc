#ifndef GATE_H
#define GATE_H

#include <windows.h>

typedef struct {
    DWORD ssn;
    PVOID jmpAddr;
} SYSCALL_GATE;

BOOL GetSyscall     (PVOID ntdll, PVOID func, SYSCALL_GATE * gate);
void PrepareSyscall (DWORD ssn, PVOID addr);
void DoSyscall      ();

#endif /* GATE_H */