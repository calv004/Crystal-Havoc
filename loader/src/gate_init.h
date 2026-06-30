#ifndef GATE_INIT_H
#define GATE_INIT_H

#include "gate.h"

/*
 * Select the indirect syscall gadget when available; fall back to the real
 * NTDLL import otherwise.  When jmpAddr is NULL the ssn field is also 0
 * (zero-initialised struct), so Draugr treats it as a plain function call.
 */
#define GATE_PTR(name, fallback) \
    (g_gates.name.jmpAddr ? g_gates.name.jmpAddr : (PVOID)(fallback))

/* Populate a FUNCTION_CALL with gate address + SSN for indirect syscall. */
#define GATE_CALL(call, gate) \
    do { (call).ptr = (gate).jmpAddr; (call).ssn = (gate).ssn; } while(0)

typedef struct {
    /* Memory */
    SYSCALL_GATE NtAllocateVirtualMemory;
    SYSCALL_GATE NtFreeVirtualMemory;
    SYSCALL_GATE NtProtectVirtualMemory;
    SYSCALL_GATE NtWriteVirtualMemory;
    SYSCALL_GATE NtReadVirtualMemory;
    SYSCALL_GATE NtQueryVirtualMemory;
    SYSCALL_GATE NtUnmapViewOfSection;
    SYSCALL_GATE NtSetInformationVirtualMemory;
    /* Thread / Process */
    SYSCALL_GATE NtCreateThreadEx;
    SYSCALL_GATE NtOpenProcess;
    SYSCALL_GATE NtOpenThread;
    SYSCALL_GATE NtSuspendThread;
    SYSCALL_GATE NtResumeThread;
    SYSCALL_GATE NtTerminateProcess;
    SYSCALL_GATE NtTerminateThread;
    SYSCALL_GATE NtGetContextThread;
    SYSCALL_GATE NtSetContextThread;
    SYSCALL_GATE NtQueueApcThread;
    SYSCALL_GATE NtAlertResumeThread;
    SYSCALL_GATE NtDuplicateObject;
    SYSCALL_GATE NtGetNextThread;
    SYSCALL_GATE NtSetInformationThread;
    /* Events / Sync */
    SYSCALL_GATE NtCreateEvent;
    SYSCALL_GATE NtSetEvent;
    SYSCALL_GATE NtClose;
    SYSCALL_GATE NtWaitForSingleObject;
    SYSCALL_GATE NtSignalAndWaitForSingleObject;
    SYSCALL_GATE NtTestAlert;
    SYSCALL_GATE NtContinue;
    /* Query */
    SYSCALL_GATE NtQueryInformationProcess;
    SYSCALL_GATE NtQuerySystemInformation;
    SYSCALL_GATE NtQueryInformationThread;
    SYSCALL_GATE NtQueryObject;
    /* Token */
    SYSCALL_GATE NtOpenProcessToken;
    SYSCALL_GATE NtOpenThreadToken;
    SYSCALL_GATE NtDuplicateToken;
    SYSCALL_GATE NtQueryInformationToken;
    /* ETW */
    SYSCALL_GATE NtTraceEvent;
    /* File I/O */
    SYSCALL_GATE NtCreateFile;
    SYSCALL_GATE NtReadFile;
    SYSCALL_GATE NtWriteFile;
    /* Section / Mapping */
    SYSCALL_GATE NtCreateSection;
    SYSCALL_GATE NtMapViewOfSection;
    /* Delay */
    SYSCALL_GATE NtDelayExecution;
} GATE_TABLE;

void init_gates(PVOID ntdll, FARPROC getprocaddress, GATE_TABLE* gates);
void hooks_init_gates(PVOID ntdll, FARPROC getprocaddress);

#endif /* GATE_INIT_H */
