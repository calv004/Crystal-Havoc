#include <windows.h>
#include "gate_init.h"

void init_gates(PVOID ntdll, FARPROC getprocaddress, GATE_TABLE* gates)
{
    typedef FARPROC (WINAPI *pGPA)(HMODULE, LPCSTR);
    pGPA gpa = (pGPA)getprocaddress;

#define INIT_GATE(name) \
    do { PVOID _fn = (PVOID)gpa((HMODULE)ntdll, #name); \
         if (_fn) GetSyscall(ntdll, _fn, &gates->name); } while(0)

    /* Memory */
    INIT_GATE(NtAllocateVirtualMemory);
    INIT_GATE(NtFreeVirtualMemory);
    INIT_GATE(NtProtectVirtualMemory);
    INIT_GATE(NtWriteVirtualMemory);
    INIT_GATE(NtReadVirtualMemory);
    INIT_GATE(NtQueryVirtualMemory);
    INIT_GATE(NtUnmapViewOfSection);
    INIT_GATE(NtSetInformationVirtualMemory);
    /* Thread / Process */
    INIT_GATE(NtCreateThreadEx);
    INIT_GATE(NtOpenProcess);
    INIT_GATE(NtOpenThread);
    INIT_GATE(NtSuspendThread);
    INIT_GATE(NtResumeThread);
    INIT_GATE(NtTerminateProcess);
    INIT_GATE(NtTerminateThread);
    INIT_GATE(NtGetContextThread);
    INIT_GATE(NtSetContextThread);
    INIT_GATE(NtQueueApcThread);
    INIT_GATE(NtAlertResumeThread);
    INIT_GATE(NtDuplicateObject);
    INIT_GATE(NtGetNextThread);
    INIT_GATE(NtSetInformationThread);
    /* Events / Sync */
    INIT_GATE(NtCreateEvent);
    INIT_GATE(NtSetEvent);
    INIT_GATE(NtClose);
    INIT_GATE(NtWaitForSingleObject);
    INIT_GATE(NtSignalAndWaitForSingleObject);
    INIT_GATE(NtTestAlert);
    INIT_GATE(NtContinue);
    /* Query */
    INIT_GATE(NtQueryInformationProcess);
    INIT_GATE(NtQuerySystemInformation);
    INIT_GATE(NtQueryInformationThread);
    INIT_GATE(NtQueryObject);
    /* Token */
    INIT_GATE(NtOpenProcessToken);
    INIT_GATE(NtOpenThreadToken);
    INIT_GATE(NtDuplicateToken);
    INIT_GATE(NtQueryInformationToken);
    /* ETW */
    INIT_GATE(NtTraceEvent);
    /* File I/O */
    INIT_GATE(NtCreateFile);
    INIT_GATE(NtReadFile);
    INIT_GATE(NtWriteFile);
    /* Section / Mapping */
    INIT_GATE(NtCreateSection);
    INIT_GATE(NtMapViewOfSection);
    /* Delay */
    INIT_GATE(NtDelayExecution);

#undef INIT_GATE
}
