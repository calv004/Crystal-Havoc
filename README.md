# Crystal-Havoc

Crystal Palace loader for Havoc Demon with callstack spoofing and indirect syscalls.

## Background

I don't use Havoc C2 without Crystal Palace anymore. The idea here is simple: instead of relying on Havoc's built-in evasion features, we strip them out and implement some features through Crystal Palace. This makes the evasion layer modular and keeps it separate from the implant itself.

The loader hooks the relevant functions in Havoc Demon and redirects them through callstack spoofing and indirect syscalls.

## Usage

Havoc's UI doesn't expose the raw Demon DLL directly, so we need to extract it from the generated shellcode.

**Step 1 — Generate shellcode in Havoc UI**

Generate the shellcode payload with your desired configuration. Make sure to disable Havoc's built-in indirect syscalls and stack spoofing — Crystal Palace handles those.

**Step 2 — Extract the raw Demon DLL**

The generated shellcode is just the reflective loader prepended to the raw Demon DLL. Strip the loader off:

```sh
dd if=demon.x64.bin of=core.x64.dll bs=1 skip=1535
```

The offset `1535` is the size of the reflective loader shellcode for this build configuration. It can vary between Havoc versions. Check the actual size after building:

```sh
wc -c Havoc/payloads/Shellcode/Shellcode.x64.bin
```

**Step 3 — Link with Crystal Palace**

```sh
./dist/link loader/loader.spec core.x64.dll crystal_havoc.bin
```

The output `crystal_havoc.bin` is position-independent shellcode ready for injection.

Optionally convert to a C array:

```sh
xxd -i crystal_havoc.bin > crystal_havoc.h
```

## Havoc Source Modifications

To make `GetProcAddress` go through Crystal Palace's IAT hook (so all Win32 calls get routed through `spoof_call`), three files in the Havoc source need to be modified.

**`payloads/Demon/src/Demon.c`**

Kernel32 function resolution changed from Havoc's internal hash-walking (`LdrFunctionAddr`) to `GetProcAddress`. This ensures Crystal Palace's hook intercepts the calls.

```c
// before
Instance->Win32.VirtualAlloc = LdrFunctionAddr(Instance->Modules.Kernel32, H_FUNC_VIRTUALALLOC);

// after
Instance->Win32.VirtualAlloc = GetProcAddress(hK32, "VirtualAlloc");
```

**`payloads/Demon/src/core/Runtime.c`**

Same change applied to all other modules loaded at runtime: `Advapi32`, `Ws2_32`, `WinHttp`, `Oleaut32`, `Mscoree`, `Amsi`.

**`teamserver/pkg/common/builder/builder.go`**

Added `-lkernel32` to the compiler flags so `GetProcAddress` is available when building the Demon DLL.

```go
"-lkernel32",
```

## Disclaimer

This is a proof of concept for authorized red team operations and security research only. Parts of the code were written with the assistance of AI. Use responsibly and only in environments where you have explicit authorization.


"-lkernel32",
```
