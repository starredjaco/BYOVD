# Ktapi-Killer

- PoC for EDR/AV process termination through `ktapi.sys` from `Kontron`
- `ktapi.sys` SHA256: `7EE17EFEF04BB7C9DE90D5210263ED6993F867E5A11F86E65E3BB1362C7DE237`
- Listed on [LOLDDrivers](https://www.loldrivers.io/)

**Standalone.** Does not use `byovd-lib`. Not a member of the BYOVD workspace — has its own `[workspace]` declaration and its own `[profile.release]`. Build directly from this directory.

## Background

Reproduction of the EDR killer technique used by **The Gentlemen** ransomware group, documented by [Expel](https://expel.com/blog/not-very-gentlemanly-analyzing-a-zero-day-exploit-used-by-the-gentlemen-ransomware-to-disable-targets-edrs/) (June 2026). The group used `ktapi.sys` as a zero-day BYOVD driver to disable EDR products before deploying ransomware.

The driver exposes arbitrary 64-bit physical memory R/W via `\Device\PhysicalMemory` + `HalTranslateBusAddress` fail-open. When `InterfaceType` is set to `0xFFFFFFFF`, HAL returns the input address unchanged, turning a bus address mapper into an arbitrary physical memory mapper. IOCTL `0x82007000` (map), `0x82007100` (unmap). No auth, no SDDL.

## What it does

1. Brute-force kernel CR3 from physical memory scan
2. Resolve ntoskrnl base + kernel exports (`ExAllocatePoolWithTag`, `PsLookupProcessByProcessId`, `PsTerminateProcess`, `ObfDereferenceObject`)
3. Locate `win32kfull.sys` in session address space
4. Hijack `NtGdiSetMagicColors` E9 stub → trampoline in CC padding → stage-2 shellcode in kernel pool
5. KernelCall primitive: write target function + args to pool, trigger via Win32k syscall
6. Per target: `PsLookupProcessByProcessId` → `PsTerminateProcess` → `ObfDereferenceObject`
7. Restore E9 stub + CC padding

Uses `PsTerminateProcess` from kernel mode — bypasses PPL and EDR process termination callbacks.

## Differences from The Gentlemen's original exploit

The Expel blog documents the original exploit using two hijacked Win32k syscalls: `NtUserFrostCrashedWindow` (redirected to a `mov [rcx], rdx; ret` gadget for arbitrary kernel write) and `NtUserSetGestureConfig` (redirected to pool shellcode for code execution), with `KUSER_SHARED_DATA` as a kernel↔usermode communication bridge to bypass SMAP.

We tested both `NtUserFrostCrashedWindow` and `NtUserSetGestureConfig` on Windows 11 25H2 build 26200 — **neither works**. The indirect call stubs the blog describes are not present in this build's `win32kfull.sys`.

This PoC uses a different approach:
- **One syscall** instead of two: `NtGdiSetMagicColors` E9 stub in `win32kfull.sys`
- **No KUSD bridge needed**: we already have arbitrary physical memory R/W through the driver, so args are written directly to kernel pool via physical write
- **Two-stage shellcode**: CC-padding trampoline → stage-2 in kernel pool that loads 4 args from pool slots, calls the target function, stores the result back to pool

## Usage

```bash
cd Ktapi-Killer
cargo build --release
.\target\release\ktapi-killer.exe
```

No CLI flags. Targets Defender processes by default (`MsMpEng.exe`, `MpDefenderCoreService.exe`, `SecurityHealthService.exe`, `MsSense.exe`, etc.).

Tested on Windows 11 25H2 (build 26200). Confirmed kills all three Defender processes.
