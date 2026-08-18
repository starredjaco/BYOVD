# Astra64-Killer

- PoC for EDR/AV process termination through `astra64.sys` from `EnTech Taiwan` (Astra32 / TVicHW)
- `ASTRA64.sys` SHA256: `4a8b6b462c4271af4a32cf8705fa64913bfcdaefb6cf02d1e722c611d428cb16`
- Listed on [LOLDDrivers](https://www.loldrivers.io/) ([magicsword-io/LOLDrivers#294](https://github.com/magicsword-io/LOLDrivers/issues/294))

**Standalone.** Does not use `byovd-lib`. Not a member of the BYOVD workspace — has its own `[workspace]` declaration and its own `[profile.release]`. Build directly from this directory.

## What it does

Data-only Shadow SSDT hijack — no shellcode, no RWX pool, no code execution in kernel-allocated memory. Patches a single entry in `KeServiceDescriptorTableShadow` to redirect `NtUserSetWindowPos` through an `FF 25` thunk in the win32k host module. The thunk's IAT slot is swapped via physical memory write between calls to chain kernel functions:

1. `ExAllocatePoolWithTag` — allocate pool buffer for EPROCESS output
2. Per target: `PsLookupProcessByProcessId` → `PsTerminateProcess` → `ObfDereferenceObject`
3. Restore original SSDT entry + IAT slot

The driver exposes `\Device\PhysicalMemory` via IOCTL `0x80002008` (no auth) and MSR read via IOCTL `0x800020EC` (`IA32_LSTAR` for KASLR bypass). Writes go through the physical-memory section, so HVCI/VBS page protections don't apply.

## Usage

```bash
cd Astra64-Killer
cargo build --release
.\target\release\astra64-killer.exe
```

No CLI flags. Targets Defender processes by default (`MsMpEng.exe`, `MpDefenderCoreService.exe`, `SecurityHealthService.exe`, `MsSense.exe`, etc.).

Tested on Windows 11 25H2 (build 26200) with HVCI + VBS enabled. Confirmed kills all three Defender processes including PPL-protected `MsMpEng.exe`.
