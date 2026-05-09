# Xkpsm-Killer
- PoC for vulnerability in xkpsm Driver from JiranJikyosoft X-Keeper

- As of 2026-05-08, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `xkpsm.sys` SHA256: `28c5bb735f9fc38e0ebd366978898f0cfcd455e4ff8bf1a321768b09e01ee84d`

## Usage

Place `xkpsm.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\Xkpsm-Killer.exe -h
BYOVD process killer using Xkpsm driver

Usage: Xkpsm-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p Xkpsm-Killer

# Run
.\Xkpsm-Killer.exe -n notepad.exe
```
