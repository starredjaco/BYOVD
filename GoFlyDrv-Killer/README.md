# GoFlyDrv-Killer
- PoC for vulnerability in GoFlyDrv Driver from Golink

- As of 2026-04-10, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `GoFly64.sys` SHA256: `2fdfdd13a0c548bb68c9d5aa8599a9265d4659da3e237fe7a42ac6ac06b9a06a`

## Usage

Place `GoFly64.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\GoFlyDrv-Killer.exe -h
BYOVD process killer using GoFlyDrv driver

Usage: GoFlyDrv-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p GoFlyDrv-Killer

# Run
.\GoFlyDrv-Killer.exe -n notepad.exe
```
