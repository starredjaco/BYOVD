# UnknownKiller
- PoC for vulnerability in an unattributed process-killer driver shipped as `unknown.sys`
- As of 2026-05-05, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `unknown.sys` SHA256: `97bd65e98cdc4e93d49edd4ea905d43a61244df0fd3323e6649330de3b1be091`

## Usage

Place `unknown.sys` in the same directory as the executable.

```text
BYOVD process killer using unknown.sys

Usage: UnknownKiller.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p UnknownKiller

# Run
.\UnknownKiller.exe -n notepad.exe
```
