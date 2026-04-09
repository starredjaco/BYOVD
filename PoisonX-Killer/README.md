# PoisonX-Killer

> *Yet another POC for a kernel-mode process killer discovered during BYOVD research. Uses a signed Microsoft driver (PoisonX.sys) that exposes an IOCTL interface capable of terminating any process including PPL-protected EDR services like CrowdStrike Falcon.*

- PoC for vulnerability in PoisonX driver from [@j3h4ck](https://x.com/j3h4ck)
- Medium article [https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4](https://medium.com/@jehadbudagga/reverse-engineering-a-0day-used-against-crowdstrike-edr-a5ea1fbe3fd4)
- Original repo [https://github.com/j3h4ck/PoisonKiller](https://github.com/j3h4ck/PoisonKiller)
- PoisonX.sys SHA256: `a5035cbd6c31616288aa66d98e5a25441ee38651fb5f330676319f921bb816a4`

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library. 

## Usage

Place `PoisonX.sys` in the same directory as the executable (driver file must be named `PoisonX.sys`).

```text
BYOVD process killer using PoisonX driver (Microsoft)

Usage: PoisonX-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p PoisonX-Killer

# Run
.\PoisonX-Killer.exe -n notepad.exe
```