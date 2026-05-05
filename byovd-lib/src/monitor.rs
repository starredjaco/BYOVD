use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::process::find_pid_by_name;
use crate::Result;

/// Install a Ctrl+C handler that clears the returned flag on signal.
///
/// Use this when you need a custom monitoring loop. For the standard PID-based
/// loop, use [`run_monitor_loop`].
pub fn setup_ctrlc_handler() -> Result<Arc<AtomicBool>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\n[!] Shutting down...");
        r.store(false, Ordering::SeqCst);
    })?;

    Ok(running)
}

/// Repeatedly look up `process_name` and call `on_found(pid)` on every match.
///
/// Loop exits on Ctrl+C. The closure form lets callers do whatever they want
/// per-PID (custom IOCTLs, multi-PID fan-out, structured logging) instead of
/// being locked into the trait-driven `send_ioctl` path.
pub fn run_monitor_loop<F>(process_name: &str, interval: Duration, mut on_found: F) -> Result<()>
where
    F: FnMut(u32) -> Result<()>,
{
    let running = setup_ctrlc_handler()?;

    println!(
        "[*] Monitoring for process: {} (Press Ctrl+C to stop)",
        process_name
    );

    while running.load(Ordering::SeqCst) {
        if let Some(pid) = find_pid_by_name(process_name) {
            match on_found(pid) {
                Ok(()) => println!("[+] Killed PID {}", pid),
                Err(e) => eprintln!("[!] Failed to kill PID {}: {}", pid, e),
            }
        }
        thread::sleep(interval);
    }

    Ok(())
}
