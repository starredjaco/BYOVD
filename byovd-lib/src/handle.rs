use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winnt::HANDLE;
use winapi::um::winsvc::{CloseServiceHandle, SC_HANDLE};

use crate::Result;

/// RAII wrapper for a Windows `HANDLE`. Auto-closes on drop.
pub struct WinHandle(HANDLE);

unsafe impl Send for WinHandle {}
unsafe impl Sync for WinHandle {}

impl WinHandle {
    /// Wrap a raw `HANDLE`. Returns an error if it is `INVALID_HANDLE_VALUE` or null.
    pub fn new(handle: HANDLE) -> Result<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            Err(format!("Invalid handle (error {})", unsafe { GetLastError() }).into())
        } else {
            Ok(Self(handle))
        }
    }

    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// RAII wrapper for a Windows Service Control Manager `SC_HANDLE`. Auto-closes on drop.
pub struct ScHandle(SC_HANDLE);

unsafe impl Send for ScHandle {}
unsafe impl Sync for ScHandle {}

impl ScHandle {
    /// Wrap a raw `SC_HANDLE`. Returns an error if it is null.
    pub fn new(handle: SC_HANDLE) -> Result<Self> {
        if handle.is_null() {
            Err(format!("Invalid service handle (error {})", unsafe { GetLastError() }).into())
        } else {
            Ok(Self(handle))
        }
    }

    pub fn as_raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// Back-compat alias for the pre-modular handle name.
pub type FileHandle = WinHandle;

/// Back-compat alias for the pre-modular handle name.
pub type ServiceHandle = ScHandle;
