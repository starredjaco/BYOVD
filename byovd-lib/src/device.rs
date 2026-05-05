use std::ptr::null_mut;

use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, HANDLE};

use crate::handle::WinHandle;
use crate::util::to_wstring;
use crate::Result;

/// Handle to a driver device for sending IOCTLs.
pub struct DeviceHandle(WinHandle);

impl DeviceHandle {
    /// Open a device with `GENERIC_READ | GENERIC_WRITE` access.
    pub fn open(device_path: &str) -> Result<Self> {
        Self::open_with_access(device_path, GENERIC_READ | GENERIC_WRITE)
    }

    /// Open a device with custom access flags.
    pub fn open_with_access(device_path: &str, access: u32) -> Result<Self> {
        let handle = WinHandle::new(unsafe {
            CreateFileW(
                to_wstring(device_path).as_ptr(),
                access,
                0,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        })?;
        Ok(Self(handle))
    }

    pub fn as_raw(&self) -> HANDLE {
        self.0.as_raw()
    }

    /// Send an IOCTL with typed input + output buffers.
    pub fn ioctl<I, O>(&self, code: u32, input: &I, output: &mut O) -> Result<u32> {
        let mut bytes_returned: DWORD = 0;
        let success = unsafe {
            DeviceIoControl(
                self.0.as_raw(),
                code,
                input as *const I as *mut c_void,
                std::mem::size_of::<I>() as DWORD,
                output as *mut O as *mut c_void,
                std::mem::size_of::<O>() as DWORD,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if success == 0 {
            return Err(ioctl_error(code));
        }
        Ok(bytes_returned)
    }

    /// Send an IOCTL using the same buffer for input AND output.
    pub fn ioctl_inout<T>(&self, code: u32, data: &mut T) -> Result<u32> {
        let mut bytes_returned: DWORD = 0;
        let size = std::mem::size_of::<T>() as DWORD;
        let success = unsafe {
            DeviceIoControl(
                self.0.as_raw(),
                code,
                data as *mut T as *mut c_void,
                size,
                data as *mut T as *mut c_void,
                size,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if success == 0 {
            return Err(ioctl_error(code));
        }
        Ok(bytes_returned)
    }

    /// Send an IOCTL with input only (no output buffer).
    pub fn ioctl_in<I>(&self, code: u32, input: &I) -> Result<u32> {
        let mut bytes_returned: DWORD = 0;
        let success = unsafe {
            DeviceIoControl(
                self.0.as_raw(),
                code,
                input as *const I as *mut c_void,
                std::mem::size_of::<I>() as DWORD,
                null_mut(),
                0,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if success == 0 {
            return Err(ioctl_error(code));
        }
        Ok(bytes_returned)
    }

    /// Send an IOCTL without checking the return value.
    /// Useful for drivers that always report failure even on success (e.g. NSecKrnl).
    pub fn ioctl_in_unchecked<I>(&self, code: u32, input: &I) {
        let mut bytes_returned: DWORD = 0;
        unsafe {
            DeviceIoControl(
                self.0.as_raw(),
                code,
                input as *const I as *mut c_void,
                std::mem::size_of::<I>() as DWORD,
                null_mut(),
                0,
                &mut bytes_returned,
                null_mut(),
            );
        }
    }

    /// Send an IOCTL with raw pointers and byte sizes (escape hatch for unusual buffer shapes).
    pub fn ioctl_raw(
        &self,
        code: u32,
        in_buf: *mut c_void,
        in_size: u32,
        out_buf: *mut c_void,
        out_size: u32,
    ) -> Result<u32> {
        let mut bytes_returned: DWORD = 0;
        let success = unsafe {
            DeviceIoControl(
                self.0.as_raw(),
                code,
                in_buf,
                in_size,
                out_buf,
                out_size,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if success == 0 {
            return Err(ioctl_error(code));
        }
        Ok(bytes_returned)
    }

    /// Internal helper backing the trait-driven `send_ioctl()`. Takes byte slices
    /// (matching `DriverConfig::build_ioctl_input` output) and an optional output
    /// buffer. `success_required = false` mirrors `ignore_ioctl_error()`.
    pub(crate) fn ioctl_bytes_legacy(
        &self,
        code: u32,
        input: &[u8],
        output: Option<&mut [u8]>,
        success_required: bool,
    ) -> Result<u32> {
        let mut bytes_returned: DWORD = 0;
        let (out_ptr, out_size) = match output {
            Some(buf) => (buf.as_mut_ptr() as LPVOID, buf.len() as DWORD),
            None => (null_mut(), 0),
        };
        let success = unsafe {
            DeviceIoControl(
                self.0.as_raw(),
                code,
                input.as_ptr() as LPVOID,
                input.len() as DWORD,
                out_ptr,
                out_size,
                &mut bytes_returned,
                null_mut(),
            )
        };
        if success == 0 && success_required {
            return Err("IOCTL call failed".into());
        }
        Ok(bytes_returned)
    }
}

fn ioctl_error(code: u32) -> Box<dyn std::error::Error> {
    format!("IOCTL 0x{:X} failed (error {})", code, unsafe {
        GetLastError()
    })
    .into()
}
