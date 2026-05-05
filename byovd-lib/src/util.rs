use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;

use winapi::um::processenv::GetCurrentDirectoryW;

use crate::Result;

const MAX_PATH: usize = 260;

/// Convert a `&str` to a null-terminated wide string suitable for Win32 W-suffix APIs.
pub fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Convert a `&str` to a null-terminated `CString` for Win32 A-suffix APIs.
pub fn to_cstring(s: &str) -> CString {
    CString::new(s).expect("string contains interior null byte")
}

/// Return the current working directory as a UTF-8 `String`.
pub fn get_current_dir() -> Result<String> {
    let mut buf = vec![0u16; MAX_PATH];
    let len = unsafe { GetCurrentDirectoryW(buf.len() as u32, buf.as_mut_ptr()) };

    if len == 0 {
        return Err("Failed to get current directory".into());
    }

    buf.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buf))
}
