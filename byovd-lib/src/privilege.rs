use std::ffi::CString;
use std::mem;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::{AdjustTokenPrivileges, CheckTokenMembership, CreateWellKnownSid};
use winapi::um::winbase::LookupPrivilegeValueA;
use winapi::um::winnt::{
    WinLocalSystemSid, LUID, LUID_AND_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};

use crate::handle::WinHandle;
use crate::Result;

/// Enable a named privilege for the current process token.
///
/// Common privilege names:
/// - `"SeDebugPrivilege"`
/// - `"SeLoadDriverPrivilege"`
pub fn enable_privilege(privilege_name: &str) -> Result<()> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(format!(
                "Failed to open process token (error {})",
                GetLastError()
            )
            .into());
        }

        let token_handle = WinHandle::new(token)?;

        let mut luid: LUID = mem::zeroed();
        let priv_cstr = CString::new(privilege_name)
            .map_err(|_| "Privilege name contains null byte")?;

        if LookupPrivilegeValueA(null_mut(), priv_cstr.as_ptr(), &mut luid) == 0 {
            return Err(format!(
                "Failed to look up privilege '{}' (error {})",
                privilege_name,
                GetLastError()
            )
            .into());
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(
            token_handle.as_raw(),
            FALSE,
            &mut tp,
            mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            null_mut(),
            null_mut(),
        ) == 0
        {
            return Err(format!(
                "Failed to adjust token privileges (error {})",
                GetLastError()
            )
            .into());
        }

        println!("[+] Enabled privilege: {}", privilege_name);
        Ok(())
    }
}

/// Verify the current process is running as LocalSystem (S-1-5-18).
/// Returns an error if not.
pub fn ensure_running_as_local_system() -> Result<()> {
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = sid.len() as DWORD;

    let created = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            sid.as_mut_ptr() as *mut _,
            &mut sid_size,
        )
    };

    if created == 0 {
        return Err("Failed to build LocalSystem SID".into());
    }

    let mut is_member: i32 = 0;
    let checked = unsafe {
        CheckTokenMembership(null_mut(), sid.as_mut_ptr() as *mut _, &mut is_member)
    };

    if checked == 0 {
        return Err("Failed to verify token membership".into());
    }

    if is_member == 0 {
        return Err("Not running as LocalSystem (S-1-5-18). Use PsExec or similar.".into());
    }

    println!("[+] Running as LocalSystem confirmed");
    Ok(())
}
