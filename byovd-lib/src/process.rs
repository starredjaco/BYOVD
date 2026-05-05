use std::ffi::CStr;
use std::mem;

use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use crate::handle::WinHandle;

/// Find the first process matching `name` (case-insensitive) and return its PID.
pub fn find_pid_by_name(name: &str) -> Option<u32> {
    let snapshot =
        WinHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }).ok()?;

    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot.as_raw(), &mut entry) } == 0 {
        return None;
    }

    let target = name.to_lowercase();

    loop {
        let current = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr()) }
            .to_string_lossy()
            .to_lowercase();

        if current == target {
            return Some(entry.th32ProcessID);
        }

        if unsafe { Process32Next(snapshot.as_raw(), &mut entry) } == 0 {
            break;
        }
    }

    None
}

/// Find all PIDs of processes matching `name` (case-insensitive), excluding system PIDs (≤ 4).
pub fn find_all_pids_by_name(name: &str) -> Vec<u32> {
    let mut pids = Vec::new();

    let snapshot = match WinHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
    {
        Ok(s) => s,
        Err(_) => return pids,
    };

    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot.as_raw(), &mut entry) } == 0 {
        return pids;
    }

    let target = name.to_lowercase();

    loop {
        let current = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr()) }
            .to_string_lossy()
            .to_lowercase();

        if current == target && entry.th32ProcessID > 4 {
            pids.push(entry.th32ProcessID);
        }

        if unsafe { Process32Next(snapshot.as_raw(), &mut entry) } == 0 {
            break;
        }
    }

    pids
}

/// Back-compat alias for `find_pid_by_name`.
pub fn get_pid_by_name(name: &str) -> Option<u32> {
    find_pid_by_name(name)
}
