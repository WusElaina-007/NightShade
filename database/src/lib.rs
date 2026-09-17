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

#![no_std]

extern crate alloc;
pub mod bindings;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::format;
use core::fmt::{Display, Formatter};
use core::iter::FusedIterator;
use filesystem::FileSystem;
use filesystem::path::Path;

#[derive(Clone)]
pub enum Value {
    String(Arc<str>),
    Integer(i64),
    Float(f64),
    Blob(Arc<[u8]>),
    Null,
}

impl Value {
    pub fn as_string(&self) -> Option<Arc<str>> {
        if let Value::String(s) = self {
            Some(s.clone())
        } else {
            None
        }
    }

    pub fn as_integer(&self) -> Option<i64> {
        if let Value::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        if let Value::Float(f) = self {
            Some(*f)
        } else {
            None
        }
    }

    pub fn as_blob(&self) -> Option<Arc<[u8]>> {
        if let Value::Blob(b) = self {
            Some(b.clone())
        } else {
            None
        }
    }

    pub fn as_null(&self) -> Option<()> {
        if let Value::Null = self {
            Some(())
        } else {
            None
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Value::String(value) => write!(f, "{value}"),
            Value::Integer(value) => write!(f, "{value}"),
            Value::Float(value) => write!(f, "{value}"),
            Value::Blob(value) => write!(f, "{}", String::from_utf8_lossy(value)),
            Value::Null => write!(f, "null"),
        }
    }
}

/// A trait representing a database which can be created from raw bytes.
///
/// This trait extends `DatabaseReader` which provides methods to read data from the database.
///
/// # Methods
/// - `from_bytes(bytes: Vec<u8>) -> Result<Self, i32>`: Constructs the database from a vector of bytes.
///
/// # Errors
/// Returns an `Err(i32)` on failure to parse the bytes into a database.
pub trait Database: DatabaseReader {
    /// Create a database instance from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A vector of bytes representing the database content.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` if the bytes could be parsed into a database,
    /// otherwise returns an `Err(i32)` error code.
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, i32>
    where
        Self: Sized;
}

/// A trait for reading data from a database.
///
/// Provides an interface to read tables and their records.
///
/// # Associated Types
/// - `Iter`: An iterator over the records in the table.
/// - `Record`: The record type, must implement `TableRecord`.
pub trait DatabaseReader {
    /// The type of iterator returned when reading a table.
    type Iter: Iterator<Item = Self::Record>
        + Send
        + FusedIterator
        + DoubleEndedIterator
        + ExactSizeIterator;

    /// The record type stored in the database tables.
    type Record: TableRecord + Clone;

    /// Reads a table by name, returning an iterator over its records if found.
    ///
    /// # Arguments
    ///
    /// * `table_name` - The name of the table to read.
    ///
    /// # Returns
    ///
    /// Returns `Some(iterator)` over the records of the table if it exists,
    /// or `None` if the table could not be found.
    fn read_table<S>(&self, table_name: S) -> Option<Self::Iter>
    where
        S: AsRef<str>;
}

/// An extension trait for `Database` to provide additional constructors.
pub trait DatabaseExt: Database {
    /// Create a database instance from a file path using the given filesystem.
    ///
    /// # Arguments
    ///
    /// * `fs` - A reference to a filesystem instance that implements `FileSystem`.
    /// * `path` - The path to the database file.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Self)` if the file was successfully read and parsed into a database,
    /// otherwise returns an `Err(i32)` error code.
    fn from_path<R, F, P>(fs: R, path: P) -> Result<Self, i32>
    where
        R: AsRef<F>,
        F: FileSystem,
        P: AsRef<Path>,
        Self: Sized;
}

/// Applies SQLite **WAL frames** onto the raw main-database bytes, in memory.
///
/// Browsers keep their DBs open in WAL mode; pages of freshly-written rows
/// live in `<db>-wal` and were previously invisible to us (we never read the
/// sidecar, and the bundled SQLite is built with `SQLITE_OMIT_WAL`).
///
/// WAL format (documented in the SQLite source, `wal.c`):
/// ```text
/// header (32): magic(4) version(4) page_size(4 BE) ckpt_seq(4) salt1(4) salt2(4) cksum1(4) cksum2(4)
/// frame  (24 + page_size): pgno(4 BE) db_size_after_commit(4 BE) salt1(4) salt2(4) cksum1(4) cksum2(4) page
/// ```
/// Frames become durable at each **commit frame** (`db_size != 0`); salt
/// values must match the header of the *first* frame generation we accept.
fn apply_wal(db: &mut Vec<u8>, wal: &[u8]) {
    if wal.len() < 32 {
        return;
    }

    let page_size = u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]) as usize;
    // Only the classic power-of-two page sizes SQLite writes (512..=65536).
    if page_size < 512 || page_size > 65536 || !page_size.is_power_of_two() {
        return;
    }

    let salt = &wal[16..24]; // salt1 || salt2 of frame generation
    let mut pos = 32usize;
    let mut pending: Vec<(usize, &[u8])> = Vec::new();
    let mut db_pages = db.len() / page_size;

    while pos + 24 + page_size <= wal.len() {
        let pgno = u32::from_be_bytes([
            wal[pos],
            wal[pos + 1],
            wal[pos + 2],
            wal[pos + 3],
        ]) as usize;
        let commit_size = u32::from_be_bytes([
            wal[pos + 4],
            wal[pos + 5],
            wal[pos + 6],
            wal[pos + 7],
        ]) as usize;

        if &wal[pos + 8..pos + 16] != salt {
            // Frame from an older checkpoint generation — WAL restart point.
            break;
        }

        let page = &wal[pos + 24..pos + 24 + page_size];
        pending.push((pgno, page));

        pos += 24 + page_size;

        if commit_size != 0 {
            // Commit: grow the database if the transaction added pages.
            if commit_size > db_pages {
                db.resize(commit_size * page_size, 0);
                db_pages = commit_size;
            }

            for (pgno, page) in pending.drain(..) {
                if pgno >= 1 && pgno <= db_pages {
                    let start = (pgno - 1) * page_size;
                    db[start..start + page_size].copy_from_slice(page);
                }
            }

            // Keep the header's "database size in pages" consistent.
            if db.len() >= 28 {
                let size_be = (db_pages as u32).to_be_bytes();
                db[24..28].copy_from_slice(&size_be);
            }
        }
    }
}

impl<T: Database> DatabaseExt for T {
    fn from_path<R, F, P>(fs: R, path: P) -> Result<Self, i32>
    where
        R: AsRef<F>,
        F: FileSystem,
        P: AsRef<Path>,
        Self: Sized,
    {
        let mut data = fs.as_ref().read_file(path.as_ref()).map_err(|e| e as i32)?;

        // Fresh WAL sidecar? Replay it onto our in-memory copy — this makes
        // rows written while the browser was running visible.
        if let Ok(wal) = fs
            .as_ref()
            .read_file(Path::new(&format!("{}-wal", path.as_ref())))
        {
            apply_wal(&mut data, &wal);
        }

        Self::from_bytes(data)
    }
}

pub trait TableRecord:
    Iterator<Item = Value> + Send + FusedIterator + DoubleEndedIterator + ExactSizeIterator
{
    fn get_value(&self, index: usize) -> Option<Value>;
}
