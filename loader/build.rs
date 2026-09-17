//! Loader build script: exports the payload/key paths supplied by the
//! builder, or materialises inert placeholders so the crate also compiles
//! standalone (`cargo check --workspace`).

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=BUILDER_PAYLOAD_FILE");
    println!("cargo:rerun-if-env-changed=BUILDER_KEY_EXPR");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out = Path::new(&out_dir);

    let payload = match std::env::var("BUILDER_PAYLOAD_FILE") {
        Ok(path) => path,
        Err(_) => {
            let placeholder = out.join("placeholder_payload.bin");
            // A 36-byte SNAES1 header that decrypts to nothing useful — the
            // loader simply fails its integrity path on a dummy build.
            std::fs::write(&placeholder, b"SNAES1\xff\xff").unwrap();
            placeholder.to_str().unwrap().to_string()
        }
    };
    println!("cargo:rustc-env=PAYLOAD_PATH={payload}");

    let key = match std::env::var("BUILDER_KEY_EXPR") {
        Ok(path) => path,
        Err(_) => {
            let placeholder = out.join("placeholder_key.rs");
            std::fs::write(&placeholder, "pub static KEY: [u8; 32] = [0; 32];").unwrap();
            placeholder.to_str().unwrap().to_string()
        }
    };
    println!("cargo:rustc-env=KEY_PATH={key}");
}
