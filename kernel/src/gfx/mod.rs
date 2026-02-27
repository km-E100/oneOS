#![allow(dead_code)]

use core::cmp;

use oneos_boot_proto::{FrameBufferFormat, FrameBufferInfo};
use spin::Mutex;

#[cfg(target_os = "none")]
use crate::drivers::serial;

#[cfg(target_os = "none")]
use crate::sandbox;

#[derive(Clone, Copy, Debug)]
pub struct GraphicsInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: FrameBufferFormat,
}

#[derive(Clone, Copy, Debug)]
pub enum GfxError {
    Unavailable,
    PermissionDenied,
}

#[derive(Clone, Copy)]
struct GraphicsDevice {
    base: *mut u32,
    width: usize,
    height: usize,
    stride: usize,
    format: FrameBufferFormat,
}

unsafe impl Send for GraphicsDevice {}
unsafe impl Sync for GraphicsDevice {}

static DEV: Mutex<Option<GraphicsDevice>> = Mutex::new(None);

pub fn init(info: &FrameBufferInfo) {
    if info.base == 0 || info.size == 0 {
        return;
    }
    if matches!(info.format, FrameBufferFormat::Unknown) {
        return;
    }

    let dev = GraphicsDevice {
        base: info.base as *mut u32,
        width: info.width as usize,
        height: info.height as usize,
        stride: info.stride as usize,
        format: info.format,
    };

    *DEV.lock() = Some(dev);

    #[cfg(target_os = "none")]
    serial::log_line_args(format_args!(
        "gfx: init {}x{} stride={} fmt={:?}",
        info.width, info.height, info.stride, info.format
    ));
}

pub fn info() -> Option<GraphicsInfo> {
    let dev = DEV.lock();
    let dev = dev.as_ref()?;
    Some(GraphicsInfo {
        width: dev.width as u32,
        height: dev.height as u32,
        stride: dev.stride as u32,
        format: dev.format,
    })
}

pub fn clear(r: u8, g: u8, b: u8) -> Result<(), GfxError> {
    with_dev(|dev| {
        let px = pack_color(dev.format, r, g, b);
        for y in 0..dev.height {
            let row = unsafe { dev.base.add(y * dev.stride) };
            for x in 0..dev.width {
                unsafe { row.add(x).write_volatile(px) };
            }
        }
    })
}

pub fn draw_rect(x: i32, y: i32, w: i32, h: i32, r: u8, g: u8, b: u8) -> Result<(), GfxError> {
    with_dev(|dev| {
        let px = pack_color(dev.format, r, g, b);
        let x0 = clamp_i32(x, 0, dev.width as i32);
        let y0 = clamp_i32(y, 0, dev.height as i32);
        let x1 = clamp_i32(x.saturating_add(w), 0, dev.width as i32);
        let y1 = clamp_i32(y.saturating_add(h), 0, dev.height as i32);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        for yy in y0..y1 {
            let row = unsafe { dev.base.add(yy as usize * dev.stride) };
            for xx in x0..x1 {
                unsafe { row.add(xx as usize).write_volatile(px) };
            }
        }
    })
}

pub fn draw_line(x0: i32, y0: i32, x1: i32, y1: i32, r: u8, g: u8, b: u8) -> Result<(), GfxError> {
    with_dev(|dev| {
        let px = pack_color(dev.format, r, g, b);
        bresenham(dev, x0, y0, x1, y1, px);
    })
}

/// Draw a 1-bit bitmap (MSB-first), with an explicit `bytes_per_row` stride.
pub fn draw_bitmap_mono(
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    bytes_per_row: usize,
    data: &[u8],
    r: u8,
    g: u8,
    b: u8,
) -> Result<(), GfxError> {
    with_dev(|dev| {
        let px = pack_color(dev.format, r, g, b);
        if width <= 0 || height <= 0 {
            return;
        }
        let need = bytes_per_row.saturating_mul(height as usize);
        if data.len() < need {
            return;
        }
        for row in 0..height {
            let src = &data[row as usize * bytes_per_row..(row as usize + 1) * bytes_per_row];
            for col in 0..width {
                let byte = src[(col as usize) >> 3];
                let bit = 7 - ((col as usize) & 7);
                if ((byte >> bit) & 1) == 0 {
                    continue;
                }
                put_pixel(dev, x + col, y + row, px);
            }
        }
    })
}

pub fn test_pattern() -> Result<(), GfxError> {
    #[cfg(target_os = "none")]
    serial::log_line("gfx: test_pattern begin");

    clear(0x00, 0x00, 0x00)?;
    // Top bar.
    draw_rect(0, 0, 10_000, 40, 0x20, 0x20, 0x20)?;
    // RGB blocks.
    draw_rect(40, 60, 120, 80, 0xFF, 0x00, 0x00)?;
    draw_rect(180, 60, 120, 80, 0x00, 0xFF, 0x00)?;
    draw_rect(320, 60, 120, 80, 0x00, 0x00, 0xFF)?;
    // Diagonal lines.
    if let Some(info) = info() {
        let w = info.width as i32;
        let h = info.height as i32;
        draw_line(0, 0, w - 1, h - 1, 0xAA, 0xAA, 0xAA)?;
        draw_line(0, h - 1, w - 1, 0, 0xAA, 0xAA, 0xAA)?;
        // Frame.
        draw_rect(20, 200, w - 40, 4, 0xFF, 0xFF, 0xFF)?;
        draw_rect(20, 200, 4, cmp::max(0, h - 240), 0xFF, 0xFF, 0xFF)?;
        draw_rect(w - 24, 200, 4, cmp::max(0, h - 240), 0xFF, 0xFF, 0xFF)?;
        draw_rect(20, h - 40, w - 40, 4, 0xFF, 0xFF, 0xFF)?;
    }

    #[cfg(target_os = "none")]
    serial::log_line("gfx: test_pattern done");
    Ok(())
}

fn with_dev<F: FnOnce(&GraphicsDevice)>(f: F) -> Result<(), GfxError> {
    #[cfg(target_os = "none")]
    {
        if sandbox::require_gpu_draw().is_err() {
            return Err(GfxError::PermissionDenied);
        }
    }
    let dev_guard = DEV.lock();
    let Some(dev) = dev_guard.as_ref() else {
        return Err(GfxError::Unavailable);
    };
    f(dev);
    Ok(())
}

fn pack_color(format: FrameBufferFormat, r: u8, g: u8, b: u8) -> u32 {
    let bytes = match format {
        FrameBufferFormat::Rgb => [r, g, b, 0],
        FrameBufferFormat::Bgr => [b, g, r, 0],
        FrameBufferFormat::Unknown => [r, g, b, 0],
    };
    u32::from_le_bytes(bytes)
}

fn clamp_i32(v: i32, lo: i32, hi: i32) -> i32 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

fn bresenham(dev: &GraphicsDevice, x0: i32, y0: i32, x1: i32, y1: i32, px: u32) {
    let mut x0 = x0;
    let mut y0 = y0;
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        put_pixel(dev, x0, y0, px);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

fn put_pixel(dev: &GraphicsDevice, x: i32, y: i32, px: u32) {
    if x < 0 || y < 0 {
        return;
    }
    let x = x as usize;
    let y = y as usize;
    if x >= dev.width || y >= dev.height {
        return;
    }
    let ptr = unsafe { dev.base.add(y * dev.stride + x) };
    unsafe { ptr.write_volatile(px) };
}
